package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
)

// nodeAWSAPI uses the existing SDK's signing and partition resolver with a small,
// bounded HTTP protocol surface. It has no retries or credential-chain fallback.
type nodeAWSAPI struct {
	client *http.Client
	now    func() time.Time
}

type nodeAWSRequestError struct {
	service  string
	status   int
	timedOut bool
}

func (e *nodeAWSRequestError) Error() string {
	if e.status != 0 {
		return fmt.Sprintf("%s discovery returned HTTP %d", e.service, e.status)
	}
	if e.timedOut {
		return e.service + " discovery request timed out"
	}
	return e.service + " discovery request unavailable"
}

func nodeDiscoveryFailureReason(err error) string {
	var requestError *nodeAWSRequestError
	if errors.As(err, &requestError) {
		return requestError.Error()
	}
	return "EC2 instance tag lookup unavailable"
}

func (a *nodeAWSAPI) DescribeInstance(ctx context.Context, region, instanceID string, creds Credentials) (InstanceDescription, error) {
	var result InstanceDescription
	if !instanceIDPattern.MatchString(instanceID) {
		return result, errors.New("invalid EC2 instance ID")
	}
	query := url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}, "InstanceId.1": {instanceID}}
	body, err := a.request(ctx, "ec2", region, http.MethodPost, "/", query.Encode(), creds)
	if err != nil {
		return result, err
	}
	var response struct {
		Instances []struct {
			ID             string `xml:"instanceId"`
			PrivateDNSName string `xml:"privateDnsName"`
			Tags           []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"reservationSet>item>instancesSet>item"`
		NextToken string `xml:"nextToken"`
	}
	if xml.Unmarshal(body, &response) != nil || len(response.Instances) != 1 || response.Instances[0].ID != instanceID || response.NextToken != "" {
		return result, errors.New("EC2 returned an invalid instance-scoped lookup response")
	}
	instance := response.Instances[0]
	result.InstanceID, result.PrivateDNSName = instance.ID, instance.PrivateDNSName
	result.Tags = make(map[string]string)
	for _, tag := range instance.Tags {
		result.Tags[tag.Key] = tag.Value
	}
	return result, nil
}

func (a *nodeAWSAPI) DescribeCluster(ctx context.Context, region, cluster string, creds Credentials) (ClusterDescription, error) {
	var result ClusterDescription
	if !clusterNamePattern.MatchString(cluster) {
		return result, errors.New("invalid EKS cluster name")
	}
	body, err := a.request(ctx, "eks", region, http.MethodGet, "/clusters/"+url.PathEscape(cluster), "", creds)
	if err != nil {
		return result, err
	}
	var response struct {
		Cluster struct {
			Name                 string `json:"name"`
			Endpoint             string `json:"endpoint"`
			CertificateAuthority struct {
				Data string `json:"data"`
			} `json:"certificateAuthority"`
		} `json:"cluster"`
	}
	if json.Unmarshal(body, &response) != nil || response.Cluster.Name != cluster {
		return result, errors.New("EKS returned an invalid cluster description")
	}
	ca, err := base64.StdEncoding.DecodeString(response.Cluster.CertificateAuthority.Data)
	if err != nil || len(ca) == 0 {
		return result, errors.New("EKS returned invalid cluster CA data")
	}
	result.Name, result.Endpoint, result.CA = response.Cluster.Name, response.Cluster.Endpoint, ca
	return result, nil
}

func (a *nodeAWSAPI) request(ctx context.Context, service, region, method, path, body string, creds Credentials) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, nodeRequestTimeout)
	defer cancel()
	endpoint, err := regionalEndpoint(service, region)
	if err != nil {
		return nil, err
	}
	reader := strings.NewReader(body)
	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, reader)
	if err != nil {
		return nil, errors.New("could not construct AWS discovery request")
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	}
	signer := v4.NewSigner(credentials.NewStaticCredentials(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken))
	if _, err := signer.Sign(req, reader, service, region, a.now()); err != nil {
		return nil, errors.New("could not sign AWS discovery request")
	}
	response, err := a.client.Do(req)
	if err != nil {
		var networkError net.Error
		timedOut := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout())
		return nil, &nodeAWSRequestError{service: service, timedOut: timedOut}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &nodeAWSRequestError{service: service, status: response.StatusCode}
	}
	return readNodeResponse(response.Body)
}
