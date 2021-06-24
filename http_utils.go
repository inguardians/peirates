package peirates

// http_utils.go contains URL requests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
)

// HeaderLine contains the left hand side (header name) and right hand side (header value) of an HTTP header.
type HeaderLine struct {
	LHS string
	RHS string
}

// DoKubernetesAPIRequest makes an API request to a kubernetes API server,
// using the connection parameters and authentication from the provided
// ServerInfo. It marshals the provided query structure to JSON, and
// unmarshalls the response JSON to the response structure pointer.
// For an example of usage, see kubectlAuthCanI.
func DoKubernetesAPIRequest(cfg ServerInfo, httpVerb, apiPath string, query interface{}, response interface{}) error {

	queryJSON, err := json.Marshal(query)
	if err != nil {
		fmt.Printf("[-] KubernetesAPIRequest failed marshalling %s to JSON: %s\n", query, err.Error())
		return err
	}

	jsonReader := bytes.NewReader(queryJSON)
	remotePath := fmt.Sprintf("https://%s:%s/%s", cfg.RIPAddress, cfg.RPort, apiPath)
	req, err := http.NewRequest(httpVerb, remotePath, jsonReader)
	if err != nil {
		fmt.Printf("[-] KubernetesAPIRequest failed building a request from URL %s : %s\n", remotePath, err.Error())
		return err
	}

	req.Header.Add("Authorization", "Bearer "+cfg.Token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	responseJSON, err := DoHTTPRequestAndGetBody(req, false, cfg.CAPath)
	if err != nil {
		fmt.Printf("[-] KubernetesAPIRequest failed to access the kubernetes API: %s\n", err.Error())
		return err
	}

	err = json.Unmarshal(responseJSON, response)
	if err != nil {
		fmt.Printf("[-] KubernetesAPIRequest failed to unmarshal JSON %s: %s\n", responseJSON, err.Error())
		return err
	}

	return nil
}

// DoHTTPRequestAndGetBody performs an HTTP request, and returns the full
// body of the reponse as a string. If ignoreTLSErrors is  true, all TLS
// errors, such as invalid certificates, will be ignored. If caCertPath is
// not an empty string, a TLS certificate will be read from the provided path
// and added to the pool of valid certificates.
func DoHTTPRequestAndGetBody(req *http.Request, ignoreTLSErrors bool, caCertPath string) ([]byte, error) {

	caCertPool, err := x509.SystemCertPool()

	if err != nil {
		fmt.Printf("[-] DoHTTPRequestAndGetBody failed to get system cert pool: %s\n", err.Error())
		return []byte{}, err
	}

	if caCertPath != "" {
		caCert, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			fmt.Printf("[-] DoHTTPRequestAndGetBody failed reading CA cert from %s: %s\n", caCertPath, err.Error())
			return []byte{}, err
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: ignoreTLSErrors,
			},
		},
	}

	responseHTTP, err := client.Do(req)
	if err != nil {
		fmt.Printf("[-] DoHTTPRequestAndGetBody failed to perform the request: %s\n", err.Error())
		return []byte{}, err
	}

	responseBody, err := ioutil.ReadAll(responseHTTP.Body)
	if err != nil {
		fmt.Printf("[-] DoHTTPRequestAndGetBody failed to read HTTP response body: %s\n", err.Error())
		return []byte{}, err
	}

	if responseHTTP.StatusCode < 200 || responseHTTP.StatusCode > 299 {
		fmt.Printf("[-] DoHTTPRequestAndGetBody got a %s status instead of a successful 2XX status. Failing and printing response: \n%s\n", responseHTTP.Status, string(responseBody))
		return []byte{}, fmt.Errorf("DoHTTPRequestAndGetBody failed with status %s", responseHTTP.Status)
	}

	return responseBody, err
}

// GetRequest is a simple helper function for making HTTP GET requests to the
// provided URL with custom headers, and the option to ignore TLS errors.
// For a more advanced helper, see DoHTTPRequestAndGetBody.
func GetRequest(url string, headers []HeaderLine, ignoreTLSErrors bool) string {

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		fmt.Printf("[-] GetRequest failed to construct an HTTP request from URL %s : %s\n", url, err.Error())
		return ""
	}

	for _, header := range headers {
		req.Header.Add(header.LHS, header.RHS)
	}

	reponse, err := DoHTTPRequestAndGetBody(req, ignoreTLSErrors, "")
	if err != nil {
		fmt.Printf("[-] GetRequest could not perform request to %s : %s\n", url, err.Error())
		return ""
	}

	return string(reponse)
}

// GetMyIPAddressesNative gets a list of IP addresses available via Golang's Net library
func GetMyIPAddressesNative() []string {

	var ipAddresses []string

	ifaces, err := net.Interfaces()
	if err != nil {
		println("ERROR: could not get interface list")
		return nil
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			println("ERROR: could not get interface information")
			return nil
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			ipString := ip.String()
			if ipString != "127.0.0.1" {
				println(ipString)
				ipAddresses = append(ipAddresses, ipString)
			}

		}
	}
	return ipAddresses
}
