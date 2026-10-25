package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	awscloud "github.com/inguardians/peirates/internal/cloud/aws"
	"github.com/inguardians/peirates/internal/kube"
	"github.com/inguardians/peirates/internal/model"
)

var generateAWSNodeToken = awscloud.GenerateNodeToken
var resolveAWSNodeTokenTarget = kube.ResolveNodeTokenTarget
var verifyAWSNodeToken = kube.VerifyNodeToken

const awsNodeTokenUsage = `Usage: aws-get-eks-node-token [--cluster-name NAME] [--region REGION] [--verify | --activate] [--allow-imdsv1]
Alias: 37
Automatically discovers the EKS cluster and region from the node's IMDS and AWS APIs.
Prints and retains the generated bearer token without changing the active identity.
--verify reports the Kubernetes identity; --activate verifies then switches to the node token.
IMDSv1 fallback is disabled unless explicitly enabled. Rerun to refresh an expired token.
`

type awsNodeTokenSelection struct {
	awscloud.NodeTokenOptions
	verify, activate bool
}

func parseAWSNodeTokenOptions(args []string) (awsNodeTokenSelection, error) {
	var selection awsNodeTokenSelection
	flags := flag.NewFlagSet("aws-get-eks-node-token", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&selection.ClusterName, "cluster-name", "", "optional cluster-name override")
	flags.StringVar(&selection.Region, "region", "", "optional region override")
	flags.BoolVar(&selection.AllowIMDSv1, "allow-imdsv1", false, "allow IMDSv1 fallback")
	flags.BoolVar(&selection.verify, "verify", false, "verify node identity")
	flags.BoolVar(&selection.activate, "activate", false, "verify and activate node identity")
	if err := flags.Parse(args); err != nil {
		return selection, err
	}
	if flags.NArg() != 0 {
		return selection, errors.New("unexpected positional arguments; use --help")
	}
	selection.verify = selection.verify || selection.activate
	return selection, nil
}

func requestAWSNodeToken(session *Session, args []string, out io.Writer) {
	selection, err := parseAWSNodeTokenOptions(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(out, awsNodeTokenUsage)
		return
	}
	if err != nil {
		fmt.Fprintf(out, "[-] EKS node token: %v\n", err)
		return
	}
	connection, targetErr := resolveAWSNodeTokenTarget(session.Connection)
	if targetErr != nil && !errors.Is(targetErr, kube.ErrNodeTokenTargetUnavailable) {
		fmt.Fprintf(out, "[-] EKS node token target: %v\n", targetErr)
		return
	}
	selection.TrustedCA = []byte(connection.CACertData)
	selection.APIEndpoint = connection.APIServer
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := generateAWSNodeToken(ctx, selection.NodeTokenOptions)
	if err != nil {
		fmt.Fprintf(out, "[-] EKS node token: %v\n", err)
		return
	}
	if result.Token == "" || !result.ExpiresAt.After(time.Now()) {
		fmt.Fprintln(out, "[-] EKS node token: empty or expired generated credential; rerun aws-get-eks-node-token")
		return
	}
	entry := model.AWSNodeToken{
		Token: result.Token, ClusterName: result.ClusterName, Region: result.Region, RoleIdentity: result.RoleIdentity,
		RegionSource: result.RegionSource, ClusterSource: result.ClusterSource, InstanceID: result.InstanceID,
		AccountID: result.AccountID, RoleName: result.RoleName, PrivateDNSName: result.PrivateDNSName,
		AcquiredAt: result.AcquiredAt, ExpiresAt: result.ExpiresAt, Corroborated: result.Corroborated,
	}
	key := model.AWSNodeTokenKey{ClusterName: entry.ClusterName, Region: entry.Region, RoleIdentity: entry.RoleIdentity}
	if session.AWSNodeTokens == nil {
		session.AWSNodeTokens = make(map[model.AWSNodeTokenKey]model.AWSNodeToken)
	}
	session.AWSNodeTokens[key] = entry
	fmt.Fprintf(out, "[+] EKS node token generated (authentication unverified)\nInstance: %q\nRegion: %q (source: %q)\nCluster: %q (source: %q; corroborated: %t)\nRole: %q\nExpires (UTC): %s\n",
		entry.InstanceID, entry.Region, entry.RegionSource, entry.ClusterName, entry.ClusterSource, entry.Corroborated, entry.RoleIdentity, entry.ExpiresAt.UTC().Format(time.RFC3339))
	for _, diagnostic := range result.Diagnostics {
		fmt.Fprintf(out, "Discovery: %q\n", diagnostic)
	}
	fmt.Fprintf(out, "Bearer token: %s\n", entry.Token)
	if !selection.verify {
		return
	}
	if targetErr != nil {
		entry.VerificationError = targetErr.Error()
		session.AWSNodeTokens[key] = entry
		fmt.Fprintf(out, "[-] EKS node token verification unavailable: %v\n", targetErr)
		return
	}
	if connection.IgnoreTLS {
		fmt.Fprintln(out, "[!] Verification uses the existing explicit insecure TLS setting.")
	}
	identity, err := verifyAWSNodeToken(ctx, connection, entry.Token)
	if err == nil {
		// Check the contract here as well, so no successful non-node identity can activate.
		if !strings.HasPrefix(identity.Username, "system:node:") || strings.TrimPrefix(identity.Username, "system:node:") == "" || !containsString(identity.Groups, "system:nodes") {
			err = errors.New("authenticated identity is not a Kubernetes node")
		}
	}
	if err != nil {
		if identity.Username != "" || len(identity.Groups) != 0 {
			fmt.Fprintf(out, "Kubernetes returned identity: %q; groups: %q\n", identity.Username, identity.Groups)
		}
		entry.VerificationError = err.Error()
		session.AWSNodeTokens[key] = entry
		fmt.Fprintf(out, "[-] EKS node token verification failed: %v\n", err)
		return
	}
	entry.Username, entry.Groups, entry.Verified = identity.Username, append([]string(nil), identity.Groups...), true
	nodeName := strings.TrimPrefix(identity.Username, "system:node:")
	entry.InstanceMatched = nodeName == entry.InstanceID || (entry.PrivateDNSName != "" && nodeName == entry.PrivateDNSName)
	session.AWSNodeTokens[key] = entry
	fmt.Fprintf(out, "[+] Verified Kubernetes node identity: %q; groups: %q\n", entry.Username, entry.Groups)
	if entry.InstanceMatched {
		fmt.Fprintln(out, "Instance association: confirmed from instance metadata.")
	} else {
		fmt.Fprintln(out, "Instance association: unproven; the authenticated node name could not be matched to instance metadata.")
	}
	if selection.activate {
		if !entry.ExpiresAt.After(time.Now()) {
			fmt.Fprintln(out, "[-] EKS node token expired before activation; rerun aws-get-eks-node-token")
			return
		}
		connection.Token, connection.TokenName = entry.Token, entry.Username
		connection.ClientCertData, connection.ClientKeyData, connection.ClientCertName = "", "", ""
		connection.ActiveTokenKind, connection.ActiveTokenExpiresAt = "eks-node", entry.ExpiresAt
		session.Connection = connection
		fmt.Fprintln(out, "[+] Activated EKS node token.")
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func printAWSNodeTokenStatus(out io.Writer, session *Session, now time.Time) {
	var lines []string
	for key, entry := range session.AWSNodeTokens {
		state := "unverified"
		if entry.Verified {
			state = "verified node; instance association unproven"
			if entry.InstanceMatched {
				state = "verified node; instance matched"
			}
		}
		if entry.VerificationError != "" {
			state = "verification failed"
		}
		if !entry.ExpiresAt.After(now) {
			state = "expired"
		}
		lines = append(lines, fmt.Sprintf("[+] EKS node token (%s): cluster %q; region %q; role %q; identity %q; expires %s\n", state, key.ClusterName, key.Region, key.RoleIdentity, entry.Username, entry.ExpiresAt.UTC().Format(time.RFC3339)))
	}
	sort.Strings(lines)
	for _, line := range lines {
		fmt.Fprint(out, line)
	}
}
