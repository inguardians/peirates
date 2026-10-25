package app

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	awscloud "github.com/inguardians/peirates/internal/cloud/aws"
	"github.com/inguardians/peirates/internal/modules"
)

func TestRunModuleCommandCloudOptions(t *testing.T) {
	var azureCalls atomic.Int32
	azureRequests := make(chan string, 1)
	useAzureFixture(t, func(w http.ResponseWriter, r *http.Request) {
		azureCalls.Add(1)
		azureRequests <- r.URL.Query().Get("resource")
		writeAzureFixture(w)
	})
	stubNodeTokenOperations(t)
	awsCalls := 0
	var awsOptions awscloud.NodeTokenOptions
	generateAWSNodeToken = func(_ context.Context, options awscloud.NodeTokenOptions) (awscloud.NodeTokenResult, error) {
		awsCalls++
		awsOptions = options
		return nodeTokenFixture(), nil
	}
	for _, provider := range []struct {
		command, label, options string
		aliases                 []string
	}{
		{"azure-get-token", "Azure token", ` --resource 'https://vault.azure.net' --client-id "client"`, []string{"azure-get-token", "get-azure-token", "36"}},
		{"aws-get-eks-node-token", "EKS node token", ` --cluster-name 'test-cluster' --region "us-east-1"`, []string{"aws-get-eks-node-token", "37"}},
	} {
		for _, alias := range provider.aliases {
			if got := canonicalModuleCommand(alias); got != provider.command {
				t.Fatalf("canonical command for %q = %q", alias, got)
			}
			for _, test := range []struct {
				suffix, output string
				request        bool
			}{
				{"", "Bearer token:", true},
				{provider.options, "Bearer token:", true},
				{" --help", "Usage: " + provider.command, false},
				{" --bad-option", "[-] " + provider.label + ":", false},
				{" --option 'unterminated", "[-] " + provider.label + ": unterminated quote", false},
				{" --option trailing\\", "[-] " + provider.label + ": trailing escape", false},
			} {
				t.Run(alias+test.suffix, func(t *testing.T) {
					session := NewSession(ServerInfo{})
					session.Interactive = false
					beforeAzure, beforeAWS := azureCalls.Load(), awsCalls
					output := captureModuleDispatchOutput(t, func() {
						result, found := runModuleCommand(newModuleRegistry(session), session, alias+test.suffix)
						if !found || result != modules.Continue {
							t.Fatalf("dispatch result = %v, found = %v", result, found)
						}
					})
					if !strings.Contains(output, test.output) {
						t.Fatalf("output = %q, want %q", output, test.output)
					}
					wantAzure, wantAWS := int32(0), 0
					if test.request {
						if provider.command == "azure-get-token" {
							wantAzure = 1
							select {
							case resource := <-azureRequests:
								if test.suffix != "" && resource != "https://vault.azure.net" {
									t.Fatalf("quoted resource = %q", resource)
								}
							default:
								t.Fatal("Azure token request missing")
							}
						} else {
							wantAWS = 1
							if test.suffix != "" && (awsOptions.ClusterName != "test-cluster" || awsOptions.Region != "us-east-1") {
								t.Fatalf("quoted AWS options = %+v", awsOptions)
							}
						}
					}
					if azureCalls.Load()-beforeAzure != wantAzure || awsCalls-beforeAWS != wantAWS {
						t.Fatalf("token requests: Azure = %d, AWS = %d; want %d, %d", azureCalls.Load()-beforeAzure, awsCalls-beforeAWS, wantAzure, wantAWS)
					}
				})
			}
		}
	}
}

func TestRunModuleCommandRegistryFallback(t *testing.T) {
	registry := modules.NewRegistry()
	calls := 0
	registry.Register(func() modules.Result { calls++; return modules.Refresh }, "short")
	registry.Register(func() modules.Result { calls++; return modules.Continue }, "ordinary")
	for _, test := range []struct {
		input  string
		result modules.Result
		found  bool
	}{
		{"short", modules.Refresh, true},
		{"minimal", modules.Refresh, true},
		{"ordinary", modules.Continue, true},
		{"short ", modules.Continue, false},
		{"short --help", modules.Continue, false},
		{"azure-get-token-suffix --help", modules.Continue, false},
		{"aws-get-eks-node-token-suffix --help", modules.Continue, false},
		{"unknown", modules.Continue, false},
		{"", modules.Continue, false},
	} {
		t.Run(test.input, func(t *testing.T) {
			before := calls
			result, found := runModuleCommand(registry, NewSession(ServerInfo{}), test.input)
			if result != test.result || found != test.found || (calls == before+1) != test.found {
				t.Fatalf("result = %v, found = %v, calls = %d; want %v, %v", result, found, calls-before, test.result, test.found)
			}
		})
	}
}

func captureModuleDispatchOutput(t *testing.T, run func()) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = file
	defer func() {
		os.Stdout = previous
		file.Close()
	}()
	run()
	output, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}
