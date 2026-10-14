package azure

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	clientA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	clientB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

func configFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "azure.json")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func tagFixture(ids ...string) string {
	var tags []string
	for _, id := range ids {
		tags = append(tags, fmt.Sprintf(`{"name":%q,"value":%q}`, KubeletIdentityTag, id))
	}
	return `{"compute":{"tagsList":[` + strings.Join(tags, ",") + `]}}`
}

func TestDiscoverIdentities(t *testing.T) {
	config := fmt.Sprintf(`{"useManagedIdentityExtension":true,"userAssignedIdentityID":%q,"aadClientSecret":"do-not-echo"}`, clientA)
	for _, test := range []struct {
		name, config, metadata string
		status, warnings       int
		ids                    []string
		wantSources            int
	}{
		{name: "config only", config: config, metadata: `{}`, ids: []string{clientA}, wantSources: 1},
		{name: "tag only", metadata: tagFixture(clientB), ids: []string{clientB}, wantSources: 1},
		{name: "deduplicate and normalize", config: config, metadata: tagFixture(strings.ToUpper(clientA), " "+clientA+" "), ids: []string{clientA}, wantSources: 2},
		{name: "distinct candidates sorted", config: config, metadata: tagFixture(clientB, clientA), ids: []string{clientA, clientB}, wantSources: 2},
		{name: "disabled config", config: strings.Replace(config, "true", "false", 1), metadata: tagFixture(), wantSources: 0},
		{name: "missing managed identity flag", config: fmt.Sprintf(`{"userAssignedIdentityID":%q}`, clientA), metadata: tagFixture()},
		{name: "missing config and tags", metadata: `{}`},
		{name: "ignore other fields", config: `{"aadClientId":"do-not-echo","aadClientSecret":"do-not-echo"}`, metadata: `{"compute":{"tagsList":[{"name":"other","value":"do-not-echo"}]},"access_token":"do-not-echo"}`},
		{name: "malformed config", config: `{"useManagedIdentityExtension":"do-not-echo"}`, metadata: tagFixture(clientB), warnings: 1, ids: []string{clientB}, wantSources: 1},
		{name: "trailing config", config: config + `{}`, metadata: `{}`, warnings: 1},
		{name: "malformed tags", config: config, metadata: `{"compute":{"tagsList":"do-not-echo"}}`, warnings: 1, ids: []string{clientA}, wantSources: 1},
		{name: "trailing metadata", metadata: tagFixture(clientA) + `{}`, warnings: 1},
		{name: "HTTP failure preserves config", config: config, metadata: `{"error":"do-not-echo","error_description":"do-not-echo"}`, status: 403, warnings: 1, ids: []string{clientA}, wantSources: 1},
		{name: "invalid IDs are not echoed", config: strings.Replace(config, clientA, "do-not-echo", 1), metadata: tagFixture("do-not-echo", clientB), warnings: 2, ids: []string{clientB}, wantSources: 1},
		{name: "empty identifiers", config: strings.Replace(config, clientA, "", 1), metadata: tagFixture(" ")},
		{name: "oversized config", config: strings.Repeat("x", maxResponseBytes+1), metadata: tagFixture(clientB), warnings: 1, ids: []string{clientB}, wantSources: 1},
		{name: "oversized metadata", config: config, metadata: strings.Repeat("x", maxResponseBytes+1), warnings: 1, ids: []string{clientA}, wantSources: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := configFixture(t, test.config)
			var calls atomic.Int32
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/metadata/instance" || r.Header.Get("Metadata") != "true" || r.URL.RawQuery != "api-version=2021-02-01" {
					t.Errorf("unexpected discovery request: %s %s %v", r.Method, r.URL, r.Header)
				}
				if test.status != 0 {
					w.WriteHeader(test.status)
				}
				fmt.Fprint(w, test.metadata)
			})
			result := client.DiscoverIdentities(context.Background(), path)
			var ids []string
			for _, candidate := range result.Candidates {
				ids = append(ids, candidate.ClientID)
			}
			if !reflect.DeepEqual(ids, test.ids) || len(result.Warnings) != test.warnings || calls.Load() != 1 {
				t.Fatalf("result=%+v calls=%d wantIDs=%v warnings=%d", result, calls.Load(), test.ids, test.warnings)
			}
			if len(result.Candidates) > 0 && len(result.Candidates[0].Sources) != test.wantSources {
				t.Fatalf("unexpected sources: %v", result.Candidates[0].Sources)
			}
			if strings.Contains(fmt.Sprint(result), "do-not-echo") {
				t.Fatal("discovery exposed unrelated data or an invalid identifier")
			}
		})
	}
}

func TestDiscoveryContinuesAfterConfigReadFailure(t *testing.T) {
	for _, path := range []string{t.TempDir(), filepath.Join(configFixture(t, `{}`), "not-a-directory")} {
		client := fixtureClient(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, tagFixture(clientA)) })
		result := client.DiscoverIdentities(context.Background(), path)
		if len(result.Warnings) != 1 || len(result.Candidates) != 1 || result.Candidates[0].ClientID != clientA {
			t.Fatalf("result=%+v", result)
		}
	}
}

func TestDiscoveryTransport(t *testing.T) {
	for _, mode := range []string{"redirect", "cancelled", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			client := fixtureClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "redirect" {
					http.Redirect(w, r, "/redirect-target", http.StatusFound)
					return
				}
				<-r.Context().Done()
			})
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
			}
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			// Prove the redirect policy is applied even if a caller relaxes it.
			client.HTTPClient.CheckRedirect = nil
			path := configFixture(t, fmt.Sprintf(`{"useManagedIdentityExtension":true,"userAssignedIdentityID":%q}`, clientA))
			result := client.DiscoverIdentities(ctx, path)
			if len(result.Warnings) != 1 || len(result.Candidates) != 1 || result.Candidates[0].ClientID != clientA {
				t.Fatalf("result=%+v", result)
			}
			if calls.Load() > 1 || (mode == "cancelled" && calls.Load() != 0) {
				t.Fatalf("unexpected request count: %d", calls.Load())
			}
			if mode == "redirect" && (calls.Load() != 1 || !strings.Contains(result.Warnings[0].Error(), "HTTP 302")) {
				t.Fatalf("redirect was not rejected: calls=%d warnings=%v", calls.Load(), result.Warnings)
			}
		})
	}
}
