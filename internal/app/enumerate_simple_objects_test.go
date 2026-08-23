package app

import (
	"errors"
	"reflect"
	"testing"
)

func stubEnumeration(t *testing.T, allowed bool, response []byte, responseErr error) *[][]string {
	t.Helper()
	originalAuth, originalKubectl := enumerateAuthCanI, enumerateKubectlSimple
	var calls [][]string
	enumerateAuthCanI = func(_ ServerInfo, _, _ string) bool { return allowed }
	enumerateKubectlSimple = func(_ ServerInfo, args ...string) ([]byte, []byte, error) {
		calls = append(calls, args)
		return response, nil, responseErr
	}
	t.Cleanup(func() {
		enumerateAuthCanI, enumerateKubectlSimple = originalAuth, originalKubectl
	})
	return &calls
}

func TestGetPodListAndGetPodsInfo(t *testing.T) {
	podsJSON := []byte(`{"items":[{"metadata":{"name":"api"}},{"metadata":{"name":"worker"}}]}`)
	calls := stubEnumeration(t, true, podsJSON, nil)
	if got, want := getPodList(ServerInfo{}), []string{"api", "worker"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("getPodList() = %#v, want %#v", got, want)
	}
	var details PodDetails
	GetPodsInfo(ServerInfo{}, &details)
	if len(details.Items) != 2 || details.Items[0].Metadata.Name != "api" {
		t.Fatalf("GetPodsInfo() parsed %#v", details.Items)
	}
	wantCall := []string{"get", "pods", "-o", "json"}
	for _, call := range *calls {
		if !reflect.DeepEqual(call, wantCall) {
			t.Errorf("kubectl arguments = %#v, want %#v", call, wantCall)
		}
	}
}

func TestGetPodListRejectsDeniedMalformedAndFailedResponses(t *testing.T) {
	for _, test := range []struct {
		name    string
		allowed bool
		body    []byte
		err     error
	}{
		{"denied", false, nil, nil},
		{"invalid JSON", true, []byte("{"), nil},
		{"kubectl error", true, nil, errors.New("kubectl failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubEnumeration(t, test.allowed, test.body, test.err)
			if got := getPodList(ServerInfo{}); len(got) != 0 {
				t.Fatalf("getPodList() = %#v, want empty", got)
			}
		})
	}
}

func TestGetSecretList(t *testing.T) {
	secretsJSON := []byte(`{"items":[{"metadata":{"name":"default-token"},"type":"kubernetes.io/service-account-token"},{"metadata":{"name":"app-config"},"type":"Opaque"}]}`)
	calls := stubEnumeration(t, true, secretsJSON, nil)
	secrets, tokens := getSecretList(ServerInfo{})
	if want := []string{"default-token", "app-config"}; !reflect.DeepEqual(secrets, want) {
		t.Fatalf("secrets = %#v, want %#v", secrets, want)
	}
	if want := []string{"default-token"}; !reflect.DeepEqual(tokens, want) {
		t.Fatalf("service-account tokens = %#v, want %#v", tokens, want)
	}
	if want := [][]string{{"get", "secrets", "-o", "json"}}; !reflect.DeepEqual(*calls, want) {
		t.Fatalf("kubectl calls = %#v, want %#v", *calls, want)
	}
}

func TestGetSecretListRejectsDeniedMalformedAndFailedResponses(t *testing.T) {
	for _, test := range []struct {
		name    string
		allowed bool
		body    []byte
		err     error
	}{
		{"denied", false, nil, nil},
		{"invalid JSON", true, []byte("{"), nil},
		{"kubectl error", true, nil, errors.New("kubectl failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			stubEnumeration(t, test.allowed, test.body, test.err)
			secrets, tokens := getSecretList(ServerInfo{})
			if len(secrets) != 0 || len(tokens) != 0 {
				t.Fatalf("getSecretList() = (%#v, %#v), want empty slices", secrets, tokens)
			}
		})
	}
}

func TestGetRolesAndNodesIssueExpectedCommands(t *testing.T) {
	calls := stubEnumeration(t, true, []byte(`{"items":[{"metadata":{"name":"reader"}}]}`), nil)
	var roles KubeRoles
	GetRoles(ServerInfo{}, &roles)
	GetNodesInfo(ServerInfo{})
	if len(roles.Items) != 1 || roles.Items[0].Metadata.Name != "reader" {
		t.Fatalf("GetRoles() parsed %#v", roles.Items)
	}
	want := [][]string{{"get", "role", "-o", "json"}, {"get", "nodes", "-o", "json"}}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("kubectl calls = %#v, want %#v", *calls, want)
	}
}

func TestGetRolesAndNodesTolerateKubectlFailures(t *testing.T) {
	stubEnumeration(t, true, nil, errors.New("kubectl failed"))
	var roles KubeRoles
	GetRoles(ServerInfo{}, &roles)
	GetNodesInfo(ServerInfo{})
	if len(roles.Items) != 0 {
		t.Fatalf("GetRoles() populated roles after a failed command: %#v", roles.Items)
	}
}
