package nodesproxyexec

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inguardians/peirates/internal/model"
)

type reviewReply struct {
	allowed bool
	err     error
}

type fakeReviewer struct {
	mu        sync.Mutex
	replies   map[string]reviewReply
	calls     []string
	active    int
	maxActive int
	delay     time.Duration
	onCall    func(context.Context, model.ServerInfo, AccessRequest) (bool, error)
}

func (reviewer *fakeReviewer) ReviewAccess(ctx context.Context, connection model.ServerInfo, request AccessRequest) (bool, error) {
	if reviewer.onCall != nil {
		return reviewer.onCall(ctx, connection, request)
	}
	reviewer.mu.Lock()
	reviewer.calls = append(reviewer.calls, connection.Token+":"+request.Verb+":"+request.NodeName)
	reviewer.active++
	if reviewer.active > reviewer.maxActive {
		reviewer.maxActive = reviewer.active
	}
	reviewer.mu.Unlock()
	defer func() {
		reviewer.mu.Lock()
		reviewer.active--
		reviewer.mu.Unlock()
	}()
	if reviewer.delay > 0 {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(reviewer.delay):
		}
	}
	reply, ok := reviewer.replies[connection.Token+":"+request.Verb]
	if !ok {
		return false, nil
	}
	return reply.allowed, reply.err
}

func TestReviewCredentialsReviewsAllTokensInOrderAndDeduplicates(t *testing.T) {
	accounts := []model.ServiceAccount{
		{Name: "first\nname", Token: "denied", DiscoveryMethod: "file\x1b"},
		{Name: "allowed-a", Token: "shared", DiscoveryMethod: "pod"},
		{Name: "broken", Token: "secret-error", DiscoveryMethod: "old"},
		{Name: "allowed-b", Token: "shared", DiscoveryMethod: "copy"},
	}
	reviewer := &fakeReviewer{replies: map[string]reviewReply{
		"denied:get":       {allowed: false},
		"shared:get":       {allowed: true},
		"shared:create":    {allowed: false},
		"secret-error:get": {err: errors.New("authentication failed for secret-error\nunsafe")},
	}, delay: 5 * time.Millisecond}
	base := model.ServerInfo{APIServer: "https://api", Token: "active", ClientCertData: "cert", ClientKeyData: "key", ClientCertName: "cert-name"}
	baseBefore := base
	accountsBefore := append([]model.ServiceAccount(nil), accounts...)

	scan, err := ReviewCredentials(context.Background(), base, accounts, "worker-1", reviewer, true)
	if err != nil {
		t.Fatalf("ReviewCredentials() error = %v", err)
	}
	if !reflect.DeepEqual(base, baseBefore) || !reflect.DeepEqual(accounts, accountsBefore) {
		t.Fatal("ReviewCredentials mutated caller-owned session values")
	}
	if len(scan.Credentials) != 4 {
		t.Fatalf("len(Credentials) = %d, want 4", len(scan.Credentials))
	}
	for index, access := range scan.Credentials {
		if access.Credential.Index != index {
			t.Errorf("Credentials[%d].Index = %d", index, access.Credential.Index)
		}
	}
	if got := scan.Credentials[0]; got.GetProxy != AccessDenied || got.CreateProxy != AccessUnchecked || got.Credential.Name != "firstname" || got.Credential.DiscoveryMethod != "file" {
		t.Errorf("denied result = %+v", got)
	}
	for _, index := range []int{1, 3} {
		if got := scan.Credentials[index]; got.GetProxy != AccessAllowed || got.CreateProxy != AccessDenied {
			t.Errorf("allowed result %d = %+v", index, got)
		}
	}
	if got := scan.Credentials[2]; got.GetProxy != AccessError || got.CreateProxy != AccessUnchecked || strings.Contains(got.GetError, "secret-error") || strings.ContainsAny(got.GetError, "\n\x1b") {
		t.Errorf("error result was not safely bounded/redacted: %+v", got)
	}

	reviewer.mu.Lock()
	calls := append([]string(nil), reviewer.calls...)
	maxActive := reviewer.maxActive
	reviewer.mu.Unlock()
	if countPrefix(calls, "shared:get:") != 1 || countPrefix(calls, "shared:create:") != 1 {
		t.Fatalf("duplicate token review calls = %v", calls)
	}
	if countPrefix(calls, "denied:create:") != 0 || countPrefix(calls, "secret-error:create:") != 0 {
		t.Fatalf("CREATE review occurred without allowed GET: %v", calls)
	}
	if maxActive > MaxReviewConcurrency {
		t.Fatalf("max concurrent reviews = %d, want <= %d", maxActive, MaxReviewConcurrency)
	}
}

func TestReviewCredentialsNeverExportsCredentialMaterial(t *testing.T) {
	token := "eyJ-super-secret-token"
	scan, err := ReviewCredentials(context.Background(), model.ServerInfo{}, []model.ServiceAccount{{Name: "safe", Token: token}}, "node.example", &fakeReviewer{replies: map[string]reviewReply{"eyJ-super-secret-token:get": {allowed: true}, "eyJ-super-secret-token:create": {allowed: false}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(scan)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	for _, rendered := range []string{string(encoded), fmt.Sprintf("%+v", scan)} {
		if strings.Contains(rendered, token) || strings.Contains(rendered, digest) {
			t.Fatalf("credential material escaped in %q", rendered)
		}
	}
	selected, err := scan.Select(0, false)
	if err != nil {
		t.Fatal(err)
	}
	if rendered := fmt.Sprintf("%+v", selected); strings.Contains(rendered, token) || strings.Contains(rendered, digest) {
		t.Fatalf("selected credential exposed material: %q", rendered)
	}
}

func TestReviewCredentialsDisabledAndSelectionRules(t *testing.T) {
	scan, err := ReviewCredentials(context.Background(), model.ServerInfo{}, []model.ServiceAccount{{Name: "one", Token: "one"}}, "worker", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Credentials[0].GetProxy != AccessUnchecked || scan.Credentials[0].CreateProxy != AccessUnchecked {
		t.Fatalf("disabled states = %+v", scan.Credentials[0])
	}
	if _, err := scan.Select(0, false); !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("unchecked Select without opt-in error = %v", err)
	}
	if _, err := scan.Select(0, true); err != nil {
		t.Fatalf("unchecked Select with opt-in error = %v", err)
	}
	for _, index := range []int{-1, 1} {
		if _, err := scan.Select(index, true); !errors.Is(err, ErrInvalidSelection) {
			t.Errorf("Select(%d) error = %v", index, err)
		}
	}
}

func TestReviewCredentialsRejectsNoTokensBadNodeAndMissingReviewer(t *testing.T) {
	tests := []struct {
		name     string
		stored   []model.ServiceAccount
		node     string
		reviewer AccessReviewer
		want     error
	}{
		{name: "empty", node: "worker", want: ErrNoCredentials},
		{name: "bad node", stored: []model.ServiceAccount{{Token: "x"}}, node: "bad/node", want: ErrInvalidNode},
		{name: "missing reviewer", stored: []model.ServiceAccount{{Token: "x"}}, node: "worker", want: errors.New("access reviewer is required")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ReviewCredentials(context.Background(), model.ServerInfo{}, test.stored, test.node, test.reviewer, true)
			if err == nil || (test.want != nil && err.Error() != test.want.Error()) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReviewCredentialsCancellationStopsPendingWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	var mu sync.Mutex
	reviewer := &fakeReviewer{onCall: func(ctx context.Context, _ model.ServerInfo, _ AccessRequest) (bool, error) {
		mu.Lock()
		calls++
		if calls == 1 {
			cancel()
		}
		mu.Unlock()
		<-ctx.Done()
		return false, ctx.Err()
	}}
	accounts := make([]model.ServiceAccount, 20)
	for i := range accounts {
		accounts[i] = model.ServiceAccount{Name: fmt.Sprint(i), Token: fmt.Sprintf("token-%d", i)}
	}
	scan, err := ReviewCredentials(ctx, model.ServerInfo{}, accounts, "worker", reviewer, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want canceled", err)
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls > MaxReviewConcurrency {
		t.Fatalf("calls after cancellation = %d, want <= %d", gotCalls, MaxReviewConcurrency)
	}
	if len(scan.Credentials) != len(accounts) {
		t.Fatalf("partial result length = %d", len(scan.Credentials))
	}
	unchecked := 0
	for _, result := range scan.Credentials {
		if result.GetProxy == AccessUnchecked {
			unchecked++
		}
	}
	if unchecked == 0 {
		t.Fatal("cancellation did not leave pending credentials unchecked")
	}
}

type fakeFactory struct {
	client       Kubelet
	err          error
	got          model.ServerInfo
	mutateSource *model.ServiceAccount
}

func (factory *fakeFactory) NewKubelet(_ context.Context, connection model.ServerInfo) (Kubelet, error) {
	if factory.mutateSource != nil {
		factory.mutateSource.Token = "mutated-after-scan"
	}
	factory.got = connection
	return factory.client, factory.err
}

type fakeKubelet struct {
	probeErr error
	lists    [][]Target
	listErrs []error
	listCall int
	exec     func(context.Context, Target, []string, io.Writer, io.Writer) (ExecStatus, error)
}

func (kubelet *fakeKubelet) Probe(context.Context) error { return kubelet.probeErr }

func (kubelet *fakeKubelet) ListRunningContainers(context.Context) ([]Target, error) {
	index := kubelet.listCall
	kubelet.listCall++
	if index < len(kubelet.listErrs) && kubelet.listErrs[index] != nil {
		return nil, kubelet.listErrs[index]
	}
	if index >= len(kubelet.lists) {
		return nil, nil
	}
	return append([]Target(nil), kubelet.lists[index]...), nil
}

func (kubelet *fakeKubelet) Exec(ctx context.Context, target Target, argv []string, stdout, stderr io.Writer) (ExecStatus, error) {
	if kubelet.exec == nil {
		return ExecStatus{}, nil
	}
	return kubelet.exec(ctx, target, argv, stdout, stderr)
}

func allowedSelection(t *testing.T, get, create AccessState, token string) SelectedCredential {
	t.Helper()
	responses := map[string]reviewReply{token + ":get": {allowed: get == AccessAllowed}}
	if get == AccessAllowed {
		responses[token+":create"] = reviewReply{allowed: create == AccessAllowed}
	}
	scan, err := ReviewCredentials(context.Background(), model.ServerInfo{Token: "active", ClientCertData: "cert", ClientKeyData: "key"}, []model.ServiceAccount{{Name: "selected", Token: token}}, "worker", &fakeReviewer{replies: responses}, get != AccessUnchecked)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := scan.Select(0, get == AccessUnchecked)
	if err != nil {
		t.Fatal(err)
	}
	return selected
}

func TestPrepareUsesImmutableCredentialAndSortsTargets(t *testing.T) {
	account := model.ServiceAccount{Name: "selected", Token: "selected-token"}
	scan, err := ReviewCredentials(context.Background(), model.ServerInfo{Token: "active", ClientCertData: "cert", ClientKeyData: "key", ClientCertName: "cert-name"}, []model.ServiceAccount{account}, "worker", &fakeReviewer{replies: map[string]reviewReply{"selected-token:get": {allowed: true}, "selected-token:create": {allowed: false}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := scan.Select(0, false)
	if err != nil {
		t.Fatal(err)
	}
	account.Token = "changed"
	targetA := Target{NodeName: "worker", Namespace: "z", PodName: "pod", ContainerName: "init", ContainerKind: ContainerInit}
	targetB := Target{NodeName: "worker", Namespace: "a", PodName: "pod", ContainerName: "regular", ContainerKind: ContainerRegular}
	kubelet := &fakeKubelet{lists: [][]Target{{targetA, targetB, targetB, {NodeName: "other", Namespace: "a", PodName: "x", ContainerName: "c", ContainerKind: ContainerRegular}, {NodeName: "worker", Namespace: "bad/name", PodName: "x", ContainerName: "c", ContainerKind: ContainerRegular}}}}
	factory := &fakeFactory{client: kubelet}
	prepared, probe, err := Prepare(context.Background(), selected, "worker", factory)
	if err != nil {
		t.Fatal(err)
	}
	if prepared == nil || probe.Classification != ClassificationPermissionCandidate {
		t.Fatalf("Prepare result = %#v, %#v", prepared, probe)
	}
	if !reflect.DeepEqual(probe.Containers, []Target{targetB, targetA}) {
		t.Fatalf("sorted containers = %#v", probe.Containers)
	}
	if factory.got.Token != "selected-token" || factory.got.ClientCertData != "" || factory.got.ClientKeyData != "" || factory.got.ClientCertName != "" {
		t.Fatalf("factory connection did not use private token-only copy: %+v", factory.got)
	}
}

func TestPrepareFailuresAreRedacted(t *testing.T) {
	selected := allowedSelection(t, AccessAllowed, AccessDenied, "private-token")
	tests := []struct {
		name    string
		factory KubeletFactory
	}{
		{name: "factory", factory: &fakeFactory{err: errors.New("bad private-token\nfactory")}},
		{name: "probe", factory: &fakeFactory{client: &fakeKubelet{probeErr: errors.New("bad private-token probe")}}},
		{name: "list", factory: &fakeFactory{client: &fakeKubelet{listErrs: []error{errors.New("bad private-token list")}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, result, err := Prepare(context.Background(), selected, "worker", test.factory)
			if err == nil || strings.Contains(err.Error(), "private-token") || strings.ContainsAny(err.Error(), "\n\x1b") {
				t.Fatalf("unsafe error = %v", err)
			}
			if result.Classification != ClassificationNotExploitableFromHere {
				t.Fatalf("classification = %q", result.Classification)
			}
		})
	}
}

func TestExecuteRevalidatesAndClassifiesEverySuccessState(t *testing.T) {
	target := Target{NodeName: "worker", Namespace: "ns", PodName: "pod", ContainerName: "container", ContainerKind: ContainerRegular}
	tests := []struct {
		name           string
		get            AccessState
		create         AccessState
		want           Classification
		reviewsEnabled bool
	}{
		{name: "get only", get: AccessAllowed, create: AccessDenied, want: ClassificationConfirmedGetOnlyExec, reviewsEnabled: true},
		{name: "broad", get: AccessAllowed, create: AccessAllowed, want: ClassificationBroadProxyAccess, reviewsEnabled: true},
		{name: "unchecked", get: AccessUnchecked, create: AccessUnchecked, want: ClassificationExecutionConfirmedUnchecked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected := allowedSelection(t, test.get, test.create, "token")
			kubelet := &fakeKubelet{
				lists: [][]Target{{target}, {target}},
				exec: func(_ context.Context, got Target, argv []string, stdout, stderr io.Writer) (ExecStatus, error) {
					if got != target || !reflect.DeepEqual(argv, []string{"/bin/echo", "ok"}) {
						t.Errorf("Exec target/argv = %#v %#v", got, argv)
					}
					_, _ = io.WriteString(stdout, "out")
					_, _ = io.WriteString(stderr, "err")
					return ExecStatus{ExitCode: 7, Protocol: "v5.channel.k8s.io", Complete: true}, nil
				},
			}
			prepared, _, err := Prepare(context.Background(), selected, "worker", &fakeFactory{client: kubelet})
			if err != nil {
				t.Fatal(err)
			}
			result, err := prepared.Execute(context.Background(), Options{Target: target, Argv: []string{"/bin/echo", "ok"}})
			if err != nil {
				t.Fatal(err)
			}
			if result.Classification != test.want || result.ExitCode != 7 || string(result.Stdout) != "out" || string(result.Stderr) != "err" || result.Protocol != "v5.channel.k8s.io" {
				t.Fatalf("ExecResult = %+v", result)
			}
			if kubelet.listCall != 2 {
				t.Fatalf("ListRunningContainers calls = %d, want 2", kubelet.listCall)
			}
		})
	}
}

func TestExecuteFailsClosedForTargetsAndArguments(t *testing.T) {
	target := Target{NodeName: "worker", Namespace: "ns", PodName: "pod", ContainerName: "container", ContainerKind: ContainerRegular}
	other := target
	other.ContainerName = "other"
	tests := []struct {
		name      string
		initial   []Target
		fresh     []Target
		target    Target
		argv      []string
		wantError error
	}{
		{name: "not offered", initial: []Target{target}, fresh: []Target{target}, target: other, argv: []string{"id"}, wantError: ErrTargetNotOffered},
		{name: "disappeared", initial: []Target{target}, fresh: nil, target: target, argv: []string{"id"}, wantError: ErrTargetNoLongerRuns},
		{name: "node mismatch", initial: []Target{target}, fresh: []Target{{NodeName: "other", Namespace: "ns", PodName: "pod", ContainerName: "container", ContainerKind: ContainerRegular}}, target: target, argv: []string{"id"}, wantError: ErrTargetNoLongerRuns},
		{name: "empty argv", initial: []Target{target}, fresh: []Target{target}, target: target, argv: nil, wantError: ErrInvalidArguments},
		{name: "nul argv", initial: []Target{target}, fresh: []Target{target}, target: target, argv: []string{"bad\x00arg"}, wantError: ErrInvalidArguments},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executed := false
			kubelet := &fakeKubelet{lists: [][]Target{test.initial, test.fresh}, exec: func(context.Context, Target, []string, io.Writer, io.Writer) (ExecStatus, error) {
				executed = true
				return ExecStatus{Complete: true}, nil
			}}
			prepared, _, err := Prepare(context.Background(), allowedSelection(t, AccessAllowed, AccessDenied, "token"), "worker", &fakeFactory{client: kubelet})
			if err != nil {
				t.Fatal(err)
			}
			result, err := prepared.Execute(context.Background(), Options{Target: test.target, Argv: test.argv})
			if !errors.Is(err, test.wantError) {
				t.Fatalf("error = %v, want %v", err, test.wantError)
			}
			if executed || result.Classification != ClassificationNotExploitableFromHere {
				t.Fatalf("executed=%v result=%+v", executed, result)
			}
		})
	}
}

func TestExecuteOutputLimitCancellationAndTimeout(t *testing.T) {
	target := Target{NodeName: "worker", Namespace: "ns", PodName: "pod", ContainerName: "container", ContainerKind: ContainerRegular}
	t.Run("combined output", func(t *testing.T) {
		kubelet := &fakeKubelet{lists: [][]Target{{target}, {target}}, exec: func(ctx context.Context, _ Target, _ []string, stdout, stderr io.Writer) (ExecStatus, error) {
			if _, err := stdout.Write([]byte("1234")); err != nil {
				return ExecStatus{}, err
			}
			_, err := stderr.Write([]byte("5678"))
			if !errors.Is(err, ErrOutputLimitExceeded) {
				t.Errorf("overflow write error = %v", err)
			}
			if ctx.Err() == nil {
				t.Error("overflow did not cancel execution context")
			}
			return ExecStatus{}, err
		}}
		prepared, _, err := Prepare(context.Background(), allowedSelection(t, AccessAllowed, AccessDenied, "token"), "worker", &fakeFactory{client: kubelet})
		if err != nil {
			t.Fatal(err)
		}
		result, err := prepared.Execute(context.Background(), Options{Target: target, Argv: []string{"id"}, OutputLimit: 6})
		if !errors.Is(err, ErrOutputLimitExceeded) || len(result.Stdout)+len(result.Stderr) != 6 {
			t.Fatalf("result/error = %+v / %v", result, err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		kubelet := &fakeKubelet{lists: [][]Target{{target}, {target}}, exec: func(ctx context.Context, _ Target, _ []string, _, _ io.Writer) (ExecStatus, error) {
			<-ctx.Done()
			return ExecStatus{}, ctx.Err()
		}}
		prepared, _, err := Prepare(context.Background(), allowedSelection(t, AccessAllowed, AccessDenied, "token"), "worker", &fakeFactory{client: kubelet})
		if err != nil {
			t.Fatal(err)
		}
		result, err := prepared.Execute(context.Background(), Options{Target: target, Argv: []string{"id"}, CommandTimeout: time.Millisecond})
		if !errors.Is(err, context.DeadlineExceeded) || result.Classification != ClassificationNotExploitableFromHere {
			t.Fatalf("result/error = %+v / %v", result, err)
		}
	})
}

func TestExecuteRequiresCompletedStatusAndRedactsErrors(t *testing.T) {
	target := Target{NodeName: "worker", Namespace: "ns", PodName: "pod", ContainerName: "container", ContainerKind: ContainerRegular}
	tests := []struct {
		name   string
		status ExecStatus
		err    error
		want   error
	}{
		{name: "incomplete", status: ExecStatus{Protocol: "v5.channel.k8s.io"}, want: ErrExecutionIncomplete},
		{name: "transport", err: errors.New("failed with private-token\nunsafe")},
		{name: "completed nonzero", status: ExecStatus{Complete: true, ExitCode: 9}, err: errors.New("exit status 9")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kubelet := &fakeKubelet{lists: [][]Target{{target}, {target}}, exec: func(context.Context, Target, []string, io.Writer, io.Writer) (ExecStatus, error) {
				return test.status, test.err
			}}
			prepared, _, err := Prepare(context.Background(), allowedSelection(t, AccessAllowed, AccessDenied, "private-token"), "worker", &fakeFactory{client: kubelet})
			if err != nil {
				t.Fatal(err)
			}
			result, err := prepared.Execute(context.Background(), Options{Target: target, Argv: []string{"id"}})
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if test.want == nil && err == nil {
				t.Fatal("expected transport/exit error")
			}
			if err != nil && (strings.Contains(err.Error(), "private-token") || strings.ContainsAny(err.Error(), "\n\x1b")) {
				t.Fatalf("unsafe execution error = %v", err)
			}
			if test.status.Complete && result.Classification != ClassificationConfirmedGetOnlyExec {
				t.Fatalf("completed classification = %q", result.Classification)
			}
		})
	}
}

func TestArgumentBounds(t *testing.T) {
	tooMany := make([]string, MaxArgumentCount+1)
	for i := range tooMany {
		tooMany[i] = "x"
	}
	for _, argv := range [][]string{tooMany, {strings.Repeat("x", MaxArgumentBytes+1)}} {
		if _, err := normalizeArgv(argv); !errors.Is(err, ErrInvalidArguments) {
			t.Fatalf("normalizeArgv(%d args) error = %v", len(argv), err)
		}
	}
	input := []string{"id"}
	got, err := normalizeArgv(input)
	if err != nil {
		t.Fatal(err)
	}
	got[0] = "changed"
	if input[0] != "id" {
		t.Fatal("normalizeArgv returned caller-owned storage")
	}
}

func countPrefix(values []string, prefix string) int {
	count := 0
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			count++
		}
	}
	return count
}
