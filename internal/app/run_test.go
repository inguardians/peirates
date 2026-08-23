package app

import (
	"os"
	"reflect"
	"testing"
)

func TestRunArgsRoutesProcessModes(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	tests := []struct {
		name, wantMode string
		args, wantArgs []string
	}{
		{name: "peirates", args: []string{"/usr/local/bin/peirates", "-m", "pwd"}, wantMode: "peirates", wantArgs: []string{"/usr/local/bin/peirates", "-m", "pwd"}},
		{name: "kubectl flag", args: []string{"peirates", "--kubectl", "get", "pods"}, wantMode: "kubectl", wantArgs: []string{"kubectl", "get", "pods"}},
		{name: "kubectl basename", args: []string{"/usr/local/bin/kubectl", "get", "nodes"}, wantMode: "kubectl", wantArgs: []string{"/usr/local/bin/kubectl", "get", "nodes"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mode := ""
			RunArgs(test.args, Entrypoints{Peirates: func() { mode = "peirates" }, Kubectl: func() { mode = "kubectl" }})
			if mode != test.wantMode {
				t.Fatalf("mode = %q, want %q", mode, test.wantMode)
			}
			if !reflect.DeepEqual(os.Args, test.wantArgs) {
				t.Fatalf("os.Args = %#v, want %#v", os.Args, test.wantArgs)
			}
		})
	}
}
