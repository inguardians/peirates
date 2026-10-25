package aws

import (
	"reflect"
	"strings"
	"testing"
)

func TestNodeBootstrapYAMLDocumentLimit(t *testing.T) {
	document := "apiVersion: node.eks.aws/v1alpha1\nkind: NodeConfig\nspec:\n  cluster:\n    name: cluster\n"
	for _, count := range []int{32, 33} {
		data := strings.Repeat(document+"---\n", count-1) + document
		_, _, err := nodeConfigName([]byte(data))
		if (err != nil) != (count > 32) {
			t.Fatalf("%d documents: %v", count, err)
		}
	}
}

func TestNodeBootstrapFormats(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		want       map[string]string
		wantError  bool
	}{
		{"al2023", "apiVersion: node.eks.aws/v1alpha1\nkind: NodeConfig\nspec:\n  cluster:\n    name: my-cluster\n", map[string]string{"my-cluster": "IMDS AL2023 NodeConfig bootstrap data"}, false},
		{"al2023_partial_merge", "apiVersion: node.eks.aws/v1alpha1\nkind: NodeConfig\nspec:\n  cluster:\n    name: my-cluster\n---\napiVersion: node.eks.aws/v1alpha1\nkind: NodeConfig\nspec:\n  kubelet:\n    config: {}\n", map[string]string{"my-cluster": "IMDS AL2023 NodeConfig bootstrap data"}, false},
		{"bottlerocket_double", "[settings.kubernetes]\ncluster-name = \"my-cluster\" # comment\napi-server = \"https://not-adopted.example\"\n", map[string]string{"my-cluster": "IMDS Bottlerocket bootstrap data"}, false},
		{"bottlerocket_single", "[settings.kubernetes]\ncluster-name = 'my-cluster'\n", map[string]string{"my-cluster": "IMDS Bottlerocket bootstrap data"}, false},
		{"bottlerocket_other_table", "[settings.other]\ncluster-name = 'wrong'\n", map[string]string{}, false},
		{"bottlerocket_duplicate", "[settings.kubernetes]\ncluster-name = 'first'\ncluster-name = 'second'\n", nil, true},
		{"al2_literal", "#!/bin/bash\n/etc/eks/bootstrap.sh 'my-cluster' --b64-cluster-ca PRIVATE-CA\n", map[string]string{"my-cluster": "IMDS AL2 bootstrap data"}, false},
		{"al2_continuation", "#!/bin/bash\nsudo /etc/eks/bootstrap.sh \\\n\"my-cluster\" --kubelet-extra-args 'other data'\n", map[string]string{"my-cluster": "IMDS AL2 bootstrap data"}, false},
		{"al2_multiple", "/etc/eks/bootstrap.sh first\n/etc/eks/bootstrap.sh second\n", map[string]string{"first": "IMDS AL2 bootstrap data", "second": "IMDS AL2 bootstrap data"}, false},
		{"al2_dynamic", "#!/bin/bash\n/etc/eks/bootstrap.sh \"${CLUSTER_NAME}\"\n", map[string]string{}, false},
		{"al2_command_substitution", "/etc/eks/bootstrap.sh $(curl https://do-not-request.example)\n", map[string]string{}, false},
		{"al2_backtick", "/etc/eks/bootstrap.sh `cat /host/cluster`\n", map[string]string{}, false},
		{"al2_comment", "# /etc/eks/bootstrap.sh fake\n", map[string]string{}, false},
		{"al2_echo", "echo '/etc/eks/bootstrap.sh fake'\n", map[string]string{}, false},
		{"al2_heredoc", "#!/bin/bash\ncat <<'EOF'\n/etc/eks/bootstrap.sh fake\nEOF\n", map[string]string{}, false},
		{"al2_multiline_quote", "#!/bin/bash\necho '\n/etc/eks/bootstrap.sh fake\n'\n", map[string]string{}, false},
		{"shell_embedded_toml", "#!/bin/bash\ncat <<'EOF'\n[settings.kubernetes]\ncluster-name = 'fake'\nEOF\n", map[string]string{}, false},
		{"toml_embedded_setting", "[settings.other]\nvalue = '''\n[settings.kubernetes]\ncluster-name = 'fake'\n'''\n", map[string]string{}, false},
		{"al2_unclosed_quote", "/etc/eks/bootstrap.sh 'bad\n", map[string]string{}, false},
		{"al2023_invalid_name", "apiVersion: node.eks.aws/v1alpha1\nkind: NodeConfig\nspec:\n  cluster:\n    name: ../PRIVATE\n", nil, true},
		{"al2023_duplicate_key", "apiVersion: node.eks.aws/v1alpha1\nkind: NodeConfig\nspec:\n  cluster:\n    name: first\n    name: second\n", nil, true},
		{"opaque", "opaque cloud init custom configuration", map[string]string{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := bootstrapClusterCandidates([]byte(tc.data))
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v", err)
			}
			if !tc.wantError && !reflect.DeepEqual(result, tc.want) {
				t.Fatalf("candidates = %v, want %v", result, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("bootstrap content leaked")
			}
		})
	}
}

func TestNodeBootstrapMultipartMergeAndSources(t *testing.T) {
	data := `MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: application/node.eks.aws

apiVersion: node.eks.aws/v1alpha1
kind: NodeConfig
spec:
  cluster:
    name: first
--BOUNDARY
Content-Type: application/node.eks.aws

apiVersion: node.eks.aws/v1alpha1
kind: NodeConfig
spec:
  cluster:
    name: last
--BOUNDARY
Content-Type: application/node.eks.aws

apiVersion: node.eks.aws/v1alpha1
kind: NodeConfig
spec:
  kubelet:
    config: {}
--BOUNDARY
Content-Type: text/x-shellscript

#!/bin/bash
/etc/eks/bootstrap.sh other-cluster
--BOUNDARY
Content-Type: text/x-shellscript

#!/bin/bash
cat <<'EOF' > /etc/eks/nodeadm.d/custom.yaml
apiVersion: node.eks.aws/v1alpha1
kind: NodeConfig
spec:
  cluster:
    name: not-a-mime-nodeconfig
EOF
--BOUNDARY
Content-Type: application/octet-stream

/etc/eks/bootstrap.sh ignored
--BOUNDARY--
`
	got, err := bootstrapClusterCandidates([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"last": "IMDS AL2023 NodeConfig bootstrap data", "other-cluster": "IMDS AL2 bootstrap data"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("multipart merge = %v", got)
	}
}

func TestNodeBootstrapMultipartLimitAndMalformed(t *testing.T) {
	base := "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=B\n\n"
	for _, data := range []string{base + "--B\nContent-Type: application/node.eks.aws\n\ntruncated", base + strings.Repeat("--B\nContent-Type: application/octet-stream\n\nignored\n", 33) + "--B--\n"} {
		if _, err := bootstrapClusterCandidates([]byte(data)); err == nil {
			t.Fatal("unbounded or malformed multipart accepted")
		}
	}
}
