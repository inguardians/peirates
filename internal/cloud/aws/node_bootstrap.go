package aws

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// bootstrapClusterCandidates deliberately extracts only recognized literal
// configuration. Nothing is executed and no endpoint or CA is adopted from it.
func bootstrapClusterCandidates(data []byte) (map[string]string, error) {
	result := map[string]string{}
	type bootstrapPart struct {
		data      []byte
		mediaType string
	}
	parts := []bootstrapPart{{data: data}}
	if message, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
		mediaType, parameters, typeErr := mime.ParseMediaType(message.Header.Get("Content-Type"))
		if typeErr == nil && strings.HasPrefix(mediaType, "multipart/") {
			if parameters["boundary"] == "" {
				return nil, errors.New("bootstrap MIME data has no boundary")
			}
			parts = nil
			reader := multipart.NewReader(message.Body, parameters["boundary"])
			for {
				part, partErr := reader.NextPart()
				if partErr == io.EOF {
					break
				}
				if partErr != nil {
					return nil, errors.New("invalid bootstrap MIME data")
				}
				if len(parts) >= 32 {
					_ = part.Close()
					return nil, errors.New("bootstrap MIME data exceeds 32 parts")
				}
				body, readErr := readNodeResponse(part)
				_ = part.Close()
				if readErr != nil {
					return nil, readErr
				}
				partType, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
				if partType == "application/node.eks.aws" || partType == "text/x-shellscript" || partType == "text/plain" || partType == "" {
					parts = append(parts, bootstrapPart{data: body, mediaType: partType})
				} else {
					// Count unrecognized parts against the work limit as well.
					parts = append(parts, bootstrapPart{})
				}
			}
		}
	}
	mergedNodeName := ""
	for _, part := range parts {
		if len(part.data) == 0 {
			continue
		}
		format := part.mediaType
		if format == "" || format == "text/plain" {
			format = inferBootstrapFormat(part.data)
		}
		if format == "application/node.eks.aws" {
			name, recognized, err := nodeConfigName(part.data)
			if err != nil {
				return nil, err
			}
			if !recognized {
				return nil, errors.New("bootstrap NodeConfig has an unsupported kind or API version")
			}
			// nodeadm merges configs in document order, with later nonzero fields
			// taking precedence. A later partial config preserves the earlier name.
			if name != "" {
				mergedNodeName = name
			}
			continue
		}
		if format == "application/toml" {
			bottleName, err := bottlerocketClusterName(string(part.data))
			if err != nil {
				return nil, err
			}
			if bottleName != "" {
				result[bottleName] = "IMDS Bottlerocket bootstrap data"
			}
			continue
		}
		for _, cluster := range al2ClusterNames(string(part.data)) {
			result[cluster] = "IMDS AL2 bootstrap data"
		}
	}
	if mergedNodeName != "" {
		result[mergedNodeName] = "IMDS AL2023 NodeConfig bootstrap data"
	}
	return result, nil
}

func inferBootstrapFormat(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#!") {
			return "text/x-shellscript"
		}
		if line == "" || line == "---" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			return "application/toml"
		}
		for _, key := range []string{"apiVersion:", "kind:", "spec:", "metadata:", "{"} {
			if strings.HasPrefix(line, key) {
				return "application/node.eks.aws"
			}
		}
		break
	}
	return "text/x-shellscript"
}

func nodeConfigName(data []byte) (string, bool, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	name, recognized := "", false
	for count := 0; ; count++ {
		var config struct {
			APIVersion string `yaml:"apiVersion"`
			Kind       string `yaml:"kind"`
			Spec       struct {
				Cluster struct {
					Name string `yaml:"name"`
				} `yaml:"cluster"`
			} `yaml:"spec"`
		}
		err := decoder.Decode(&config)
		if err == io.EOF {
			return name, recognized, nil
		}
		if count >= 32 {
			return "", false, errors.New("bootstrap YAML exceeds 32 documents")
		}
		if err != nil {
			if recognized || bytes.Contains(data, []byte("kind: NodeConfig")) {
				return "", false, errors.New("invalid bootstrap NodeConfig YAML")
			}
			return "", false, nil
		}
		if config.Kind != "NodeConfig" || config.APIVersion != "node.eks.aws/v1alpha1" {
			continue
		}
		recognized = true
		if config.Spec.Cluster.Name != "" {
			if !clusterNamePattern.MatchString(config.Spec.Cluster.Name) {
				return "", false, errors.New("bootstrap NodeConfig contains an invalid cluster name")
			}
			name = config.Spec.Cluster.Name
		}
	}
}

func bottlerocketClusterName(data string) (string, error) {
	// Multiline TOML strings can contain fake table/setting lines. They are
	// outside this bounded parser's supported literal configuration subset.
	if strings.Contains(data, `"""`) || strings.Contains(data, "'''") {
		return "", nil
	}
	inKubernetes, seen := false, false
	name := ""
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 4096), nodeResponseLimit)
	for scanner.Scan() {
		line := strings.TrimSpace(stripBootstrapComment(scanner.Text()))
		if strings.HasPrefix(line, "[") {
			inKubernetes = line == "[settings.kubernetes]"
			continue
		}
		if !inKubernetes {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || (key != "cluster-name" && key != `"cluster-name"` && key != "'cluster-name'") {
			continue
		}
		if seen {
			return "", errors.New("bootstrap Bottlerocket data contains duplicate cluster-name settings")
		}
		seen = true
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			name = value[1 : len(value)-1]
		} else {
			var err error
			name, err = strconv.Unquote(value)
			if err != nil {
				return "", errors.New("bootstrap Bottlerocket cluster-name is not a literal string")
			}
		}
		if !clusterNamePattern.MatchString(name) {
			return "", errors.New("bootstrap Bottlerocket contains an invalid cluster name")
		}
	}
	if scanner.Err() != nil {
		return "", errors.New("bootstrap data contains an oversized line")
	}
	return name, nil
}

func stripBootstrapComment(line string) string {
	var quote rune
	escape := false
	for i, r := range line {
		if escape {
			escape = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escape = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' {
			return line[:i]
		}
	}
	return line
}

func al2ClusterNames(data string) []string {
	data = strings.ReplaceAll(data, "\\\r\n", "")
	data = strings.ReplaceAll(data, "\\\n", "")
	// Embedded scripts and heredocs need full shell evaluation to establish
	// which invocation will execute. Reject these ambiguous scripts wholesale.
	for _, line := range strings.Split(data, "\n") {
		line = stripBootstrapComment(line)
		if strings.Contains(line, "<<") || unbalancedShellQuote(line) {
			return nil
		}
	}
	var names []string
	for _, line := range strings.Split(data, "\n") {
		tokens := literalShellWords(stripBootstrapComment(line))
		for len(tokens) > 0 && (tokens[0] == "sudo" || tokens[0] == "exec" || tokens[0] == "bash" || tokens[0] == "/bin/bash" || tokens[0] == "sh" || tokens[0] == "/bin/sh") {
			tokens = tokens[1:]
		}
		if len(tokens) >= 2 && tokens[0] == "/etc/eks/bootstrap.sh" && clusterNamePattern.MatchString(tokens[1]) {
			names = append(names, tokens[1])
		}
	}
	return names
}

func unbalancedShellQuote(line string) bool {
	var quote rune
	escape := false
	for _, r := range line {
		if escape {
			escape = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escape = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
		}
	}
	return quote != 0 || escape
}

// literalShellWords handles quoting and escapes but rejects expansion in any
// token before the first shell operator. It is intentionally not a shell parser.
func literalShellWords(line string) []string {
	var words []string
	var word strings.Builder
	var quote rune
	active, escape, dynamic := false, false, false
	flush := func() {
		if active {
			if dynamic {
				words = append(words, "")
			} else {
				words = append(words, word.String())
			}
		}
		word.Reset()
		active, dynamic = false, false
	}
	for _, r := range line {
		if escape {
			word.WriteRune(r)
			active, escape = true, false
			continue
		}
		if r == '\\' && quote != '\'' {
			escape, active = true, true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				if quote == '"' && (r == '$' || r == '`') {
					dynamic = true
				}
				word.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote, active = r, true
			continue
		}
		if strings.ContainsRune(";|&<>()", r) {
			break
		}
		if r == ' ' || r == '\t' || r == '\r' {
			flush()
			continue
		}
		if r == '$' || r == '`' || r == '*' || r == '?' {
			dynamic = true
		}
		word.WriteRune(r)
		active = true
	}
	if quote != 0 || escape {
		return nil
	}
	flush()
	return words
}
