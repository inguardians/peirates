package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/inguardians/peirates/internal/cloud/azure"
	"github.com/inguardians/peirates/internal/modules"
)

var azureMetadataClient = azure.NewMetadataClient()

// AzureTokenKey identifies one requested audience and resolved identity.
type AzureTokenKey struct{ IdentityType, Identity, Resource string }

// AzureSessionToken retains the original selector alongside the acquired token.
type AzureSessionToken struct {
	Selection azure.TokenRequest
	Token     azure.Token
}

func azureIdentity(selection azure.TokenRequest) (string, string) {
	switch {
	case selection.ClientID != "":
		return "client_id", selection.ClientID
	case selection.ObjectID != "":
		return "object_id", selection.ObjectID
	case selection.MSIResourceID != "":
		return "msi_res_id", selection.MSIResourceID
	default:
		return "default", ""
	}
}

func (s *Session) retainAzureToken(selection azure.TokenRequest, token azure.Token) {
	kind, id := azureIdentity(selection)
	if token.ClientID != "" {
		kind, id = "client_id", token.ClientID
	}
	if s.AzureTokens == nil {
		s.AzureTokens = make(map[AzureTokenKey]AzureSessionToken)
	}
	s.AzureTokens[AzureTokenKey{kind, id, selection.Resource}] = AzureSessionToken{Selection: selection, Token: token}
}

func printAzureTokenStatus(out io.Writer, session *Session, now time.Time) {
	var lines []string
	for key, entry := range session.AzureTokens {
		state := "available"
		if !entry.Token.ExpiresOn.After(now) {
			state = "expired"
		}
		lines = append(lines, fmt.Sprintf("[+] Azure token (%s): %s %q; resource %q; expires %s\n", state, key.IdentityType, key.Identity, key.Resource, entry.Token.ExpiresOn.UTC().Format(time.RFC3339)))
	}
	sort.Strings(lines)
	for _, line := range lines {
		fmt.Fprint(out, line)
	}
}

const azureTokenUsage = `Usage: azure-get-token [--resource URI] [--client-id ID | --object-id ID | --msi-res-id ID]
Aliases: 36, get-azure-token
Bare interactive invocation prompts for resource and identity. Options and -m skip prompts.
Default resource: https://management.azure.com/; default identity: IMDS selection.
`

func azureTokenSelection(args []string, interactive bool, in io.Reader, out io.Writer) (azure.TokenRequest, error) {
	selection := azure.TokenRequest{Resource: azure.DefaultResource}
	flags := flag.NewFlagSet("azure-get-token", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&selection.Resource, "resource", azure.DefaultResource, "resource URI")
	flags.StringVar(&selection.ClientID, "client-id", "", "managed identity client ID")
	flags.StringVar(&selection.ObjectID, "object-id", "", "managed identity object ID")
	flags.StringVar(&selection.MSIResourceID, "msi-res-id", "", "managed identity resource ID")
	if err := flags.Parse(args); err != nil {
		return selection, err
	}
	if flags.NArg() != 0 {
		return selection, errors.New("unexpected positional arguments")
	}
	var emptyOption, optionAsValue bool
	flags.Visit(func(f *flag.Flag) {
		if strings.TrimSpace(f.Value.String()) == "" {
			emptyOption = true
		}
		if strings.HasPrefix(strings.TrimSpace(f.Value.String()), "-") {
			optionAsValue = true
		}
	})
	if optionAsValue {
		return selection, errors.New("missing option value: values must not begin with a dash")
	}
	if emptyOption {
		return selection, errors.New("options require nonempty values")
	}
	if len(args) == 0 && interactive {
		reader := bufio.NewReader(&singleByteReader{reader: in})
		read := func(prompt string) (string, error) {
			fmt.Fprint(out, prompt)
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("Azure token request cancelled: %w", err)
			}
			if strings.ContainsAny(line, "\x03\x1b") {
				return "", errors.New("Azure token request cancelled")
			}
			return strings.TrimSpace(line), nil
		}
		resource, err := read("Resource URI [" + azure.DefaultResource + "]: ")
		if err != nil {
			return selection, err
		}
		if resource != "" {
			selection.Resource = resource
		}
		kind, err := read("Identity [default/client-id/object-id/msi-res-id] [default]: ")
		if err != nil {
			return selection, err
		}
		switch kind {
		case "", "default":
		case "client-id", "object-id", "msi-res-id":
			id, err := read("Identity " + kind + ": ")
			if err != nil {
				return selection, err
			}
			if id == "" {
				return selection, errors.New("identity identifier is required")
			}
			switch kind {
			case "client-id":
				selection.ClientID = id
			case "object-id":
				selection.ObjectID = id
			case "msi-res-id":
				selection.MSIResourceID = id
			}
		default:
			return selection, errors.New("identity must be default, client-id, object-id, or msi-res-id")
		}
	}
	return selection, selection.Validate()
}

func requestAzureToken(session *Session, args []string, in io.Reader, out io.Writer) {
	selection, err := azureTokenSelection(args, session.Interactive, in, out)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(out, azureTokenUsage)
		return
	}
	if err != nil {
		fmt.Fprintf(out, "[-] Azure token: %v\n", err)
		return
	}
	token, err := azureMetadataClient.RequestToken(context.Background(), selection)
	if err != nil {
		fmt.Fprintf(out, "[-] Azure token: %v\n", err)
		return
	}
	session.retainAzureToken(selection, token)
	kind, id := azureIdentity(selection)
	fmt.Fprintf(out, "[+] Azure managed identity token\nResource: %s\nIdentity selection: %s %s\nExpires (UTC): %s\nBearer token: %s\n", selection.Resource, kind, id, token.ExpiresOn.UTC().Format(time.RFC3339), token.AccessToken)
}

// runModuleCommand preserves registry dispatch and handles only Azure's inline options.
func runModuleCommand(registry *modules.Registry, session *Session, input string) (modules.Result, bool) {
	fields := strings.Fields(input)
	if len(fields) > 1 && canonicalModuleCommand(fields[0]) == "azure-get-token" {
		// This parser handles quotes and escapes without invoking a shell or expansion.
		args, err := parseNodesProxyCommand(input)
		if err != nil {
			fmt.Fprintf(os.Stdout, "[-] Azure token: %v\n", err)
		} else {
			requestAzureToken(session, args[1:], os.Stdin, os.Stdout)
		}
		return modules.Continue, true
	}
	return registry.Run(canonicalModuleCommand(input))
}
