package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/inguardians/peirates/internal/cloud/azure"
)

var azureMetadataClient = azure.NewMetadataClient()
var azureConfigPath = azure.DefaultConfigPath

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
		identity := fmt.Sprintf("%s %q", key.IdentityType, key.Identity)
		if claims, err := azure.DecodeIdentityClaims(entry.Token.AccessToken); err == nil {
			resourceID := strings.TrimRight(claims.ManagedIdentityResourceID, "/")
			if slash := strings.LastIndex(resourceID, "/"); slash >= 0 {
				if name := resourceID[slash+1:]; strings.TrimSpace(name) != "" {
					identity = fmt.Sprintf("managed identity %q (%s)", name, identity)
				}
			}
		}
		lines = append(lines, fmt.Sprintf("[+] Azure token (%s): %s; resource %q; expires %s\n", state, identity, key.Resource, entry.Token.ExpiresOn.UTC().Format(time.RFC3339)))
	}
	sort.Strings(lines)
	for _, line := range lines {
		fmt.Fprint(out, line)
	}
}

const azureTokenUsage = `Usage: azure-get-token [--resource URI] [--client-id ID | --object-id ID | --msi-res-id ID]
                       [--list-identities | --no-discovery]
Aliases: 36, get-azure-token
Bare interactive invocation prompts for resource and identity. Options and -m skip prompts.
Without an explicit identity, discover client IDs from /etc/kubernetes/azure.json and AKS IMDS tags.
A single candidate is the default; multiple candidates require a choice or --client-id.
--list-identities shows candidates and their sources without requesting a token.
--no-discovery uses IMDS default selection when no explicit identity is provided.
Default resource: https://management.azure.com/; no candidates: IMDS default selection.
`

type azureTokenOptions struct {
	azure.TokenRequest
	listIdentities bool
	noDiscovery    bool
}

func printAzureIdentityDiscovery(out io.Writer, discovery azure.IdentityDiscovery) {
	for _, warning := range discovery.Warnings {
		fmt.Fprintf(out, "[!] Azure identity discovery: %v\n", warning)
	}
	if len(discovery.Candidates) == 0 {
		fmt.Fprintln(out, "[*] No Azure client IDs discovered from node config or AKS IMDS tags; identities may still be assigned.")
		return
	}
	fmt.Fprintln(out, "[+] Azure identity candidates (IMDS availability is confirmed when requesting a token):")
	for i, candidate := range discovery.Candidates {
		fmt.Fprintf(out, "  %d. %s\n     Source: %s\n", i+1, candidate.ClientID, strings.Join(candidate.Sources, "; "))
	}
}

func azureTokenSelection(args []string, interactive bool, in io.Reader, out io.Writer) (azureTokenOptions, error) {
	selection := azureTokenOptions{TokenRequest: azure.TokenRequest{Resource: azure.DefaultResource}}
	flags := flag.NewFlagSet("azure-get-token", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&selection.Resource, "resource", azure.DefaultResource, "resource URI")
	flags.StringVar(&selection.ClientID, "client-id", "", "managed identity client ID")
	flags.StringVar(&selection.ObjectID, "object-id", "", "managed identity object ID")
	flags.StringVar(&selection.MSIResourceID, "msi-res-id", "", "managed identity resource ID")
	flags.BoolVar(&selection.listIdentities, "list-identities", false, "list discovered identity candidates without requesting a token")
	flags.BoolVar(&selection.noDiscovery, "no-discovery", false, "skip identity discovery")
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
	if err := selection.Validate(); err != nil {
		return selection, err
	}
	identityKind, _ := azureIdentity(selection.TokenRequest)
	if selection.listIdentities && (selection.noDiscovery || identityKind != "default") {
		return selection, errors.New("--list-identities cannot be combined with an identity selector or --no-discovery")
	}
	if identityKind != "default" {
		return selection, nil
	}
	prompt := len(args) == 0 && interactive
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
	if prompt {
		resource, err := read("Resource URI [" + azure.DefaultResource + "]: ")
		if err != nil {
			return selection, err
		}
		if resource != "" {
			selection.Resource = resource
		}
	}
	var discovery azure.IdentityDiscovery
	if !selection.noDiscovery {
		discovery = azureMetadataClient.DiscoverIdentities(context.Background(), azureConfigPath)
		printAzureIdentityDiscovery(out, discovery)
	}
	if selection.listIdentities {
		return selection, nil
	}
	if prompt {
		identityPrompt := "Identity [default/client-id/object-id/msi-res-id] [default]: "
		defaultIdentity := "default"
		if len(discovery.Candidates) == 1 {
			identityPrompt = "Identity [1/default/client-id/object-id/msi-res-id] [1]: "
			defaultIdentity = "1"
		} else if len(discovery.Candidates) > 1 {
			identityPrompt = fmt.Sprintf("Identity [1-%d/default/client-id/object-id/msi-res-id] (required): ", len(discovery.Candidates))
			defaultIdentity = ""
		}
		kind, err := read(identityPrompt)
		if err != nil {
			return selection, err
		}
		if kind == "" {
			kind = defaultIdentity
		}
		switch kind {
		case "default":
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
			index, err := strconv.Atoi(kind)
			if err != nil || index < 1 || index > len(discovery.Candidates) {
				return selection, errors.New("identity must be a listed number, default, client-id, object-id, or msi-res-id; multiple candidates require an explicit choice")
			}
			selection.ClientID = discovery.Candidates[index-1].ClientID
		}
	} else {
		switch len(discovery.Candidates) {
		case 0:
			// Preserve default IMDS selection if neither source supplied a candidate.
		case 1:
			selection.ClientID = discovery.Candidates[0].ClientID
			fmt.Fprintf(out, "[*] Using discovered client ID: %s\n", selection.ClientID)
		default:
			return selection, errors.New("multiple Azure identity candidates found; select one with --client-id ID")
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
	if selection.listIdentities {
		return
	}
	token, err := azureMetadataClient.RequestToken(context.Background(), selection.TokenRequest)
	if err != nil {
		fmt.Fprintf(out, "[-] Azure token: %v\n", err)
		return
	}
	session.retainAzureToken(selection.TokenRequest, token)
	kind, id := azureIdentity(selection.TokenRequest)
	fmt.Fprintf(out, "[+] Azure managed identity token\nResource: %s\nIdentity selection: %s %s\nExpires (UTC): %s\n", selection.Resource, kind, id, token.ExpiresOn.UTC().Format(time.RFC3339))
	printAzureIdentityClaims(out, token.AccessToken)
	fmt.Fprintf(out, "Bearer token: %s\n", token.AccessToken)
}

func printAzureIdentityClaims(out io.Writer, accessToken string) {
	claims, err := azure.DecodeIdentityClaims(accessToken)
	if err != nil {
		fmt.Fprintf(out, "Decoded identity claims: unavailable (%v).\n", err)
		return
	}
	if claims == (azure.IdentityClaims{}) {
		fmt.Fprintln(out, "Decoded identity claims: no supported identity fields present.")
		return
	}
	fmt.Fprintln(out, "Decoded identity claims (signature not verified):")
	for _, field := range []struct{ label, value string }{
		{"Managed identity:", claims.ManagedIdentityResourceID},
		{"Client ID:", claims.ClientID},
		{"Principal ID:", claims.PrincipalID},
		{"Tenant ID:", claims.TenantID},
		{"Source resource:", claims.SourceResourceID},
	} {
		if field.value != "" {
			// Escape control characters so claims cannot inject terminal output.
			quoted := strconv.Quote(field.value)
			fmt.Fprintf(out, "  %-17s %s\n", field.label, quoted[1:len(quoted)-1])
		}
	}
}
