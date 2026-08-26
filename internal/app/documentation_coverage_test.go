package app

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type documentedMenuItem struct {
	commands []string
	file     string
}

func TestAdvertisedMainMenuItemsHaveDocumentation(t *testing.T) {
	docsDir := filepath.Join("..", "..", "docs", "commands")
	manifest := readDocumentationManifest(t, filepath.Join(docsDir, "manifest.tsv"))

	advertised := make(map[string]struct{})
	for _, functionName := range []string{"printMenuMinimal", "printMenuClassic"} {
		menuText := menuLiteralFromFunction(t, "menu.go", functionName)
		for _, key := range advertisedMenuKeys(t, menuText) {
			advertised[key] = struct{}{}
		}
	}

	assertSameMenuKeys(t, advertised, manifest)

	for key, item := range manifest {
		path := filepath.Join(docsDir, item.file)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("menu item %q documentation %q cannot be read: %v", key, item.file, err)
			continue
		}
		text := string(content)
		if !strings.HasPrefix(text, "# ") {
			t.Errorf("menu item %q documentation %q must start with a level-one heading", key, item.file)
		}
		for _, command := range item.commands {
			if !strings.Contains(text, "`"+command+"`") {
				t.Errorf("menu item %q documentation %q does not name command %q in code formatting", key, item.file, command)
			}
		}
	}
}

func readDocumentationManifest(t *testing.T, path string) map[string]documentedMenuItem {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	items := make(map[string]documentedMenuItem)
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("%s:%d: expected three tab-separated fields", path, lineNumber)
		}
		key := strings.TrimSpace(fields[0])
		if _, exists := items[key]; exists {
			t.Fatalf("%s:%d: duplicate menu key %q", path, lineNumber, key)
		}
		commands := strings.Split(strings.TrimSpace(fields[1]), ",")
		for index := range commands {
			commands[index] = strings.TrimSpace(commands[index])
		}
		items[key] = documentedMenuItem{commands: commands, file: strings.TrimSpace(fields[2])}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return items
}

func menuLiteralFromFunction(t *testing.T, path, functionName string) string {
	t.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != functionName {
			continue
		}
		var menuText string
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			literal, literalOK := call.Args[0].(*ast.BasicLit)
			if !ok || name.Name != "println" || !literalOK || literal.Kind != token.STRING {
				return true
			}
			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				t.Fatalf("unquote menu literal in %s: %v", functionName, unquoteErr)
			}
			menuText = value
			return false
		})
		if menuText == "" {
			t.Fatalf("%s does not contain a println string literal", functionName)
		}
		return menuText
	}
	t.Fatalf("function %s not found in %s", functionName, path)
	return ""
}

func advertisedMenuKeys(t *testing.T, menuText string) []string {
	t.Helper()

	var keys []string
	for _, rawLine := range strings.Split(menuText, "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		closingBracket := strings.IndexByte(line, ']')
		if closingBracket < 0 {
			t.Fatalf("malformed main-menu line %q", rawLine)
		}
		label := strings.TrimSpace(line[1:closingBracket])
		if label != "" {
			if _, err := strconv.Atoi(label); err != nil {
				keys = append(keys, firstMenuCommand(t, label, rawLine))
				continue
			}
		}

		remainder := line[closingBracket+1:]
		openingCommand := strings.IndexByte(remainder, '[')
		if openingCommand < 0 {
			t.Fatalf("main-menu line has no command annotation: %q", rawLine)
		}
		keys = append(keys, firstMenuCommand(t, remainder[openingCommand+1:], rawLine))
	}
	return keys
}

func firstMenuCommand(t *testing.T, value, line string) string {
	t.Helper()
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == '[' || r == ']'
	})
	if len(fields) == 0 {
		t.Fatalf("cannot find a command in main-menu line %q", line)
	}
	return fields[0]
}

func assertSameMenuKeys(t *testing.T, advertised map[string]struct{}, manifest map[string]documentedMenuItem) {
	t.Helper()

	var undocumented []string
	for key := range advertised {
		if _, ok := manifest[key]; !ok {
			undocumented = append(undocumented, key)
		}
	}
	var unadvertised []string
	for key := range manifest {
		if _, ok := advertised[key]; !ok {
			unadvertised = append(unadvertised, key)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(unadvertised)
	if len(undocumented) > 0 {
		t.Errorf("advertised main-menu items missing from docs/commands/manifest.tsv: %s", strings.Join(undocumented, ", "))
	}
	if len(unadvertised) > 0 {
		t.Errorf("manifest entries not advertised by either main menu: %s", strings.Join(unadvertised, ", "))
	}
}
