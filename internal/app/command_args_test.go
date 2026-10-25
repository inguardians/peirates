package app

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseCommandArgs(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []string
		wantError string
	}{
		{name: "words", input: "cat /etc/shadow", want: []string{"cat", "/etc/shadow"}},
		{name: "quotes and escapes", input: `printf "%s %s" 'two words' escaped\ value ""`, want: []string{"printf", "%s %s", "two words", "escaped value", ""}},
		{name: "unterminated quote", input: `echo "unfinished`, wantError: "unterminated quote"},
		{name: "trailing escape", input: `echo trailing\`, wantError: "trailing escape"},
		{name: "empty", input: "   ", wantError: "command is empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseCommandArgs(test.input)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCommandArgs: %v", err)
			}
			if fmt.Sprint(got) != fmt.Sprint(test.want) {
				t.Fatalf("argv = %#v, want %#v", got, test.want)
			}
		})
	}
}
