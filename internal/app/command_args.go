package app

import (
	"errors"
	"strings"
	"unicode"
)

// parseCommandArgs splits quoted and escaped arguments without shell expansion.
func parseCommandArgs(commandLine string) ([]string, error) {
	var argv []string
	var current strings.Builder
	var quote rune
	escaped := false
	tokenStarted := false

	flush := func() {
		argv = append(argv, current.String())
		current.Reset()
		tokenStarted = false
	}

	for _, character := range commandLine {
		if escaped {
			current.WriteRune(character)
			escaped = false
			tokenStarted = true
			continue
		}
		if quote != 0 {
			switch {
			case character == quote:
				quote = 0
			case quote == '"' && character == '\\':
				escaped = true
			default:
				current.WriteRune(character)
			}
			continue
		}

		switch {
		case unicode.IsSpace(character):
			if tokenStarted {
				flush()
			}
		case character == '\'' || character == '"':
			quote = character
			tokenStarted = true
		case character == '\\':
			escaped = true
			tokenStarted = true
		default:
			current.WriteRune(character)
			tokenStarted = true
		}
	}
	if escaped {
		return nil, errors.New("trailing escape")
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if tokenStarted {
		flush()
	}
	if len(argv) == 0 {
		return nil, errors.New("command is empty")
	}
	return argv, nil
}
