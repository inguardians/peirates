package ui

import "testing"

func TestMainMenuCompletionOrder(t *testing.T) {
	completer := SetUpCompletionMainMenu()
	if len(completer.Children) != len(mainMenuCommands) {
		t.Fatalf("got %d entries, want %d", len(completer.Children), len(mainMenuCommands))
	}
	for i, command := range mainMenuCommands {
		if completer.Children[i].Name != command+" " {
			t.Fatalf("entry %d = %q, want %q", i, completer.Children[i].Name, command)
		}
	}
}
