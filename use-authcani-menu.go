package peirates

import (
	"io"
	"strings"

	"github.com/ergochat/readline"
)

func setUpCompletionAuthCanIMenu() *readline.PrefixCompleter {
	completer := readline.NewPrefixCompleter(
		// [true] Set peirates to check whether an action is permitted
		readline.PcItem("true"),
		// [false] Set peirates to skip the auth can-i check
		readline.PcItem("false"),
		// [exit] Leave the setting at its current value
		readline.PcItem("exit"),
	)
	return completer
}

func setAuthCanIMenu(UseAuthCanI *bool, interactive bool) {

	// Toggle UseAuthCanI between true and false
	println("\nWhen Auth-Can-I is set to true, Peirates uses the kubectl auth can-i feature to determine if an action is permitted before taking it.")
	println("Toggle this to false if auth can-i results aren't accurate for this cluster.")
	println("Auth-Can-I is currently set to ", *UseAuthCanI)
	println("\nPlease choose a new value for Auth-Can-I:")
	println("[true] Set peirates to check whether an action is permitted")
	println("[false] Set peirates to skip the auth can-i check")
	println("[exit] Leave the setting at its current value")

	println("\nChoice: ")

	// Set up main menu tab completion
	var completer *readline.PrefixCompleter = setUpCompletionAuthCanIMenu()

	l, err := readline.NewEx(&readline.Config{
		Prompt:          "\033[31m»\033[0m ",
		HistoryFile:     "/tmp/peirates.tmp",
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",

		HistorySearchFold: true,
		// FuncFilterInputRune: filterInput,
	})
	if err != nil {
		panic(err)
	}
	defer l.Close()
	// l.CaptureExitSignal()

	var input string

	line, err := l.Readline()
	if err == readline.ErrInterrupt {
		if len(line) == 0 {
			println("Empty line")
			pauseToHitEnter(interactive)
			return
		}
	} else if err == io.EOF {
		println("Empty line")
		pauseToHitEnter(interactive)
		return
	}
	input = strings.TrimSpace(line)

	if err != nil {
		println("Error reading input: %v", err)
		pauseToHitEnter(interactive)
		return
	}

	switch strings.ToLower(input) {
	case "exit":
		return
	case "true", "1", "t":
		*UseAuthCanI = true
	case "false", "0", "f":
		*UseAuthCanI = false
	}
	// Skip the "press enter to continue"

}
