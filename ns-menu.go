package peirates

import (
	"fmt"
	"io"
	"strings"

	"github.com/ergochat/readline"
)

func setUpCompletionNsMenu() *readline.PrefixCompleter {
	completer := readline.NewPrefixCompleter(
		// [1] List namespaces [list]
		readline.PcItem("list"),
		// [2] Switch namespace [switch]
		readline.PcItem("switch"),
	)
	return completer
}

func interactiveNSMenu(connectionString *ServerInfo) {

	// Set up main menu tab completion
	var completer *readline.PrefixCompleter = setUpCompletionNsMenu()

	l, err := readline.NewEx(&readline.Config{
		Prompt:          "\033[31m»\033[0m ",
		HistoryFile:     "/tmp/peirates.history",
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

	println(`
			[1] List namespaces [list]
			[2] Switch namespace [switch]
			`)

	var input string

	line, err := l.Readline()
	if err == readline.ErrInterrupt {
		if len(line) == 0 {
			println("Empty line")
			pauseToHitEnter(true)
			return
		}
	} else if err == io.EOF {
		println("Empty line")
		pauseToHitEnter(true)
		return
	}
	input = strings.TrimSpace(line)

	if err != nil {
		return
	}

	switch input {
	case "1", "list":
		listNamespaces(*connectionString)

	case "2", "switch":
		menuSwitchNamespaces(connectionString)

	default:
		fmt.Printf("You must choose option from the options above.")
		pauseToHitEnter(true)
		return
	}
}
