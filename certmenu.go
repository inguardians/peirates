package peirates

import (
	"fmt"
	"io"
	"strings"

	"github.com/ergochat/readline"
)

func setUpCompletionCertMenu() *readline.PrefixCompleter {
	completer := readline.NewPrefixCompleter(
		readline.PcItem("list"),
		readline.PcItem("switch"),
	)
	return completer
}

func certMenu(clientCertificates *[]ClientCertificateKeyPair, connectionString *ServerInfo, interactive bool) {

	// Set up main menu tab completion
	var completer *readline.PrefixCompleter = setUpCompletionCertMenu()

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

	println("Current certificate-based authentication: ", connectionString.ClientCertName)
	println(` 

	[1] List client certificates [list]
	[2] Switch active client certificates [switch]

	Peirates (certmenu):>#`)
	// println("[3] Enter new client certificate and key [add]")
	// println("[4] Export service accounts to JSON [export]")
	// println("[5] Import service accounts from JSON [import]")
	// println("[6] Decode a stored or entered service account token (JWT) [decode]")

	println("\n")

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
		return
	}

	switch strings.ToLower(input) {
	case "1", "list":
		println("\nAvailable Client Certificate/Key Pairs:")
		for i, account := range *clientCertificates {
			fmt.Printf("  [%d] %s\n", i, account.Name)
		}
	case "2", "switch":
		println("\nAvailable Client Certificate/Key Pairs:")
		for i, account := range *clientCertificates {
			fmt.Printf("  [%d] %s\n", i, account.Name)
		}
		println("\nEnter certificate/key pair number or exit to abort: ")
		var tokNum int
		_, err = fmt.Scanln(&input)
		if err != nil {
			fmt.Printf("Error reading input: %s\n", err.Error())
			pauseToHitEnter(interactive)
			return
		}
		if input == "exit" {
			pauseToHitEnter(interactive)
			return
		}

		_, err := fmt.Sscan(input, &tokNum)
		if err != nil {
			fmt.Printf("Error parsing certificate/key pair selection: %s\n", err.Error())
		} else if tokNum < 0 || tokNum >= len(*clientCertificates) {
			fmt.Printf("Certificate/key pair  %d does not exist!\n", tokNum)
		} else {
			assignAuthenticationCertificateAndKeyToConnection((*clientCertificates)[tokNum], connectionString)
			fmt.Printf("Selected %s\n", connectionString.ClientCertName)
		}
	}
}
