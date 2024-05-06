package peirates

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ergochat/readline"
)

func setUpCompletionSaMenu() *readline.PrefixCompleter {
	completer := readline.NewPrefixCompleter(
		// [1] List service accounts [list]
		readline.PcItem("list"),
		// [2] Switch primary service account [switch]
		readline.PcItem("switch"),
		// [3] Enter new service account JWT [add]
		readline.PcItem("add"),
		// [4] Export service accounts to JSON [export]
		readline.PcItem("export"),
		// [5] Import service accounts from JSON [import]
		readline.PcItem("import"),
		// [6] Decode a stored or entered service account token (JWT) [decode]
		readline.PcItem("decode"),
		// [7] Display a stored service account token in its raw form [display]
		readline.PcItem("display"),
	)
	return completer
}

func saMenu(serviceAccounts *[]ServiceAccount, connectionString *ServerInfo, interactive bool) {

	// Set up main menu tab completion
	var completer *readline.PrefixCompleter = setUpCompletionSaMenu()

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

	println("Current primary service account: ", connectionString.TokenName)
	println("\n")
	println("[1] List service accounts [list]")
	println("[2] Switch primary service account [switch]")
	println("[3] Enter new service account JWT [add]")
	println("[4] Export service accounts to JSON [export]")
	println("[5] Import service accounts from JSON [import]")
	println("[6] Decode a stored or entered service account token (JWT) [decode]")
	println("[7] Display a stored service account token in its raw form [display]")

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

	switch strings.ToLower(input) {
	case "1", "list":
		listServiceAccounts(*serviceAccounts, *connectionString)
	case "2", "switch":
		switchServiceAccounts(*serviceAccounts, connectionString)
	case "3", "add":
		serviceAccount := acceptServiceAccountFromUser()
		*serviceAccounts = append(*serviceAccounts, serviceAccount)

		println()
		println("[1] Switch to this service account")
		println("[2] Maintain current service account")
		_, err = fmt.Scanln(&input)
		if err != nil {
			fmt.Printf("Error reading input: %s\n", err.Error())
			pauseToHitEnter(interactive)
			return
		}

		switch input {
		case "1":
			assignServiceAccountToConnection(serviceAccount, connectionString)

		case "2":
			pauseToHitEnter(interactive)
			return
		default:
			println("Input not understood - adding service account but not switching context")
		}
		println("")
	case "4", "export":
		serviceAccountJSON, err := json.Marshal(serviceAccounts)
		if err != nil {
			fmt.Printf("[-] Error exporting service accounts: %s\n", err.Error())
			pauseToHitEnter(interactive)
			return
		} else {
			println(string(serviceAccountJSON))
		}
	case "5", "import":
		var newserviceAccounts []ServiceAccount
		println("Please enter service account token")
		err := json.NewDecoder(os.Stdin).Decode(&newserviceAccounts)
		if err != nil {
			fmt.Printf("[-] Error importing service accounts: %s\n", err.Error())
			pauseToHitEnter(interactive)
			return
		} else {
			*serviceAccounts = append(*serviceAccounts, newserviceAccounts...)
			fmt.Printf("[+] Successfully imported service accounts\n")
		}
	case "6", "decode":
		var token string
		println("\n1) Decode a JWT entered via a string.")
		println("2) Decode a service account token stored here.")
		println("Peirates:># ")
		_, err = fmt.Scanln(&input)

		if err != nil {
			fmt.Printf("[-] Error reading input: %s\n", err.Error())
			pauseToHitEnter(interactive)
			return
		}

		switch input {
		case "1":
			println("\nEnter a JWT: ")
			_, err = fmt.Scanln(&token)
			if err != nil {
				print("Error reading input: %s\n", err.Error())
				pauseToHitEnter(interactive)
				return
			}
			printJWT(token)
		case "2":
			println("\nAvailable Service Accounts:")
			for i, account := range *serviceAccounts {
				if account.Name == connectionString.TokenName {
					fmt.Printf("> [%d] %s\n", i, account.Name)
				} else {
					fmt.Printf("  [%d] %s\n", i, account.Name)
				}
			}
			println("\nEnter service account number or exit to abort: ")
			var tokNum int
			_, err = fmt.Scanln(&input)
			if input == "exit" {
				pauseToHitEnter(interactive)
				return
			}
			_, err := fmt.Sscan(input, &tokNum)
			if err != nil {
				fmt.Printf("Error parsing service account selection: %s\n", err.Error())
				pauseToHitEnter(interactive)
				return
			} else if tokNum < 0 || tokNum >= len(*serviceAccounts) {
				fmt.Printf("Service account %d does not exist!\n", tokNum)
				pauseToHitEnter(interactive)
				return
			} else {
				printJWT((*serviceAccounts)[tokNum].Token)
			}
		}
	case "7", "display":
		displayServiceAccountTokenInteractive(*serviceAccounts, connectionString)

	}
}
