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
		readline.PcItem("listsa"),
		// [2] Switch primary service account [switch]
		readline.PcItem("switchsa"),
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

func saMenu(serviceAccounts *[]ServiceAccount, connectionString *ServerInfo, interactive bool, logToFile bool, outputFileName string) {

	// Set up main menu tab completion
	var completer *readline.PrefixCompleter = setUpCompletionSaMenu()

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

	if len(connectionString.TokenName) != 0 {
		println("Current primary service account: ", connectionString.TokenName)
	}

	println(`
	[1] List service accounts [listsa]
	[2] Switch primary service account [switchsa]
	[3] Enter new service account JWT [add]
	[4] Export service accounts to JSON [export]
	[5] Import service accounts from JSON [import]
	[6] Decode a stored or entered service account token (JWT) [decode]
	[7] Display a stored service account token in its raw form [display]
	`)
	fmt.Printf("\nPeirates (service account menu):># ")

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
	case "1", "list", "listsa":
		listServiceAccounts(*serviceAccounts, *connectionString, logToFile, outputFileName)
	case "2", "switch", "switchsa":
		switchServiceAccounts(*serviceAccounts, connectionString, logToFile, outputFileName)
	case "3", "add":
		serviceAccount, err := acceptServiceAccountFromUser()
		if err != nil {
			fmt.Printf("Error accepting service account - encountered error: %s\n", err.Error())
			pauseToHitEnter(interactive)
			return
		}
		*serviceAccounts = append(*serviceAccounts, serviceAccount)

		println(`
		[1] Switch to this service account
		[2] Maintain current service account
		`)
		fmt.Printf("\nPeirates (add svc acct):># ")

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
	case "4", "export", "exportsa":
		serviceAccountJSON, err := json.Marshal(serviceAccounts)
		if err != nil {
			fmt.Printf("[-] Error exporting service accounts: %s\n", err.Error())
			pauseToHitEnter(interactive)
			return
		} else {
			outputToUser(string(serviceAccountJSON), logToFile, outputFileName)
		}
	case "5", "import", "importsa":
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
		println(`
		1) Decode a JWT entered via a string.
		2) Decode a service account token stored here.

		`)
		fmt.Printf("\nPeirates (decode):># ")

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
		displayServiceAccountTokenInteractive(*serviceAccounts, connectionString, logToFile, outputFileName)

	}
}
