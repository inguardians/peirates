package peirates

import "fmt"

func interactiveNSMenu(connectionString *ServerInfo) {

	println(`
			[1] List namespaces [list]
			[2] Switch namespace [switch]
			`)
	var input string

	_, err := fmt.Scanln(&input)
	if err != nil {
		fmt.Printf("Error reading input: %s\n", err.Error())
		pauseToHitEnter(true)
		return
	}

	switch input {
	case "1", "list":
		listNamespaces(*connectionString)

	case "2", "switch":
		menuSwitchNamespaces(connectionString)

	default:
		break
	}
}
