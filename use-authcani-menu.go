package peirates

import (
	"fmt"
	"strings"
)

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

	var input string

	_, err := fmt.Scanln(&input)
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
