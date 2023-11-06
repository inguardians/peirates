package peirates

import (
	"fmt"
	"strings"
)

func kubectl_interactive(connectionString ServerInfo) error {
	println(`
This function allows you to run a kubectl command, with only a few restrictions.

Your command must not:

- specify a different service account 
- use a different API server
- run for longer than a few seconds (as in kubectl exec)

Your command will crash this program if it is not permitted.

These requirements are dynamic - watch new versions for changes.

Leave off the "kubectl" part of the command.  For example:

- get pods
- get pod podname -o yaml
- get secret secretname -o yaml

`)

	// FEATURE IDEA/TODO: allow any output to be saved into raw text and/or structured objects (YAML/JSON)
        //                    save this output in a named object that the user can recall, parse with jq-type stuff.

	fmt.Printf("Please enter a kubectl command: ")
	input, err := ReadLineStripWhitespace()

	arguments := strings.Fields(input)

	kubectlOutput, _, err := runKubectlSimple(connectionString, arguments...)
	if err != nil {
		println("[-] Could not perform action: kubectl ", input)
		return err
	}
	kubectlOutputLines := strings.Split(string(kubectlOutput), "\n")
	for _, line := range kubectlOutputLines {
		println(line)
	}
	return nil
}
