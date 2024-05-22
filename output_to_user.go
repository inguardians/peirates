//Build API configuration (svc account token, namespace, API server) -- automated prereq for other steps

package peirates

import (
	"os"
)

func outputToUser(kubectlOutputString string, logToFile bool, outputFileName string) {

	println(kubectlOutputString)

	if logToFile {
		file, err := os.OpenFile(outputFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			println("[-] Could not open file: ", outputFileName)
			return
		}

		_, err = file.WriteString(kubectlOutputString)
		if err != nil {
			println("[-] Could not write to file: ", outputFileName)
			return
		}

		file.Close()

	}

}
