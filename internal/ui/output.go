// Package ui owns terminal output and interactive presentation behavior.
package ui

import "os"

// OutputToUser prints output and optionally appends it to a file.
func OutputToUser(output string, logToFile bool, outputFileName string) {
	println(output)
	if !logToFile {
		return
	}
	file, err := os.OpenFile(outputFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		println("[-] Could not open file: ", outputFileName)
		return
	}
	defer file.Close()
	if _, err = file.WriteString(output); err != nil {
		println("[-] Could not write to file: ", outputFileName)
	}
}

// PrintIfVerbose prints message when verbose output is enabled.
func PrintIfVerbose(message string, verbose bool) {
	if verbose {
		println(message)
	}
}
