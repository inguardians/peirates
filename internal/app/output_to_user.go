package app

import "github.com/inguardians/peirates/internal/ui"

func outputToUser(output string, logToFile bool, outputFileName string) {
	ui.OutputToUser(output, logToFile, outputFileName)
}

func printIfVerbose(message string, verbose bool) { ui.PrintIfVerbose(message, verbose) }
