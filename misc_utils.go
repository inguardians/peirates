package peirates

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ReadLineStripWhitespace() (string, error) {
	line, err := ReadLine()

	return strings.TrimSpace(line), err

}

// readLine reads up through the next \n from stdin. The returned string does
// not include the \n.
func ReadLine() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return line[:len(line)-1], err
}

// pauseToHitEnter() just gives us a simple way to let the user see input before clearing the screen.
func pauseToHitEnter(interactive bool) {
	var err error
	if interactive {
		var input string

		println("Press enter to continue")
		_, err = fmt.Scanln(&input)
		if err != nil {
			println("Problem with scanln: %v", err)
		}
	}
}
