package peirates

import (
	"bufio"
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
