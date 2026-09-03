//go:build !linux

package hostpid

import (
	"fmt"
	"io"
	"os"
)

// Launch reports that Linux namespace entry is unavailable on this platform.
func Launch(_ io.Reader, _, _ io.Writer) error { return ErrUnsupported }

// RunWorker reports that the private worker cannot run on this platform.
func RunWorker(args []string, _, _, stderr *os.File) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "%s internal worker does not accept arguments\n", outputPrefix)
		return 2
	}
	fmt.Fprintf(stderr, "%s %v\n", outputPrefix, ErrUnsupported)
	return 1
}
