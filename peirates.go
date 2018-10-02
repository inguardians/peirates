// You need to use "package main" for executables
// BTW always run `go fmt` before you check in code. go fmt is law.
package main

// Imports. If you don't use an import that's an error so
// I haven't imported json yet.
// Also, number one rule of Go: Try to stick to the
// standard library as much as possible
import (
	"flag"      // Command line flag parsing
	"fmt"       // String formatting (Printf, Sprintf)
	"io/ioutil" // Utils for dealing with IO streams
	"log"       // Logging utils
	"net/http"  // HTTP client/server
)

// Struct type definition to contain our options. This is
// different from the original python code that had each
// of the options as top-level variables
type options struct {
	rIPAddress string
	rPort      string
	infoPods   bool
}

// Create a global variable named "opts" initialized to
// default values
var opts = options{}

// Function to parse options. We call it in main()
func parseOptions() {
	// This is like the parser.add_option stuff except
	// it works implicitly on a global parser instance.
	// Notice the use of pointers (&opts.rIPAddress for
	// example) to bind flags to variables
	flag.StringVar(&opts.rIPAddress, "i", "127.0.0.1", "Remote IP address: ex. 10.22.34.67")
	flag.StringVar(&opts.rPort, "p", "6443", "Remote Port: ex 10255, 10250")
	flag.BoolVar(&opts.infoPods, "e", false, "Export pod information from remote Kubernetes server via curl")

	// This is the function that actually runs the parser
	// once you've defined all your options.
	flag.Parse()

	// If the IP or Port are their empty string, we want
	// to just print out usage and crash because they have
	// to be defined
	if opts.rIPAddress == "" {
		// flag.Usage() prints out an auto-generated usage string.
		flag.Usage()
		// log.Fatal prints a message to stderr and crashes the program.
		log.Fatal("Error: must provide remote IP address (-i)")
	}
	if opts.rPort == "" {
		// Same as before
		flag.Usage()
		log.Fatal("Error: must provide remote Port (-p)")
	}
}

// Here's the requestme equivalent.
func requestme(location string) {
	// Make a request, getting a response and possibly an error.
	// fmt.Sprintf is a function which acts like printf() except it returns a string.
	res, err := http.Get(fmt.Sprintf("http://%s:%s/%s", opts.rIPAddress, opts.rPort, location))

	// These three lines are a common idiom when you just want to crash if an error happens.
	if err != nil {
		// Remember, log.Fatal() prints to stderr and then crashes.
		log.Fatal(err)
	}

	// Read the entire response into memory.
	contents, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	// "contents" is a byte slice ([]byte). We use
	// string() to convert it to a string type.
	// The difference is that the string type is for
	// UTF-8 strings specifically, while the byte slice
	// type is for any sort of binary data. However, in
	// this case, we know the server is returning back
	// text data. If we did not convert it, println()
	// would print the pointer of the byte slice instead
	// of the actual string
	println(string(contents))
}

func main() {
	// Run the option parser to initialize opts
	parseOptions()

	// This part is direct conversion from the python
	// Note that we use println() instead of print().
	// In go, print() does not add a newline while
	// println() does.
	if opts.infoPods {
		requestme("pods")
		println("---------------------------")
		println("Extracting Pods via Curl  | ")
		println("--------------------------------------------------------------------------------------->")
		requestme("pods")
		println("--------------------------------------------------------------------------------------->")
		requestme("stats")
		requestme("stats/summary")
		requestme("stats/container")
		requestme("metrics")
		requestme("healthz")
	}

}

// Example of a multi-line comment
/*
https://10.23.58.40:6443/api
https://10.23.58.40:6443/api/v1
https://10.23.58.40:6443/apis
https://10.23.58.40:6443/apis/apps
https://10.23.58.40:6443/apis/batch
https://10.23.58.40:6443/apis/extentions
https://10.23.58.40:6443/apis/policy
https://10.23.58.40:6443/version
https://10.23.58.40:6443/apis/apps/v1/proxy (500)
https://10.23.58.40:6443/apis/apps/v1/watch (500)
*/
