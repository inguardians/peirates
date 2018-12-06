// commandline.go contains logic and data structures relevant to actually
// running peirates as a command line tool. Mainly this is just flag handling.
package peirates

import (
	"flag" // Command line flag parsing
	"log"
	"strings"
)

type CommandLineOptions struct {
	connectionConfig      *ServerInfo
	commandToRunInPods    string
	podsToRunTheCommandIn []string
}

// parseOptions parses command-line options. We call it in main().
// func parseOptions(connectionString *ServerInfo, kubeData *Kube_Data) {
func parseOptions(opts *CommandLineOptions) {
	// This is like the parser.add_option stuff except
	// it works implicitly on a global parser instance.
	// Notice the use of pointers (&connectionString.RIPAddress for
	// example) to bind flags to variables

	// After parsing flags, this string will be split on commas and stored
	// as a list in opts.podsToRunTheCommandIn
	var podListRaw string

	flag.StringVar(&opts.connectionConfig.RIPAddress, "i", "10.23.58.40", "Remote IP address: ex. 10.22.34.67")
	flag.StringVar(&opts.connectionConfig.RPort, "p", "6443", "Remote Port: ex 10255, 10250")
	flag.StringVar(&podListRaw, "L", "", "List of comma seperated Pods: ex pod1,pod2,pod3")
	flag.StringVar(&opts.commandToRunInPods, "c", "hostname", "Command to run in pods")
	// flag.BoolVar(&connectionString.infoPods, "e", false, "Export pod information from remote Kubernetes server via curl")

	// JAY / TODO: println("FIXME: parseOptions clobbers Builder()")

	// flag.StringVar(&connectionString.Token, "t", "", "Token to be used for accessing Kubernetes server")
	// flag.StringVar(&connectionString.CAPath, "c", "", "Path to CA certificate")

	// This is the function that actually runs the parser
	// once you've defined all your options.
	flag.Parse()

	// If the IP or Port are their empty string, we want
	// to just print out usage and crash because they have
	// to be defined
	if opts.connectionConfig.RIPAddress == "" {
		// flag.Usage() prints out an auto-generated usage string.
		flag.Usage()
		// log.Fatal prints a message to stderr and crashes the program.
		log.Fatal("Error: must provide remote IP address (-i)")
	}
	if opts.connectionConfig.RPort == "" {
		// Same as before
		flag.Usage()
		log.Fatal("Error: must provide remote Port (-p)")
	}

	if podListRaw != "" {
		opts.podsToRunTheCommandIn = strings.Split(podListRaw, ",")
	}
}
