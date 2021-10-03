// commandline.go contains logic and data structures relevant to actually
// running peirates as a command line tool. Mainly this is just flag handling.
package peirates

import (
	"flag" // Command line flag parsing
	"log"
	"os"
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
	// Notice the use of pointers (&connectionString.APIServer for
	// example) to bind flags to variables

	// After parsing flags, this string will be split on commas and stored
	// as a list in opts.podsToRunTheCommandIn
	var podListRaw string

	flagset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flagset.StringVar(&opts.connectionConfig.APIServer, "u", opts.connectionConfig.APIServer, "API Server URL: ex. https://10.96.0.1:6443")
	flagset.StringVar(&opts.connectionConfig.Token, "t", opts.connectionConfig.Token, "Token (JWT)")
	flagset.StringVar(&podListRaw, "L", "", "List of comma-seperated Pods: ex pod1,pod2,pod3")
	flagset.StringVar(&opts.commandToRunInPods, "c", "hostname", "Command to run in pods")

	// This is the function that actually runs the parser
	// once you've defined all your options.
	flagset.Parse(os.Args[1:])

	// If the API Server URL is passed in, normalize it.
	if len(opts.connectionConfig.APIServer) > 0 {

		// Trim any leading or trailing whitespace
		APIServer := strings.TrimSpace(opts.connectionConfig.APIServer)

		// Remove any trailing /
		APIServer = strings.TrimSuffix(APIServer, "/")

		// Check to see if APIServer begins with http or https, adding https if it does not.
		if !(strings.HasPrefix(APIServer, "http://") || strings.HasPrefix(APIServer, "https://")) {
			APIServer = "https://" + APIServer
		}

		opts.connectionConfig.APIServer = APIServer

	}
	if opts.connectionConfig.Token != "" {
		log.Println("JWT provided on the command line.")
	}

	if podListRaw != "" {
		opts.podsToRunTheCommandIn = strings.Split(podListRaw, ",")
	}
}
