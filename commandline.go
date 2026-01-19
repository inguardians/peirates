// commandline.go contains logic and data structures relevant to actually
// running peirates as a command line tool. Mainly this is just flag handling.
package peirates

import (
	"flag" // Command line flag parsing
	"os"
	"strings"
)

type CommandLineOptions struct {
	noCloudDetection bool
	connectionConfig *ServerInfo
	moduleToRun      string
	verbose          bool
}

// parseOptions parses command-line options. We call it in main().
// func parseOptions(connectionString *ServerInfo, kubeData *Kube_Data) {
func parseOptions(opts *CommandLineOptions) {
	// This is like the parser.add_option stuff except it works implicitly on a global parser instance.
	// Notice the use of pointers (&connectionString.APIServer for example) to bind flags to variables

	flagset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flagset.StringVar(&opts.connectionConfig.APIServer, "u", opts.connectionConfig.APIServer, "API Server URL: ex. https://10.96.0.1:6443")
	flagset.BoolVar(&opts.connectionConfig.ignoreTLS, "k", false, "Ignore TLS checking on API server requests?")
	flagset.BoolVar(&opts.noCloudDetection, "c", false, "Skip checking what cloud we are on.")

	flagset.StringVar(&opts.connectionConfig.Token, "t", opts.connectionConfig.Token, "Token (JWT)")
	flagset.StringVar(&opts.moduleToRun, "m", "", "module to run from menu - items on main menu with an * support this.")
	flagset.BoolVar(&opts.verbose, "v", false, "verbose mode - display debug messages")

	// This is the function that actually runs the parser
	// once you've defined all your options.
	err := flagset.Parse(os.Args[1:])
	if err != nil {
		println("Problem with args: %v", err)
	}

	// Parse Verbose flag first, since it is used below.
	Verbose = opts.verbose
	if Verbose {
		println("DEBUG: verbose mode on")
	}

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
		printIfVerbose("API server URL provided on the command line: "+opts.connectionConfig.APIServer, Verbose)

	}

	// If a certificate authority path is passed in, normalize it.
	if len(opts.connectionConfig.CAPath) > 0 {
		CAPath := strings.TrimSpace(opts.connectionConfig.CAPath)
		opts.connectionConfig.CAPath = CAPath
		printIfVerbose("Certificate authority path provided on the command line: "+opts.connectionConfig.CAPath, Verbose)
	}

	if opts.connectionConfig.Token != "" {
		printIfVerbose("JWT provided on the command line.", Verbose)
	}

}
