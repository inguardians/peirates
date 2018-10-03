// Peirates - an Attack tool for Kubernetes clusters
//
// You need to use "package main" for executables
//
// BTW always run `go fmt` before you check in code. go fmt is law.
//
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
	"os/exec"
	"regexp"
	"strings"

	// Packages belonging to Peirates go here
	"config"
)

// Struct type definition to contain our options. This is
// different from the original python code that had each
// of the options as top-level variables
// type ServerInfo struct {
// 	RIPAddress string
// 	RPort      string
// 	Token      string //pass token  via command line
// 	CAPath     string //path to ca certificate
// 	Namespace  string // namespace that this pod's service account is tied to
// }

// Function to parse options. We call it in main()
func parseOptions(connectionString *config.ServerInfo) {
	// This is like the parser.add_option stuff except
	// it works implicitly on a global parser instance.
	// Notice the use of pointers (&connectionString.RIPAddress for
	// example) to bind flags to variables
	flag.StringVar(&connectionString.RIPAddress, "i", "10.23.58.40", "Remote IP address: ex. 10.22.34.67")
	flag.StringVar(&connectionString.RPort, "p", "6443", "Remote Port: ex 10255, 10250")
	// flag.BoolVar(&connectionString.infoPods, "e", false, "Export pod information from remote Kubernetes server via curl")
	println("FIXME: parseOptions clobbers config.Builder()")
	// flag.StringVar(&connectionString.Token, "t", "", "Token to be used for accessing Kubernetes server")
	// flag.StringVar(&connectionString.CAPath, "c", "", "Path to CA certificate")

	// This is the function that actually runs the parser
	// once you've defined all your options.
	flag.Parse()

	// If the IP or Port are their empty string, we want
	// to just print out usage and crash because they have
	// to be defined
	if connectionString.RIPAddress == "" {
		// flag.Usage() prints out an auto-generated usage string.
		flag.Usage()
		// log.Fatal prints a message to stderr and crashes the program.
		log.Fatal("Error: must provide remote IP address (-i)")
	}
	if connectionString.RPort == "" {
		// Same as before
		flag.Usage()
		log.Fatal("Error: must provide remote Port (-p)")
	}
}

// get_pod_list() returns an array of pod names, parsed from kubectl get pods
func get_pod_list(connectionString config.ServerInfo) []string {

	var pods []string

	get_pods_raw, err := exec.Command("kubectl", "-n", connectionString.Namespace, "--token="+connectionString.Token, "--certificate-authority="+connectionString.CAPath, "--server=https://"+connectionString.RIPAddress+":"+connectionString.RPort, "get", "pods").Output()
	if err != nil {
		log.Fatal(err)
	}
	// Iterate over kubectl get pods, stripping off the first line which matches NAME and then grabbing the first column

	get_pods_lines := strings.Split(string(get_pods_raw), "\n")
	for _, line := range get_pods_lines {
		matched, err := regexp.MatchString(`^\s*$`, line)
		if err != nil {
			log.Fatal(err)
		}
		if !matched {
			pod := strings.Fields(line)[0]
			if pod != "NAME" {
				pods = append(pods, pod)
			}
		}
	}

	return pods
}

func getHostname(connectionString config.ServerInfo, PodName string) {
	println("DEBUG: started getHostname on " + PodName)
	println("DEBUG: about to run")
	println("kubectl", "-n", connectionString.Namespace, "--token="+connectionString.Token, "--certificate-authority="+connectionString.CAPath, "--server=https://"+connectionString.RIPAddress+":"+connectionString.RPort, "exec", "-it", PodName, "hostname")
	out, err := exec.Command("kubectl", "-n", connectionString.Namespace, "--token="+connectionString.Token, "--certificate-authority="+connectionString.CAPath, "--server=https://"+connectionString.RIPAddress+":"+connectionString.RPort, "exec", "-it", PodName, "hostname").Output()
	if err != nil {
		fmt.Println("Checking for hostname of pod "+PodName+" failed: ", err)
	} else {
		println("Hostname of pod is: " + string(out))
	}
}

func createPods(connectionString config.ServerInfo) {
	out, err := exec.Command("kubectl", "-n", connectionString.Namespace, "--token="+connectionString.Token, "--certificate-authority="+connectionString.CAPath, "--server=https://"+connectionString.RIPAddress+":"+connectionString.RPort, "auth", "can-i", "create", "pod").Output()
	if err != nil {
		fmt.Println("Checking for Pod creation failed: ", err)
	} else {
		println("Can this token create pods: " + string(out))
	}

}

func inAPod(connectionString config.ServerInfo) {
	out, err := exec.Command("mount").Output()
	if err != nil {
		fmt.Println("Checking if we are running in a Pod failed: ", err)
	} else {
		mountout := string(out)
		inpod := strings.Contains(mountout, "kubernetes")
		println("Are we currently running on a pod: ", inpod)
	}

}

// Here's the requestme equivalent.
func requestme(connectionString config.ServerInfo, location string) {
	// Make a request, getting a response and possibly an error.
	// fmt.Sprintf is a function which acts like printf() except it returns a string.
	res, err := http.Get(fmt.Sprintf("http://%s:%s/%s", connectionString.RIPAddress, connectionString.RPort, location))

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

	// Create a global variable named "connectionString" initialized to
	// default values
	var connectionString config.ServerInfo = config.Builder()

	// Run the option parser to initialize connectionStrings
	println("\n\nStarting periates...")
	parseOptions(&connectionString)

	all_pods := get_pod_list(connectionString)

	for _, pod := range all_pods {
		println("Checking out pod: " + pod)
		getHostname(connectionString, pod)
	}

	createPods(connectionString)
	inAPod(connectionString)
	// This part is direct conversion from the python
	// Note that we use println() instead of print().
	// In go, print() does not add a newline while
	// println() does.
	/*	if connectionString.infoPods {
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
	*/
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
