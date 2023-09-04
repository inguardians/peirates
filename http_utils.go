package peirates

// http_utils.go contains URL requests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HeaderLine contains the left hand side (header name) and right hand side (header value) of an HTTP header.
type HeaderLine struct {
	LHS string
	RHS string
}

// DoKubernetesAPIRequest makes an API request to a kubernetes API server,
// using the connection parameters and authentication from the provided
// ServerInfo. It marshals the provided query structure to JSON, and
// unmarshalls the response JSON to the response structure pointer.
// For an example of usage, see kubectlAuthCanI.
func DoKubernetesAPIRequest(cfg ServerInfo, httpVerb, apiPath string, query interface{}, response interface{}) error {

	queryJSON, err := json.Marshal(query)
	if err != nil {
		fmt.Printf("[-] KubernetesAPIRequest failed marshalling %s to JSON: %s\n", query, err.Error())
		return err
	}

	jsonReader := bytes.NewReader(queryJSON)
	remotePath := cfg.APIServer + "/" + apiPath
	req, err := http.NewRequest(httpVerb, remotePath, jsonReader)
	if err != nil {
		fmt.Printf("[-] KubernetesAPIRequest failed building a request from URL %s : %s\n", remotePath, err.Error())
		return err
	}

	req.Header.Add("Authorization", "Bearer "+cfg.Token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	responseJSON, err := DoHTTPRequestAndGetBody(req, true, false, cfg.CAPath)
	if err != nil {
		fmt.Printf("[-] KubernetesAPIRequest failed to access the kubernetes API: %s\n", err.Error())
		return err
	}

	err = json.Unmarshal(responseJSON, response)
	if err != nil {
		fmt.Printf("[-] KubernetesAPIRequest failed to unmarshal JSON %s: %s\n", responseJSON, err.Error())
		return err
	}

	return nil
}

// DoHTTPRequestAndGetBody performs an HTTP request, and returns the full
// body of the reponse as a string. If ignoreTLSErrors is  true, all TLS
// errors, such as invalid certificates, will be ignored. If caCertPath is
// not an empty string, a TLS certificate will be read from the provided path
// and added to the pool of valid certificates.
func DoHTTPRequestAndGetBody(req *http.Request, https bool, ignoreTLSErrors bool, caCertPath string) ([]byte, error) {

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	if https {

		caCertPool, err := x509.SystemCertPool()

		if err != nil && caCertPath == "" {
			fmt.Printf("[-] DoHTTPRequestAndGetBody failed to get system cert pool: %s\n", err.Error())
			return []byte{}, err
		}

		if caCertPath != "" {
			caCert, err := ioutil.ReadFile(caCertPath)
			if err != nil {
				fmt.Printf("[-] DoHTTPRequestAndGetBody failed reading CA cert from %s: %s\n", caCertPath, err.Error())
				return []byte{}, err
			}
			caCertPool.AppendCertsFromPEM(caCert)
		}

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            caCertPool,
					InsecureSkipVerify: ignoreTLSErrors,
				},
			},
		}
	}

	responseHTTP, err := client.Do(req)
	if err != nil {
		fmt.Printf("[-] DoHTTPRequestAndGetBody failed to perform the request: %s\n", err.Error())
		return []byte{}, err
	}

	responseBody, err := ioutil.ReadAll(responseHTTP.Body)
	if err != nil {
		fmt.Printf("[-] DoHTTPRequestAndGetBody failed to read HTTP response body: %s\n", err.Error())
		return []byte{}, err
	}

	if responseHTTP.StatusCode < 200 || responseHTTP.StatusCode > 299 {
		fmt.Printf("[-] DoHTTPRequestAndGetBody got a %s status instead of a successful 2XX status. Failing and printing response: \n%s\n", responseHTTP.Status, string(responseBody))
		return []byte{}, fmt.Errorf("DoHTTPRequestAndGetBody failed with status %s", responseHTTP.Status)
	}

	return responseBody, err
}

// GetRequest is a simple helper function for making HTTP GET requests to the
// provided URL with custom headers, and the option to ignore TLS errors.
// For a more advanced helper, see DoHTTPRequestAndGetBody.
func GetRequest(url string, headers []HeaderLine, ignoreTLSErrors bool) string {

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		fmt.Printf("[-] GetRequest failed to construct an HTTP request from URL %s : %s\n", url, err.Error())
		return ""
	}

	for _, header := range headers {
		req.Header.Add(header.LHS, header.RHS)
	}

	https := false
	if strings.HasPrefix(url, "https:") {
		https = true
	}

	reponse, err := DoHTTPRequestAndGetBody(req, https, ignoreTLSErrors, "")
	if err != nil {
		fmt.Printf("[-] GetRequest could not perform request to %s : %s\n", url, err.Error())
		return ""
	}

	return string(reponse)
}

func createHTTPrequest(method string, urlWithoutValues string, headers []HeaderLine, paramLocation string, params map[string]string) (*http.Request, error) {
	var err error

	// Store a URL starting point that we may put values on.
	urlWithData := urlWithoutValues

	// Create a data structure for values sent in the body of the request.

	var dataSection *strings.Reader = nil
	var contentLength string

	// If there are parameters, add them to the end of urlWithData

	const headerContentType = "Content-Type"
	const headerValFormURLEncoded = "application/x-www-form-urlencoded"

	if len(params) > 0 {

		if paramLocation == "url" {
			urlWithData = urlWithData + "?"

			for key, value := range params {
				urlWithData = urlWithData + key + "=" + value + "&"
			}

			// Strip the final & off the query string
			urlWithData = strings.TrimSuffix(urlWithData, "&")

		} else if paramLocation == "body" {

			// Add a Content-Type by default that curl would use with -d
			// Content-Type: application/x-www-form-urlencoded
			contentTypeFormURLEncoded := true
			foundContentType := false
			for _, header := range headers {
				if header.LHS == headerContentType {
					foundContentType = true
					if header.RHS != headerValFormURLEncoded {
						contentTypeFormURLEncoded = false
					}
				}
			}
			// Add a Content-Type header.
			if !foundContentType {
				headers = append(headers, HeaderLine{LHS: headerContentType, RHS: headerValFormURLEncoded})
			}

			// Now place the values in the body, encoding if content type is x-www-form-urlencoded
			if contentTypeFormURLEncoded {

				data := url.Values{}
				for key, value := range params {
					fmt.Printf("key[%s] value[%s]\n", key, value)
					data.Set(key, value)
				}
				encodedData := data.Encode()

				dataSection = strings.NewReader(encodedData)
				contentLength = strconv.Itoa(len(encodedData))
			} else {
				var bodySection string
				for key, value := range params {
					bodySection = bodySection + key + value + "\n"
				}
				dataSection = strings.NewReader(bodySection)
				contentLength = strconv.Itoa(len(bodySection))

			}
		} else {
			println("paramLocation was not url or body.")
			return nil, nil
		}
	}

	fmt.Println("[+] Using method " + method + " for URL " + urlWithData)

	var request *http.Request
	// Build the request, adding in any headers found so far.
	if dataSection != nil {
		request, err = http.NewRequest(method, urlWithData, dataSection)
		request.Header.Add("Content-Length", contentLength)
	} else {
		request, err = http.NewRequest(method, urlWithData, nil)
	}
	if err != nil {
		println("[-] Error handling data: ", err)
	}
	for _, header := range headers {
		request.Header.Add(header.LHS, header.RHS)
	}

	return request, nil
}

func curlNonWizard(arguments ...string) (request *http.Request, https bool, ignoreTLSErrors bool, caCertPath string, err error) {

	// Scan through the arguments for a method
	method := "GET"
	var fullURL string
	for i, argument := range arguments {
		if argument == "-X" {
			// Method is being set
			method = arguments[i+1]
			println("DEBUG: found argument -X " + method)
		} else if argument == "-k" {
			ignoreTLSErrors = true
		} else if argument == "-d" {
			// TODO: parse out next argument as POST data
		} else if strings.HasPrefix(argument, "http://") {
			fullURL = argument
		} else if strings.HasPrefix(argument, "https://") {
			fullURL = argument
			https = true
			// TODO: Allow user to enter a caCertPath?
			caCertPath = ""
		}
		// TODO: Implement headers

	}

	var headers []HeaderLine
	paramLocation := "url"
	var params map[string]string

	// Make the request and get the response.
	request, err = createHTTPrequest(method, fullURL, headers, paramLocation, params)
	return request, https, ignoreTLSErrors, caCertPath, err

}

func GetMyIPAddress(interfaceName string) (string, error) {

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		fmt.Printf("Error retrieving interface %s: %v\n", interfaceName, err)
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		fmt.Printf("Error retrieving addresses for interface %s: %v\n", interfaceName, err)
		return "", err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String(), nil
		}
	}
	return "", errors.New("Could not find a valid IP address for this interface")
}

// GetMyIPAddressesNative gets a list of IP addresses available via Golang's Net library
func GetMyIPAddressesNative() []string {

	var ipAddresses []string

	ifaces, err := net.Interfaces()
	if err != nil {
		println("ERROR: could not get interface list")
		return nil
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			println("ERROR: could not get interface information")
			return nil
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			ipString := ip.String()
			if ipString != "127.0.0.1" {
				println(ipString)
				ipAddresses = append(ipAddresses, ipString)
			}

		}
	}
	return ipAddresses
}
