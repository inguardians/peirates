package peirates

import (
	"fmt"
	"net/url"
	"strings"
)

func curl(interactive bool, logToFile bool, outputFileName string) {

	println("[+] Enter a URL, including http:// or https:// - if parameters are required, you must provide them as part of the URL: ")
	fullURL, err := ReadLineStripWhitespace()
	if err != nil {
		println("Problem with reading URL: %v", err)
		pauseToHitEnter(interactive)
		return
	}
	fullURL = strings.ToLower(fullURL)

	// Make sure the URL begins with http:// or https://.
	if !strings.HasPrefix(fullURL, "http://") && !strings.HasPrefix(fullURL, "https://") {
		fmt.Println("This URL does not start with http:// or https://")
		pauseToHitEnter(interactive)
		return
	}

	// If the URL is https, ask more questions.
	https := false
	ignoreTLSErrors := false
	caCertPath := ""

	if strings.HasPrefix(fullURL, "https://") {
		https = true
		// Ask the user if they want to ignore certificate validation
		println("Would you like to ignore whether the server certificate is valid (y/n)? This corresponds to curl's -k flag.")
		answer, err := ReadLineStripWhitespace()
		if err != nil {
			println("Problem with stripping whitespace: %v", err)
		}
		answer = strings.ToLower(answer)
		if strings.HasPrefix(answer, "y") {
			ignoreTLSErrors = true
		}

		println("If you would like to set a custom certificate authority cert path, enter it here.  Otherwise, hit enter.")
		caCertPath, err = ReadLineStripWhitespace()
		if err != nil {
			println("Problem with stripping whitespace: %v", err)
			pauseToHitEnter(interactive)
			return
		}
	}

	// Get the HTTP method
	method := "--undefined--"
	for (method != "GET") && (method != "POST") {
		fmt.Println("[+] Enter method - only GET and POST are supported: ")
		input, err := ReadLineStripWhitespace()
		if err != nil {
			println("Problem with stripping whitespace: %v", err)
			pauseToHitEnter(interactive)
			return
		}
		method = strings.TrimSpace(strings.ToUpper(input))
	}

	// Store the headers in a list
	var headers []HeaderLine

	inputHeader := "undefined"

	fmt.Println("[+] Specify custom header lines, if desired, entering the Header name, hitting Enter, then the Header value.")
	for inputHeader != "" {
		// Request a header name

		fmt.Println("[+] Enter a header name or a blank line if done: ")
		input, err := ReadLineStripWhitespace()
		if err != nil {
			println("Problem with stripping whitespace: %v", err)
			pauseToHitEnter(interactive)
			return
		}

		inputHeader = strings.TrimSpace(input)

		if inputHeader != "" {
			// Remove trailing : if present
			inputHeader = strings.TrimSuffix(inputHeader, ":")

			// Request a header rhs (value)
			fmt.Println("[+] Enter a value for " + inputHeader + ":")
			input, err = ReadLineStripWhitespace()
			if err != nil {
				println("Problem with stripping whitespace: %v", err)
				pauseToHitEnter(interactive)
				return
			}

			// Add the header value to the list
			var header HeaderLine
			header.LHS = inputHeader
			header.RHS = input
			headers = append(headers, header)
		}

	}

	inputParameter := "--undefined--"

	// Store the parameters in a map
	params := map[string]string{}

	fmt.Printf("[+] Now enter parameters which will be placed into the query string or request body.\n\n")
	fmt.Printf("    If you set a Content-Type manually to something besides application/x-www-form-urlencoded, use the parameter name as the complete key=value pair and leave the value blank.\n\n")

	for inputParameter != "" {
		// Request a parameter name

		fmt.Println("[+] Enter a parameter or a blank line to finish entering parameters: ")
		inputParameter, err = ReadLineStripWhitespace()
		if err != nil {
			println("Problem with stripping whitespace: %v", err)
			pauseToHitEnter(interactive)
			return
		}

		if inputParameter != "" {
			// Request a parameter value
			fmt.Println("[+] Enter a value for " + inputParameter + ": ")
			input, err := ReadLineStripWhitespace()
			if err != nil {
				println("Problem with stripping whitespace: %v", err)
				pauseToHitEnter(interactive)
				return
			}

			// Add the parameter pair to the list
			params[inputParameter] = url.QueryEscape(input)
		}

	}

	var paramLocation string
	if len(params) > 0 {
		for (paramLocation != "url") && (paramLocation != "body") {
			fmt.Println("\nWould you like to place parameters in the URL (like in a GET query) or in the body (like in a POST)\nurl or body: ")
			paramLocation, err = ReadLineStripWhitespace()
			if err != nil {
				println("Problem with stripping whitespace: %v", err)
				pauseToHitEnter(interactive)
				return
			}
			paramLocation = strings.ToLower(paramLocation)
		}
	}

	// Make the request and get the response.
	request, err := createHTTPrequest(method, fullURL, headers, paramLocation, params)
	if err != nil {
		println("Could not create request.")
		pauseToHitEnter(interactive)
		return
	}
	responseBody, err := DoHTTPRequestAndGetBody(request, https, ignoreTLSErrors, caCertPath)
	if err != nil {
		println("Request failed.")
		pauseToHitEnter(interactive)
		return
	}
	outputToUser(string(responseBody), logToFile, outputFileName)
	pauseToHitEnter(interactive)
}
