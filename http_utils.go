// http_utils.go contains URL requests
package peirates

import (
	"crypto/tls"
	"io/ioutil"
	"net/http"
)

type HeaderLine struct {
	LHS string
	RHS string
}

func GetRequest(url string, headers []HeaderLine, tls_checking bool) string {
	// These are two examples of HTTP requests we're making

	// Need to get project ID from metadata API
	var client *http.Client
	if !(tls_checking) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	} else {
		client = &http.Client{}
	}

	request, err := http.NewRequest("GET", url, nil)
	for _, header := range headers {
		request.Header.Add(header.LHS, header.RHS)
	}
	response, err := client.Do(request)
	if err != nil {
		println("Error - could not perform request " + url)
		response.Body.Close()
		return ""

	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		println("Error: could not parse HTTP response")
		return ""

	}
	// Parse result as one or more accounts, then construct a request asking for each account's credentials
	return string(body)
}
