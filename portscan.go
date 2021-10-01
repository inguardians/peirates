package peirates

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"time"
)

func scan_worker(ip string, ports, results chan int) {
	for p := range ports {
		ip_port := fmt.Sprintf("%s:%d", ip, p)
		//		fmt.Printf("DEBUG: checking %s:%d\n", ip, p)
		conn, err := net.DialTimeout("tcp", ip_port, 50*time.Millisecond)
		if err != nil {
			results <- 0
			continue
		}
		conn.Close()
		results <- p
	}
}

func scan_controller(ip string) {
	ports := make(chan int, 1000)
	results := make(chan int)

	var openports []int

	// Start up one worker per port?
	for i := 0; i < cap(ports); i++ {
		go scan_worker(ip, ports, results)
	}

	// Start up a parallel thread to send ports into the channel
	go func() {
		for i := 1; i <= 65535; i++ {
			ports <- i
		}
	}()

	// Go get the results, adding them to the openports array/slice
	for i := 0; i < 65535; i++ {
		port := <-results
		if port != 0 {
			openports = append(openports, port)
		}
	}

	// Close the ports worker assignment channel
	close(ports)
	// Close the results channel
	close(results)

	// Sort the set of openports in place.
	sort.Ints(openports)
	for _, port := range openports {
		fmt.Printf("%s:%d open\n", ip, port)
	}
}

// This function included with permission of the author.
// See his blog post here:
// https://www.stevencampbell.info/Golang-Convert-CIDR-Address-To-Hosts/
func cidrHosts(network string) []string {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(network)
	if err != nil {
		log.Fatal(err)
	}
	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	// fing the start IP address
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	// find the final IP address
	finish := (start & mask) | (mask ^ 0xffffffff)
	// make a slice to return host addresses
	var hosts []string
	// loop through addresses as uint32
	for i := start + 1; i <= finish-1; i++ {
		// convert back to net.IPs
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}
	// return a slice of strings containing IP addresses
	return hosts
}

func test() {
	println("Test")
	// scan_controller(cidrHosts("192.168.48.0/24"))
}
