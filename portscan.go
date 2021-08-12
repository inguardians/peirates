package peirates

import (
	"fmt"
	"net"
	"sort"
)

func scan_worker(ip string, ports, results chan int) {
	for p := range ports {
		ip_port := fmt.Sprintf("%s:%d", ip, p)
		conn, err := net.Dial("tcp", ip_port)
		if err != nil {
			results <- 0
			continue
		}
		conn.Close()
		results <- p
	}
}

func scan_controller(ip) {
	ports := make(chan int, 100)
	results := make(chan int)

	var openports []int
	
	# Start up one worker per port?
	for i := 0 ; i < cap(ports) ; i++ {
		go scan_worker(ip, ports, results)
	}
	
	// Start up a parallel thread to send ports into the channel
	go func() {
		for i:= 1 ; i <=65535 ; i++ {
			ports <- i
		}
	}()
	
	// Go get the results, adding them to the openports array/slice
	for i := 0 ; i < 65535 ; i++ {
		port := <-results
		if port != 0 {
			openports = append(openports,port)
		}
	}
	
	// Close the ports worker assignment channel
	close(ports)
	// Close the results channel
	close(results)
	
	// Sort the set of openports in place.
	sort.Ints(openports)
	for _, port := range openports {
		fmt.Printf("%d/tcp open\n", port) 
	}
}

func main() {
   scan_controller("192.168.48.1");
 }