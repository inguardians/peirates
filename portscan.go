package peirates

import (
	"fmt"
	"net"
)

func scan_worker(ip, ports, results chan int) {
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
