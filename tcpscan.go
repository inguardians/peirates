package peirates

import (
	"fmt"
	"regexp"
)

func tcpScan(interactive bool) {
	var input string
	var matched bool

	for !matched {
		println("Enter an IP address to scan or hit enter to exit the portscan function: ")
		_, err := fmt.Scan(&input)
		if err != nil {
			println("Input error: %v", err)
			pauseToHitEnter(interactive)
			return
		}
		if input == "" {
			pauseToHitEnter(interactive)
			return
		}
		check_pattern_1, err := regexp.Match(`^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*$`, []byte(input))
		if err != nil {
			println("Error on regexp match against IP address pattern.")
			continue
		}
		if check_pattern_1 {
			// Scan an IP
			println("Scanning " + input)
			scan_controller(input)
			pauseToHitEnter(interactive)
			return
		} else {
			check_pattern_2, err := regexp.Match(`^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/[0,1,2,3]?\d)\s*$`, []byte(input))
			if err != nil {
				println("Error on regexp match against ip/bits CIDR pattern.")
				continue
			}
			if check_pattern_2 {
				println("Hidden CIDR scan mode used - this may be slow or unpredictable")
				hostList := cidrHosts(input)
				for _, host := range hostList {
					println("Scanning " + host)
					scan_controller(host)
				}
				pauseToHitEnter(interactive)
				return
			} else {
				println("Error: input must match an IP address or a CIDR formatted network.")
				continue
			}

		}
	}
}
