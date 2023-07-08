package peirates

import (
	"fmt"
	"net"
	"strconv"
)

// This is a workalike for @raesene's Ruby code: https://github.com/raesene/alpine-containertools/blob/master/scripts/k8s-dns-enum.rb

type serviceHostIPPort struct {
	hostName string
	IP       string
	port     uint16
}

// This routine pulls a list of all services via Core DNS
func getAllServicesViaDNS() (*[]serviceHostIPPort, error) {

	wildcardRecord := "any.any.svc.cluster.local"
	var serviceHostIPPorts []serviceHostIPPort

	// Perform DNS SRV request on wildcardRecord
	_, srvs, err := net.LookupSRV("", "", wildcardRecord)
	if err != nil {
		return nil, err
	}

	// Parse out the output
	for _, srv := range srvs {
		// Each service contains these elements:
		// name , port , priority, weight

		// Now lookup the IP address for the service.
		ips, err := net.LookupHost(srv.Target)
		if err != nil {
			// Don't return a result for any service lacking an IP address?
			continue
		}
		// Return only the first IP address.
		serviceHostIPPorts = append(serviceHostIPPorts, serviceHostIPPort{srv.Target, ips[0], srv.Port})
	}

	return &serviceHostIPPorts, nil
}

func enumerateDNS() error {

	println("\nRequesting SRV record any.any.svc.cluster.local - thank @raesene:\n")
	servicesSlicePointer, err := getAllServicesViaDNS()

	if err != nil {
		println("error: no services returned - this cluster may have CoreDNS version 1.9.0 or later - see https://github.com/coredns/coredns/issues/4984")
		println(err)
		return err
	}
	// Print the services' DNS names, IP addresses and ports, but also create a unique set of IPs and ports to portscan:
	names := make(map[string]bool)
	nameList := ""
	ports := make(map[uint16]bool)
	portList := ""

	for _, svc := range *servicesSlicePointer {
		fmt.Printf("Service: %s(%s):%d\n", svc.hostName, svc.IP, svc.port)
		if _, present := names[svc.hostName]; !present {
			names[svc.hostName] = true
			nameList = nameList + " " + svc.hostName
		}
		if _, present := ports[svc.port]; !present {
			ports[svc.port] = true
			// Append the port to the portList, prepending with a , unless this is the first port.
			if portList != "" {
				portList = portList + ","
			}
			portList = portList + strconv.Itoa(int(svc.port))
			// portList = portList + strconv.FormatUint(uint16(svc.port), 10)

		}
	}

	// Now print a list of names and ports
	println("\nPortscan these services via:")
	println("nmap -sTVC -v -n -p " + portList + nameList)
	return nil
}
