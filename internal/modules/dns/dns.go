// Package dns enumerates Kubernetes services through cluster DNS.
package dns

import (
	"fmt"
	"net"
	"strconv"
)

type Service struct {
	HostName string
	IP       string
	Port     uint16
}

type Resolver struct {
	LookupSRV  func(service, proto, name string) (string, []*net.SRV, error)
	LookupHost func(host string) ([]string, error)
}

func NewResolver() Resolver {
	return Resolver{LookupSRV: net.LookupSRV, LookupHost: net.LookupHost}
}

func (r Resolver) Services() ([]Service, error) {
	_, records, err := r.LookupSRV("", "", "any.any.svc.cluster.local")
	if err != nil {
		return nil, err
	}
	var services []Service
	for _, record := range records {
		ips, err := r.LookupHost(record.Target)
		if err != nil {
			continue
		}
		services = append(services, Service{HostName: record.Target, IP: ips[0], Port: record.Port})
	}
	return services, nil
}

func (r Resolver) Enumerate() error {
	println("\nRequesting SRV record any.any.svc.cluster.local - thank @raesene:\n")
	services, err := r.Services()
	if err != nil {
		println("error: no services returned - this cluster may have CoreDNS version 1.9.0 or later - see https://github.com/coredns/coredns/issues/4984")
		println(err)
		return err
	}
	names := make(map[string]bool)
	nameList := ""
	ports := make(map[uint16]bool)
	portList := ""
	for _, service := range services {
		fmt.Printf("Service: %s(%s):%d\n", service.HostName, service.IP, service.Port)
		if !names[service.HostName] {
			names[service.HostName] = true
			nameList += " " + service.HostName
		}
		if !ports[service.Port] {
			ports[service.Port] = true
			if portList != "" {
				portList += ","
			}
			portList += strconv.Itoa(int(service.Port))
		}
	}
	println("\nPortscan these services via:")
	println("nmap -sTVC -v -n -p " + portList + nameList)
	return nil
}
