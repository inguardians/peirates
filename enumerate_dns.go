package peirates

import(
    "net"
)

type serviceHostIPPort struct {
    hostName string
    IP string
    port uint16
}


// This routine pulls a list of all services via Core DNS -- 
func getAllServicesViaDNS() (*[]serviceHostIPPort, error) {

    wildcardRecord := "any.any.svc.cluster.local"
    var serviceHostIPPorts []serviceHostIPPort

    println("DEBUG: performing DNS SRV request on " , wildcardRecord)
    _, srvs, err := net.LookupSRV("","",wildcardRecord)
    if err != nil {
        return nil, err
    }

    // Parse out the output
    for _, srv := range(srvs) {
        // Each service contains these elements:
        // name , port , priority, weight


        // Now lookup the IP address for the service.
        
        ips , err := net.LookupHost(srv.Target)
        if err != nil {
            continue
        }
        // Return only the first IP address.


        serviceHostIPPorts = append(serviceHostIPPorts, serviceHostIPPort{ srv.Target, ips[0], srv.Port, })
    } 


    return &serviceHostIPPorts, nil
}

func main() {

    servicesSlicePointer, err := getAllServicesViaDNS()
    
    if err != nil {
        println("no services returned or some kind of error")
    }
    for _, svc := range(*servicesSlicePointer) {
        println("Service:")
        println(svc.hostName)
        println(svc.IP)
        println(svc.port)
    }
    // Prepare to portscan
}