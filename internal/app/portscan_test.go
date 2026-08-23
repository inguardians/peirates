package app

import (
	"net"
	"strconv"
	"testing"
)

func TestCIDRHosts(t *testing.T) {
	got := cidrHosts("192.0.2.0/30")
	if len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "192.0.2.2" {
		t.Fatalf("hosts = %#v", got)
	}
	if got := cidrHosts("192.0.2.1/32"); len(got) != 0 {
		t.Fatalf("/32 hosts = %#v", got)
	}
}

func TestScanWorkerReportsOpenAndClosedPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	ports, results := make(chan int, 2), make(chan int, 2)
	ports <- openPort
	ports <- closedPort
	close(ports)
	go scan_worker("127.0.0.1", ports, results)
	first, second := <-results, <-results
	if !((first == openPort && second == 0) || (first == 0 && second == openPort)) {
		t.Fatalf("results = %d, %d (open port %s)", first, second, strconv.Itoa(openPort))
	}
}

func TestPortscanTestHelper(t *testing.T) { test() }
