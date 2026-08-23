package app

import "github.com/inguardians/peirates/internal/modules/portscan"

func scan_worker(ip string, ports, results chan int) { portscan.ScanWorker(ip, ports, results) }
func scan_controller(ip string)                      { portscan.Scan(ip) }
func cidrHosts(network string) []string              { return portscan.CIDRHosts(network) }
func test()                                          { println("Test") }
