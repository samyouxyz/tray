package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

type ARPEntry struct {
	IP  string
	MAC string
}

func GetLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func ARPScan() ([]ARPEntry, error) {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`\(?([\d.]+)\)?\s+at\s+([a-fA-F0-9:]+|incomplete)`)
	matches := re.FindAllStringSubmatch(string(output), -1)

	var entries []ARPEntry
	for _, match := range matches {
		entries = append(entries, ARPEntry{IP: match[1], MAC: match[2]})
	}
	return entries, nil

}

func DiscoverMDNS(timeout time.Duration) ([]*zeroconf.ServiceEntry, error) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, err
	}

	entries := make(chan *zeroconf.ServiceEntry)
	var results []*zeroconf.ServiceEntry
	go func(resultsChan chan *zeroconf.ServiceEntry) {
		for entry := range entries {
			resultsChan <- entry
		}
	}(entries)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = resolver.Browse(ctx, "_services._dns-sd._udp", "local.", entries)

	if err != nil {
		return nil, err
	}
	<-ctx.Done()

	for entry := range entries {
		results = append(results, entry)
	}
	return results, nil

}

func ipsToStrings(ips []net.IP) []string {
	res := make([]string, len(ips))
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	return res
}

func main() {
	localIP, err := GetLocalIP()
	if err != nil {
		log.Fatalf("Error getting local IP address: %v", err)
	}
	fmt.Printf("Local IP: %s\n", localIP)

	// arp scanning
	arpEntries, err := ARPScan()
	if err != nil {
		log.Fatalf("Error running ARP scan: %v", err)
	}

	for _, entry := range arpEntries {
		fmt.Printf("IP: %s, MAC: %s \n", entry.IP, entry.MAC)
	}

	// mDNS discovery
	mdnsEntries, err := DiscoverMDNS(5 * time.Second)
	if err != nil {
		log.Fatalf("Error discovering mDNS services: %v", err)
	}
	fmt.Printf("mDNS discvoery results:\n")
	for _, entry := range mdnsEntries {
		log.Println(entry)
		fmt.Printf("Name: %s, Hostname: %s, Addresses: %s \n",
			entry.ServiceInstanceName(), entry.HostName, strings.Join(ipsToStrings(entry.AddrIPv4), ", "))
	}

}
