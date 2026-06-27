package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp and dst port 80 or dst port 443 or dst port 53")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("[x] Network monitor started on en0... Press Ctrl+C to stop.")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for packet := range packetSource.Packets() {
			processPacket(packet)
		}
	}()

	<-sigChan
	fmt.Println("\nShutting down network monitor...")
}

func processPacket(packet gopacket.Packet) {
	var srcIP, dstIP string
	var protocol layers.IPProtocol
	var srcPort, dstPort uint16
	var transport string

	if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ip := ip4.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		protocol = ip.Protocol
	} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ip := ip6.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
		protocol = ip.NextHeader
	} else {
		return
	}

	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		t := tcp.(*layers.TCP)
		srcPort = uint16(t.SrcPort)
		dstPort = uint16(t.DstPort)
		transport = "TCP"
	} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		u := udp.(*layers.UDP)
		srcPort = uint16(u.SrcPort)
		dstPort = uint16(u.DstPort)
		transport = "UDP"
	}

	payloadStr := ""
	if app := packet.ApplicationLayer(); app != nil {
		payload := app.Payload()
		if len(payload) > 0 {
			maxLen := 512
			if len(payload) < maxLen {
				maxLen = len(payload)
			}
			payloadStr = string(payload[:maxLen])
		}
	}

	event := NetworkEvent{
		Timestamp: time.Now(),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol.String(),
		Transport: transport,
		Payload:   payloadStr,
	}

	go analyzeWithAI(event)
}

type NetworkEvent struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Protocol  string    `json:"protocol"`  // e.g. "TCP", "UDP"
	Transport string    `json:"transport"` // "TCP" or "UDP"
	Payload   string    `json:"payload_snippet,omitempty"`
}

func analyzeWithAI(event NetworkEvent) {
	fmt.Printf("[EVENT] %s:%d → %s:%d | %s | %s\n",
		event.SrcIP, event.SrcPort,
		event.DstIP, event.DstPort,
		event.Transport, event.Protocol)

}
