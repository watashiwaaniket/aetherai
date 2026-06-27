package main

import (
	"log"
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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	appLayer := packet.ApplicationLayer()

	if ipLayer != nil && tcpLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		tcp := tcpLayer.(*layers.TCP)

		var payloadStr string
		if appLayer != nil {
			payload := appLayer.Payload()
			payloadStr = string(payload[:min(512, len(payload))])
		}

		event := NetworkEvent{
			Timestamp: time.Now(),
			SrcIP:     ip.SrcIP.String(),
			DstIP:     ip.DstIP.String(),
			SrcPort:   uint16(tcp.SrcPort),
			DstPort:   uint16(tcp.DstPort),
			Payload:   payloadStr,
		}

		go analyzeWithAI(event)
	}
}

type NetworkEvent struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Payload   string    `json:"payload_snippet"`
	// ... more fields
}
