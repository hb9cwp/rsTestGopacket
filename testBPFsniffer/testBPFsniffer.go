/*
 from
  https://github.com/hb9cwp/HoneyBadger/tree/master/cmd/testBpfSniffer
  https://github.com/david415/HoneyBadger/tree/master/cmd/testBpfSniffer

*/

package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"github.com/google/gopacket/bsdbpf"
	"github.com/hb9cwp/gopacket/bsdbpf"
)

func main() {
	var err error
	var ci gopacket.CaptureInfo
	var frame []byte
	sniffer, err := bsdbpf.NewBPFSniffer("alc0", nil)
	if err != nil {
		panic(err)
	}
	for {
		frame, ci, err = sniffer.ReadPacketData()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s ", ci.Timestamp)
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		// Iterate over all layers, printing out each layer type
		for _, layer := range packet.Layers() {
			fmt.Printf("%v - ", layer.LayerType())
		}

		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("src:%d > dst:%d", tcp.SrcPort, tcp.DstPort)
		}

		// DNS
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			//fmt.Printf("*DNS*")
			dns, _ := dnsLayer.(*layers.DNS)
			//fmt.Printf("%#v", dns.Questions)
			fmt.Printf("%v", dns.Questions)
		}

		fmt.Println()
	}
}
