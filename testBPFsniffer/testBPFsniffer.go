/*
 from
  https://github.com/hb9cwp/HoneyBadger/tree/master/cmd/testBpfSniffer
  https://github.com/david415/HoneyBadger/tree/master/cmd/testBpfSniffer

*/

package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/bsdbpf"
	"github.com/google/gopacket/layers"
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
		fmt.Printf("timeStamp %s\n", ci.Timestamp)
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		}

		// Iterate over all layers, printing out each layer type
		for _, layer := range packet.Layers() {
			fmt.Println("PACKET LAYER:", layer.LayerType())
		}
	}
}
