/*
 FreeBSD Golang sniffer using BPF,
 by david415, the author of bsdbpf
  https://gist.github.com/david415/d38936fd3e93168ae221

 only for *BSD with src/syscall/bpf_bsd.go
  https://golang.org/src/syscall/bpf_bsd.go
*/

package main

import (
	"encoding/hex"
	"fmt"
	"syscall"
	//"syscall/bpf_bsd"
)

func main() {
	enable := 1

	fd, err := syscall.Open("/dev/bpf0", syscall.O_RDWR, syscall.S_IRUSR|syscall.S_IWUSR)
	if err != nil {
		panic(err)
	}
	err = syscall.SetBpfInterface(fd, "vtnet0")
	if err != nil {
		panic(err)
	}
	err = syscall.SetBpfImmediate(fd, enable)
	if err != nil {
		panic(err)
	}
	err = syscall.SetBpfHeadercmpl(fd, enable)
	if err != nil {
		panic(err)
	}

	var bufLen int
	bufLen, err = syscall.BpfBuflen(fd)
	if err != nil {
		panic(err)
	}
	fmt.Printf("buflen %d\n", bufLen)

	err = syscall.SetBpfPromisc(fd, enable)
	if err != nil {
		panic(err)
	}

	var n int
	for {
		buf := make([]byte, bufLen)
		n, err = syscall.Read(fd, buf)
		if err != nil {
			panic(err)
		}
		//fmt.Printf("% X\n", buf[:n])
		fmt.Printf("\npacket of size %d captured\n", n)
		fmt.Print(hex.Dump(buf[:n]))

	}
}
