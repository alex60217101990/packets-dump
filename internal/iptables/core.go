package iptables

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/coreos/go-iptables/iptables"
)

type SysClassNetStatsElement struct {
	Path string
	Fd   *os.File
}

func Pps(close <-chan struct{}, iface string) {
	go func() {
		interval := time.Duration(1) * time.Second
		ticker := time.NewTicker(interval)
		sysPaths := []SysClassNetStatsElement{
			SysClassNetStatsElement{
				Path: fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", iface),
			},
			SysClassNetStatsElement{
				Path: fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", iface),
			},
		}

		err := os.Chmod(sysPaths[0].Path, 0644)
		if err != nil {
			log.Println(err)
			return
		}
		err = os.Chmod(sysPaths[1].Path, 0644)
		if err != nil {
			log.Println(err)
			return
		}
		var (
			oldRxPackets, oldTxPackets uint32
			newRxPackets, newTxPackets uint32
		)
		sysPaths[0].Fd, err = os.OpenFile(sysPaths[0].Path, os.O_RDWR, 0444)
		if err != nil {
			log.Println(err)
			return
		}
		sysPaths[1].Fd, err = os.OpenFile(sysPaths[1].Path, os.O_RDWR, 0444)
		if err != nil {
			log.Println(err)
			return
		}
		defer func() {
			ticker.Stop()
			for _, sys := range sysPaths {
				sys.Fd.Close()
			}
		}()
		// Start reading from the file with a reader.
		readers := []*bufio.Reader{
			bufio.NewReader(sysPaths[0].Fd),
			bufio.NewReader(sysPaths[1].Fd),
		}
		oldRxPackets, oldTxPackets = queueDiff(readers, sysPaths[0].Fd, sysPaths[1].Fd)
	Exit:
		for {
			select {
			case <-close:
				break Exit
			case <-ticker.C:
				newRxPackets, newTxPackets = queueDiff(readers, sysPaths[0].Fd, sysPaths[1].Fd)
				log.Printf("TX %s: %d pkts/s RX %s: %d pkts/s",
					iface, newTxPackets-oldTxPackets,
					iface, newRxPackets-oldRxPackets)
				oldRxPackets, oldTxPackets = newRxPackets, newTxPackets
			}
		}
	}()
}

func queueDiff(readers []*bufio.Reader, files ...*os.File) (rx, tx uint32) {
	defer func() {
		for _, file := range files {
			file.Seek(0, io.SeekStart)
		}
	}()
	var (
		data []byte
		buf  int64
	)
	data, _, err := readers[0].ReadLine()
	if err != nil {
		log.Println(err)
		return rx, tx
	}
	buf, err = strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		log.Println(err)
		return rx, tx
	}
	rx = uint32(buf)
	data, _, err = readers[1].ReadLine()
	if err != nil {
		log.Println(err)
		return rx, tx
	}
	buf, err = strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		log.Println(err)
		return rx, tx
	}
	tx = uint32(buf)
	return rx, tx
}

// TODO: implement irq_balance script and finished iptables forwarding interface...

func AddForwardRule() {
	ipt, err := iptables.New()
	table := "nat"
	iface := "eth0"
	chain := "PREROUTING"
	// put a simple rule in
	err = ipt.Append(table, chain, "-i", iface, "-p", "tcp", "--dport", "4224", "-j", "DNAT", "--to-destination", "172.28.1.2:7777")
	if err != nil {
		log.Printf("Append failed: %v", err)
	}
	log.Println("add success!!!")
}

func DelForwardRule() {
	ipt, err := iptables.New()
	table := "nat"
	iface := "eth0"
	chain := "PREROUTING"
	// drop a simple rule in
	err = ipt.Delete(table, chain, "-i", iface, "-p", "tcp", "--dport", "4224", "-j", "DNAT", "--to-destination", "172.28.1.2:7777")
	if err != nil {
		log.Printf("Delete failed: %v", err)
	}
	log.Println("del success!!!")
}
