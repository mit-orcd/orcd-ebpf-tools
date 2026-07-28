package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"time"
)

const time_per_query = 1

func simple_render(sw *SlidingWindow, objs *collectorObjects) {
	kill_sig := make(chan os.Signal, 1)
	signal.Notify(kill_sig, os.Interrupt) // catch exiting program

	ticker := time.NewTicker(time_per_query * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-kill_sig:
			log.Printf("Exiting...")
			return

		case <-ticker.C:

			/* TODO: Change for bubble tea TUI */
			fmt.Print("\033[H\033[2J")
			log.Printf("Accumulated Writes:")

			for usr, files := range sw.total_summary.users {
				fmt.Printf("===== UID %d =====\n", usr)
				for ino_ip, metrics := range files.files {

					var ipBytes [4]byte
					binary.LittleEndian.PutUint32(ipBytes[:], ino_ip.ip)
					ip_addr := netip.AddrFrom4(ipBytes)

					fmt.Printf("ino %d, ip %s: r%d rb%d w%d wb%d\n", ino_ip.ino, ip_addr.String(), metrics.r_ops_count, metrics.r_bytes, metrics.w_ops_count, metrics.w_bytes)
				}
			}

			fmt.Printf("\n\n==== LOG ====\n")

			sw.UpdateMetrics(objs.NfsOpsCounts)
		}
	}
}
