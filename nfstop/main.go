package main

import (
	"log"
	"os"

	"github.com/cilium/ebpf/link"
)

func main() {

	/* Load and Attach eBPF Programs */

	// Load eBPF objects to the objs struct
	var objs collectorObjects
	if err := loadCollectorObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Attach to kernel
	wlink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.WriteOps,
	})
	if err != nil {
		log.Fatal("Attaching Write Fentry:", err)
	}
	defer wlink.Close()

	rlink, err := link.AttachTracing(link.TracingOptions{
		Program: objs.ReadOps,
	})
	if err != nil {
		log.Fatal("Attaching Read Fentry:", err)
	}
	defer rlink.Close()

	log.Printf("Programs Loaded!\n")

	/* Window & Display Logic */
	sw := InitWindow()

	go sw.MaintainInodeResolution(objs.collectorMaps.Events)

	if len(os.Args) > 1 && os.Args[1] == "simple" {
		simple_render(sw, &objs)
	} else {
		bubble_render(sw, &objs)
	}
}
