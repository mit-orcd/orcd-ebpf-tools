package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	// Build CollectionSpec so we can rewrite const volatile globals.
	spec, err := loadChmodblock()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	bmask := uint32(0o007)
	if s, ok := os.LookupEnv("BMASK"); ok {
		parsed, err := strconv.ParseUint(s, 8, 32)
		if err != nil {
			log.Fatalf("Invalid BMASK %q: %v", s, err)
		}
		bmask = uint32(parsed)
	}

	if err := spec.Variables["bmask"].Set(bmask); err != nil {
		log.Fatalf("Failed to set bmask: %v", err)
	} else {
		log.Printf("Correctly set bmask to %04o", bmask)
	}

	// Load eBPF objects compiled from restrict_chmod.c
	var objs chmodblockObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach the LSM program to the kernel
	lsm, err := link.AttachLSM(link.LSMOptions{
		Program: objs.chmodblockPrograms.RestrictChmodOtherBits,
	})
	if err != nil {
		log.Fatalf("Failed to attach LSM program: %v", err)
	}
	defer lsm.Close()

	log.Println("restrict_chmod LSM program loaded and attached successfully")
	log.Println("Restricting chmod to deny 'other' permission bits for non-root users")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Detaching and cleaning up...")
}
