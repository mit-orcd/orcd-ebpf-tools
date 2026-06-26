package main

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type SlidingWindow struct {
	time_per_update_ms int

	// Window Logic to implement later
	// total_display_time_s int
	// windows              []WindowSummary
	// start_window         int // index of oldest window
	// current_window       int // index of newest window
	// windows_max_quantity int // maximum number of windows to store

	total_summary WindowSummary

	ino_mu           sync.RWMutex
	ino_to_filenames map[uint64]string

	last_update     time.Time
	last_interval_s float64
}

/* Structures to store all aggregated metrics */
type WindowSummary struct {
	users map[uint32]*UserMetrics // uid --> UserMetrics --(ino, ip)---> FileMetrics
	ips   map[uint32]*IpMetrics   // ip ---> IpMetrics ----(ino, uid)--> FileMetrics

	ordered_users []*UserMetrics // default: ordered by highest usage
	ordered_ips   []*IpMetrics
}

func (w *WindowSummary) sortUsers(byRate bool) {
	var grand_total uint64
	var grand_rate float64

	for _, user := range w.users {
		grand_total += user.usage_total
		grand_rate += user.usage_rate
	}

	// TODO: instead of recreating array, just add new users
	w.ordered_users = make([]*UserMetrics, 0)
	for _, user := range w.users {
		if byRate {
			if grand_rate > 0 {
				user.usage_normalized = float32(user.usage_rate) / float32(grand_rate)
			}
		} else {
			if grand_total > 0 {
				user.usage_normalized = float32(user.usage_total) / float32(grand_total)
			}
		}
		w.ordered_users = append(w.ordered_users, user)
	}

	slices.SortFunc(w.ordered_users, func(a, b *UserMetrics) int {
		if byRate {
			return cmp.Compare(b.usage_rate, a.usage_rate)
		}
		return cmp.Compare(b.usage_total, a.usage_total)
	})
}

type InoIpKey struct {
	ino uint64
	ip  uint32
}

type InoUidKey struct {
	ino uint64
	uid uint32
}

// Metrics from a specific user
type UserMetrics struct {
	files            map[InoIpKey]*FileMetrics
	usage_total      uint64
	usage_rate       float64 // bytes/sec in the last collection interval
	usage_normalized float32

	ordered_files []*FileMetrics
	uid           uint32
}

type FileSortOrder int

const (
	SortByReadBytes FileSortOrder = iota
	SortByWriteBytes
	SortByTotalBytes
	SortByReadRate
	SortByWriteRate
	SortByTotalRate
)

func (um *UserMetrics) sortFiles(orderBy FileSortOrder) {
	// todo: instead of recreating entire array, just add new files (i.e. need to keep track of what files are new)
	um.ordered_files = make([]*FileMetrics, 0)
	for _, file := range um.files {
		um.ordered_files = append(um.ordered_files, file)
	}
	slices.SortFunc(um.ordered_files, func(a, b *FileMetrics) int {
		switch orderBy {
		case SortByReadBytes:
			return cmp.Compare(b.r_bytes, a.r_bytes)
		case SortByWriteBytes:
			return cmp.Compare(b.w_bytes, a.w_bytes)
		case SortByTotalBytes:
			return cmp.Compare(b.r_bytes+b.w_bytes, a.r_bytes+a.w_bytes)
		case SortByReadRate:
			return cmp.Compare(b.r_bytes_rate, a.r_bytes_rate)
		case SortByWriteRate:
			return cmp.Compare(b.w_bytes_rate, a.w_bytes_rate)
		case SortByTotalRate:
			return cmp.Compare(b.r_bytes_rate+b.w_bytes_rate, a.r_bytes_rate+a.w_bytes_rate)
		}
		return cmp.Compare(b.r_bytes+b.w_bytes, a.r_bytes+a.w_bytes)
	})
}

// Metrics from a specific ip
type IpMetrics struct {
	files            map[InoUidKey]*FileMetrics
	usage_total      uint64
	usage_normalized float32

	ordered_files []*FileMetrics
}

type FileMetrics struct {
	r_ops_count uint64
	r_bytes     uint64
	w_ops_count uint64
	w_bytes     uint64

	// Per-interval rates (set each collection cycle)
	r_ops_rate   float64
	r_bytes_rate float64
	w_ops_rate   float64
	w_bytes_rate float64

	ino uint64
	ip  uint32
	uid uint32
}

func InitWindow() SlidingWindow {
	sw := SlidingWindow{}
	sw.total_summary.users = make(map[uint32]*UserMetrics)
	sw.total_summary.ips = make(map[uint32]*IpMetrics)
	sw.ino_to_filenames = make(map[uint64]string)

	return sw
}

// Continually populates sw.ino_to_filenames using the ebpf ringbuffer
func (sw *SlidingWindow) MaintainInodeResolution(file_ringbuf *ebpf.Map) {
	rd, err := ringbuf.NewReader(file_ringbuf)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	var event collectorEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received close signal of ringbuf, exiting...")
				return
			}
			log.Printf("reading ringbuf error: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event error: %s", err)
			continue
		}

		sw.ino_mu.Lock()
		sw.ino_to_filenames[event.Ino] = string(event.Pname[:bytes.IndexByte(event.Pname[:], 0)]) + "/" + string(event.Name[:bytes.IndexByte(event.Name[:], 0)])
		sw.ino_mu.Unlock()
	}
}

// UpdateMetrics drains the eBPF map, accumulates totals, and computes
// per-interval rates based on the elapsed time since the last call.
func (sw *SlidingWindow) UpdateMetrics(ebpf_map *ebpf.Map) {
	now := time.Now()
	elapsed_s := 1.0 // safe default for the very first call
	if !sw.last_update.IsZero() {
		elapsed_s = now.Sub(sw.last_update).Seconds()
		if elapsed_s <= 0 {
			elapsed_s = 1.0
		}
	}
	sw.last_update = now
	sw.last_interval_s = elapsed_s

	w := &sw.total_summary

	// Zero out all rate fields so files with no activity this interval show 0.
	for _, um := range w.users {
		um.usage_rate = 0
		for _, fm := range um.files {
			fm.r_ops_rate = 0
			fm.r_bytes_rate = 0
			fm.w_ops_rate = 0
			fm.w_bytes_rate = 0
		}
	}

	iterator := ebpf_map.Iterate()

	var keys []collectorKeyT

	var valtmp []collectorValT
	var key collectorKeyT
	// populate all the keys
	for iterator.Next(&key, &valtmp) {
		keys = append(keys, key)
	}

	// obtain the values corresponding to the keys
	for _, k := range keys {
		var perCPUVals []collectorValT
		if err := ebpf_map.LookupAndDelete(k, &perCPUVals); err != nil {
			log.Printf("Delete error %v", err)
			continue
		}

		// Sum values across all CPUs before aggregating
		var val collectorValT
		for _, cpuVal := range perCPUVals {
			val.W_requests += cpuVal.W_requests
			val.W_bytes += cpuVal.W_bytes
			val.R_requests += cpuVal.R_requests
			val.R_bytes += cpuVal.R_bytes
		}

		/** Add data to user metrics **/
		user_metrics, ok := w.users[k.Uid]
		if !ok {
			user_metrics = &UserMetrics{
				files: make(map[InoIpKey]*FileMetrics),
			}
			w.users[k.Uid] = user_metrics
			user_metrics.uid = k.Uid
		}

		if user_metrics.files == nil {
			user_metrics.files = make(map[InoIpKey]*FileMetrics)
		}
		file_ip_key := InoIpKey{ino: k.Ino, ip: k.Ipv4}
		file_metrics, ok := user_metrics.files[file_ip_key]
		if !ok {
			file_metrics = &FileMetrics{}
			file_metrics.ino = k.Ino
			file_metrics.ip = k.Ipv4
			file_metrics.uid = k.Uid
		}

		// Accumulate totals
		file_metrics.w_ops_count += val.W_requests
		file_metrics.w_bytes += val.W_bytes
		file_metrics.r_ops_count += val.R_requests
		file_metrics.r_bytes += val.R_bytes

		// Set per-interval rates
		file_metrics.r_ops_rate += float64(val.R_requests) / elapsed_s
		file_metrics.r_bytes_rate += float64(val.R_bytes) / elapsed_s
		file_metrics.w_ops_rate += float64(val.W_requests) / elapsed_s
		file_metrics.w_bytes_rate += float64(val.W_bytes) / elapsed_s

		// Update UserMetrics
		user_metrics.files[file_ip_key] = file_metrics
		user_metrics.usage_total += val.W_bytes + val.R_bytes
		user_metrics.usage_rate += float64(val.W_bytes+val.R_bytes) / elapsed_s

		/** Add data to ip metrics **/
		ip_metrics, ok := w.ips[k.Ipv4]
		if !ok {
			ip_metrics = &IpMetrics{
				files: make(map[InoUidKey]*FileMetrics),
			}
		}
		if ip_metrics.files == nil {
			ip_metrics.files = make(map[InoUidKey]*FileMetrics)
		}
		file_uid_key := InoUidKey{ino: k.Ino, uid: k.Uid}
		ip_metrics.files[file_uid_key] = file_metrics
		w.ips[k.Ipv4] = ip_metrics
	}
}
