package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/user"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
)

func makeUserColumns(width int, mode DisplayMode) []table.Column {
	ioHeader := "I/O (kB)"
	if mode == DisplayRates {
		ioHeader = "I/O (B/s)"
	}
	return []table.Column{
		{Title: "USER", Width: width * 12 / 100},
		{Title: ioHeader, Width: width * 10 / 100},
		{Title: "%", Width: width * 5 / 100},
	}
}

func makeTrafficColumnsWithIP(width int, mode DisplayMode) []table.Column {
	if mode == DisplayRates {
		return []table.Column{
			{Title: "PATH HINT", Width: width * 30 / 100},
			{Title: "IPv4", Width: width * 9 / 100},
			{Title: "R/s", Width: width * 6 / 100},
			{Title: "RB/s", Width: width * 9 / 100},
			{Title: "W/s", Width: width * 6 / 100},
			{Title: "WB/s", Width: width * 9 / 100},
		}
	}
	return []table.Column{
		{Title: "PATH HINT", Width: width * 30 / 100},
		{Title: "IPv4", Width: width * 9 / 100},
		{Title: "READS", Width: width * 6 / 100},
		{Title: "RBYTES", Width: width * 9 / 100},
		{Title: "WRITES", Width: width * 6 / 100},
		{Title: "WBYTES", Width: width * 9 / 100},
	}
}

// fmtBytes formats a byte count as a human-readable size string.
func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fkB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// fmtRate formats a bytes/sec rate as a human-readable string.
func fmtRate(bps float64) string {
	switch {
	case bps >= 1<<30:
		return fmt.Sprintf("%.1fGB/s", bps/float64(1<<30))
	case bps >= 1<<20:
		return fmt.Sprintf("%.1fMB/s", bps/float64(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.1fkB/s", bps/float64(1<<10))
	default:
		return fmt.Sprintf("%.0fB/s", bps)
	}
}

// fmtOpsRate formats an ops/sec rate.
func fmtOpsRate(ops float64) string {
	if ops >= 1000 {
		return fmt.Sprintf("%.1fk/s", ops/1000)
	}
	return fmt.Sprintf("%.1f/s", ops)
}

func parse_ip(ip uint32) string {
	var ipBytes [4]byte
	binary.LittleEndian.PutUint32(ipBytes[:], ip)
	ip_addr := netip.AddrFrom4(ipBytes)
	return ip_addr.String()
}

func (m *model) updateUserTable() {
	m.user_table.SetColumns(makeUserColumns(m.width, m.displayMode))
	m.user_table.SetHeight(m.height - 4)

	m.sw.total_summary.sortUsers(m.displayMode == DisplayRates)

	rows := make([]table.Row, 0)

	for _, um := range m.sw.total_summary.ordered_users {
		usr := um.uid
		var username string
		usrstr := fmt.Sprintf("%d", usr)
		u, err := user.LookupId(usrstr)
		if err != nil {
			username = usrstr
		} else {
			username = u.Username
		}

		var ioVal string
		if m.displayMode == DisplayRates {
			ioVal = fmtRate(um.usage_rate)
		} else {
			ioVal = fmtBytes(um.usage_total)
		}

		r := table.Row{
			username,
			ioVal,
			fmt.Sprintf("%.1f%%", um.usage_normalized*100),
		}
		rows = append(rows, r)
	}

	m.user_table.SetRows(rows)
}

func (m *model) updateTrafficTableWithIP(uid uint32) {
	m.traffic_table.SetColumns(makeTrafficColumnsWithIP(m.width, m.displayMode))
	m.traffic_table.SetHeight(m.height - 4)

	user_metric := m.sw.total_summary.users[uid]

	if m.displayMode == DisplayRates {
		user_metric.sortFiles(SortByTotalRate)
	} else {
		user_metric.sortFiles(SortByTotalBytes)
	}

	rows := make([]table.Row, 0)

	for _, file := range user_metric.ordered_files {
		m.sw.ino_mu.RLock()
		filename, ok := m.sw.ino_to_filenames[file.ino]
		m.sw.ino_mu.RUnlock()
		if !ok {
			filename = fmt.Sprintf("%d", file.ino)
		}

		var r table.Row
		if m.displayMode == DisplayRates {
			r = table.Row{
				filename,
				parse_ip(file.ip),
				fmtOpsRate(file.r_ops_rate),
				fmtRate(file.r_bytes_rate),
				fmtOpsRate(file.w_ops_rate),
				fmtRate(file.w_bytes_rate),
			}
		} else {
			r = table.Row{
				filename,
				parse_ip(file.ip),
				fmt.Sprintf("%d", file.r_ops_count),
				fmtBytes(file.r_bytes),
				fmt.Sprintf("%d", file.w_ops_count),
				fmtBytes(file.w_bytes),
			}
		}
		rows = append(rows, r)
	}

	m.traffic_table.SetRows(rows)
}

func (m *model) updateTables() tea.Msg {

	m.user_table.SetColumns(makeUserColumns(m.width, m.displayMode))
	m.user_table.SetHeight(m.height - 4) // subtract space for header/footer/borders

	m.traffic_table.SetColumns(makeTrafficColumnsWithIP(m.width, m.displayMode))
	m.traffic_table.SetHeight(m.height - 4) // subtract space for header/footer/borders

	rows_users := make([]table.Row, 0)
	rows_traffic := make([]table.Row, 0)

	for usr, umetrics := range m.sw.total_summary.users {

		// uid to username resolution
		var username string
		usrstr := fmt.Sprintf("%d", usr)
		u, err := user.LookupId(usrstr)
		if err != nil {
			// fall back to uid
			username = usrstr
		} else {
			username = u.Username
		}

		for ino_ip, metrics := range umetrics.files {

			// ino to filename resolution
			m.sw.ino_mu.RLock()
			filename, ok := m.sw.ino_to_filenames[ino_ip.ino]
			m.sw.ino_mu.RUnlock()
			if !ok {
				filename = fmt.Sprintf("%d", ino_ip.ino)
			}

			r_user := table.Row{
				username,
				"",
				"",
			}
			rows_users = append(rows_users, r_user)

			r_traffic := table.Row{
				filename,
				parse_ip(ino_ip.ip),
				fmt.Sprintf("%d", metrics.r_ops_count),
				fmt.Sprintf("%d", metrics.r_bytes),
				fmt.Sprintf("%d", metrics.w_ops_count),
				fmt.Sprintf("%d", metrics.w_bytes),
			}
			rows_traffic = append(rows_traffic, r_traffic)
		}
	}

	m.user_table.SetRows(rows_users)
	m.traffic_table.SetRows(rows_traffic)

	return nil
}
