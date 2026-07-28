package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

/** If Styles do not display in TMUX:

Go or create ~/.tmux.conf and append:
```
set -g default-terminal "tmux-256color"
set -g terminal-overrides 'xterm*:Tc'
```

Then set it as the source file
`tmux source-file ~/.tmux.conf`
**/

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type DisplayMode int

const (
	DisplayTotals DisplayMode = iota
	DisplayRates
)

type model struct {
	user_table    table.Model
	traffic_table table.Model
	sw            *SlidingWindow
	objs          *collectorObjects
	width         int
	height        int
	help          help.Model
	displayMode   DisplayMode
}

type updateTickMsg time.Time

func updateTableEvery(delay time.Duration) tea.Cmd {
	return tea.Every(delay, func(t time.Time) tea.Msg {
		return updateTickMsg(t)
	})
}

func (m *model) Init() tea.Cmd { return updateTableEvery(1 * time.Second) }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case updateTickMsg:
		m.sw.UpdateMetrics(m.objs.NfsOpsCounts)
		// m.updateTables()
		m.updateUserTable()
		// Check the cursor location
		if m.user_table.Focused() {
			idx := m.user_table.Cursor()
			if idx >= 0 && len(m.sw.total_summary.ordered_users) > 0 {
				uid := m.sw.total_summary.ordered_users[idx].uid
				m.updateTrafficTableWithIP(uid)
			}
		}
		return m, tea.Batch(
			updateTableEvery(1 * time.Second),
		)
	case tea.KeyMsg:
		switch msg.String() {
		case "t":
			if m.displayMode == DisplayTotals {
				m.displayMode = DisplayRates
			} else {
				m.displayMode = DisplayTotals
			}
			m.updateUserTable()
			if m.user_table.Focused() {
				idx := m.user_table.Cursor()
				if idx >= 0 && len(m.sw.total_summary.ordered_users) > 0 {
					uid := m.sw.total_summary.ordered_users[idx].uid
					m.updateTrafficTableWithIP(uid)
				}
			}
		case "esc", "tab":
			if m.user_table.Focused() {
				m.user_table.Blur()
				m.traffic_table.Focus()
			} else {
				m.user_table.Focus()
				m.traffic_table.Blur()
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		//case "enter":
		//	if m.user_table.Focused() {
		//		idx := m.user_table.Cursor()
		//		uid := m.sw.total_summary.ordered_users[idx].uid
		//		m.updateTrafficTableWithIP(uid)
		//		m.selected_uid = &uid
		//	}
		//	return m, tea.Batch(
		//		tea.Printf("Let's go to %s!", m.user_table.SelectedRow()[1]),
		//	)
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// m.updateTables()
		m.updateUserTable()
	}

	m.user_table, cmd = m.user_table.Update(msg) // table keymaps
	return m, cmd
}

func (m *model) View() string {
	left := baseStyle.Render(m.user_table.View())
	right := baseStyle.Render(m.traffic_table.View())
	joint := lipgloss.JoinHorizontal(lipgloss.Top, left, right)

	modeLabel := "totals"
	if m.displayMode == DisplayRates {
		modeLabel = "rates"
	}
	helpView := m.help.ShortHelpView(m.user_table.KeyMap.ShortHelp())
	return joint + "\n" + helpView + fmt.Sprintf("  • t: toggle mode [%s]", modeLabel) + "\n"
}

func bubble_render(sw *SlidingWindow, objs *collectorObjects) {

	w, h, err := term.GetSize(0)
	if err != nil {
		fmt.Println("Could not get window size, making best guess")
		w, h = 80, 25
	}

	user_columns := makeUserColumns(w, DisplayTotals)
	traffic_columns := makeTrafficColumnsWithIP(w, DisplayTotals)

	rows := []table.Row{
		// {"1", "test", "1", "4096", "31", "51283491", "path"},
	}

	users_table := table.New(
		table.WithColumns(user_columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(h-5), // padding
	)

	traffic_table := table.New(
		table.WithColumns(traffic_columns),
		table.WithRows(rows),
		table.WithFocused(false),
		table.WithHeight(h-5),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	users_table.SetStyles(s)
	traffic_table.SetStyles(s)

	m := model{users_table, traffic_table, sw, objs, w, h, help.New(), DisplayTotals}
	if _, err := tea.NewProgram(&m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
