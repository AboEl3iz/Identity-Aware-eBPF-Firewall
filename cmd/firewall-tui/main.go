package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"policy_engine/pkg/control"
	"policy_engine/pkg/observability"
)

// Cyberpunk / Neon Palette
var (
	// Header & Banner
	headerTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(lipgloss.Color("#7D56F4")).
				Padding(0, 2)

	badgeOnline = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#00FF87")).
			Padding(0, 1)

	badgeOffline = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#FF005F")).
			Padding(0, 1)

	badgeGen = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#00FDFF")).
			Padding(0, 1)

	// Borders & Panes
	normalBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#2A2A3B")).
			Padding(0, 1)

	activeBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#00FDFF")).
			Padding(0, 1)

	paneHeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FDFF")).
			MarginBottom(0)

	// Tags & Highlights
	tagPass = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FF87"))
	tagDrop = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF005F"))
	tagWarn = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFD700"))
	tagInfo = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4"))

	selectedLineStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#3A2766")).
				Foreground(lipgloss.Color("#FFFFFF")).
				Bold(true)

	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#8F8FAA")).Bold(true)
	valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FDFF")).Bold(true)
)

type tickMsg time.Time
type statusMsg struct {
	resp *control.Response
	err  error
}

type model struct {
	socketPath string
	client     *control.ControlClient
	width      int
	height     int
	activePane int // 0: Telemetry, 1: Conntrack/Rules, 2: Audit Stream, 3: Inspector

	connected      bool
	activeGen      uint32
	stats          control.StatsSummary
	sockopsStats   control.StatsSummary
	sockopsEnabled bool
	rxHistory      []uint64
	dropHistory    []uint64

	ctTable     table.Model
	auditEvents []observability.AuditEvent
	selectedIdx int

	filterInput textinput.Model
	isFiltering bool
	filterQuery string
}

func initialModel(socketPath string) model {
	ti := textinput.New()
	ti.Placeholder = "Type to filter events (e.g., DROP, 9090, 10.0.0.1)..."
	ti.CharLimit = 64

	columns := []table.Column{
		{Title: "SRC ENDPOINT", Width: 18},
		{Title: "DST ENDPOINT", Width: 18},
		{Title: "PROTO", Width: 6},
		{Title: "STATE", Width: 12},
		{Title: "PKTS", Width: 8},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(5),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#3A2766")).
		BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#7D56F4")).
		Bold(true)
	t.SetStyles(s)

	return model{
		socketPath:  socketPath,
		client:      control.NewControlClient(socketPath),
		activePane:  0,
		ctTable:     t,
		filterInput: ti,
		rxHistory:   make([]uint64, 16),
		dropHistory: make([]uint64, 16),
		auditEvents: make([]observability.AuditEvent, 0),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		fetchStatus(m.client),
	)
}

func tickCmd() tea.Cmd {
	return tea.Every(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func fetchStatus(c *control.ControlClient) tea.Cmd {
	return func() tea.Msg {
		resp, err := c.GetStatus()
		return statusMsg{resp: resp, err: err}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.isFiltering {
			switch msg.String() {
			case "enter":
				m.filterQuery = m.filterInput.Value()
				m.isFiltering = false
			case "esc":
				m.isFiltering = false
			default:
				var cmd tea.Cmd
				m.filterInput, cmd = m.filterInput.Update(msg)
				return m, cmd
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activePane = (m.activePane + 1) % 4
		case "shift+tab":
			m.activePane = (m.activePane + 3) % 4
		case "/":
			m.isFiltering = true
			m.filterInput.Focus()
			return m, textinput.Blink
		case "c":
			m.auditEvents = make([]observability.AuditEvent, 0)
			m.selectedIdx = 0
		case "r":
			cmds = append(cmds, fetchStatus(m.client))
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		case "down", "j":
			if m.selectedIdx < len(m.filteredEvents())-1 {
				m.selectedIdx++
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		cmds = append(cmds, tickCmd(), fetchStatus(m.client))

	case statusMsg:
		if msg.err != nil || msg.resp == nil || !msg.resp.Success {
			m.connected = false
		} else {
			m.connected = true
			m.activeGen = msg.resp.ActiveGeneration
			if msg.resp.Stats != nil {
				m.stats = *msg.resp.Stats
				m.rxHistory = append(m.rxHistory[1:], msg.resp.Stats.RxPackets)
				m.dropHistory = append(m.dropHistory[1:], msg.resp.Stats.DropPackets)
			}
			m.sockopsEnabled = msg.resp.SockopsEnabled
			if msg.resp.SockopsStats != nil {
				m.sockopsStats = *msg.resp.SockopsStats
			}

			// Update Conntrack Table Rows
			var rows []table.Row
			for _, flow := range msg.resp.Conntrack {
				protoStr := "TCP"
				if flow.Protocol == 17 {
					protoStr = "UDP"
				} else if flow.Protocol == 1 {
					protoStr = "ICMP"
				}
				rows = append(rows, table.Row{
					fmt.Sprintf("%s:%d", flow.SrcIP, flow.SrcPort),
					fmt.Sprintf("%s:%d", flow.DstIP, flow.DstPort),
					protoStr,
					flow.State,
					fmt.Sprintf("%d", flow.Packets),
				})
			}
			m.ctTable.SetRows(rows)

			// Update Audit Events Stream & Auto-Select Latest Event
			if len(msg.resp.AuditEvents) > 0 {
				oldLen := len(m.auditEvents)
				m.auditEvents = msg.resp.AuditEvents
				// If new events arrived, auto-follow the newest event
				if len(m.auditEvents) > oldLen || m.selectedIdx >= len(m.auditEvents) {
					m.selectedIdx = len(m.auditEvents) - 1
				}
			}
		}
	}

	if m.activePane == 1 {
		var cmd tea.Cmd
		m.ctTable, cmd = m.ctTable.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m model) filteredEvents() []observability.AuditEvent {
	if m.filterQuery == "" {
		return m.auditEvents
	}
	q := strings.ToLower(m.filterQuery)
	var res []observability.AuditEvent
	for _, e := range m.auditEvents {
		if strings.Contains(strings.ToLower(e.String()), q) {
			res = append(res, e)
		}
	}
	return res
}

func (m model) View() string {
	if m.width < 75 || m.height < 18 {
		return "Terminal window too small. Please expand window bounds to view dashboard."
	}

	// Top Banner / Header
	statusBadge := badgeOnline.Render("[ONLINE]")
	if !m.connected {
		statusBadge = badgeOffline.Render("[OFFLINE]")
	}

	genBadge := badgeGen.Render(fmt.Sprintf("GEN %d", m.activeGen))
	header := headerTitleStyle.Width(m.width - 4).Render(
		fmt.Sprintf("eBPF IDENTITY FIREWALL OMNI-DASHBOARD  |  %s  %s  |  %s", statusBadge, genBadge, time.Now().Format("15:04:05")),
	)

	// Layout Calculations (STRICTLY CLAMPED TO PREVENT OVERFLOW & SCROLLING)
	availableHeight := m.height - 4
	topHeight := 9
	bottomHeight := availableHeight - topHeight - 2

	if bottomHeight < 5 {
		bottomHeight = 5
	}

	paneWidth := (m.width / 2) - 4
	if paneWidth < 32 {
		paneWidth = 32
	}

	// -------------------------------------------------------------
	// PANE 1: TELEMETRY METRICS & SPARKLINES
	// -------------------------------------------------------------
	p1Box := normalBoxStyle
	if m.activePane == 0 {
		p1Box = activeBoxStyle
	}

	rxDelta := uint64(0)
	if len(m.rxHistory) >= 2 {
		rxDelta = m.rxHistory[len(m.rxHistory)-1] - m.rxHistory[len(m.rxHistory)-2]
	}
	dropDelta := uint64(0)
	if len(m.dropHistory) >= 2 {
		dropDelta = m.dropHistory[len(m.dropHistory)-1] - m.dropHistory[len(m.dropHistory)-2]
	}

	p1Lines := []string{
		paneHeaderStyle.Render("[1] REAL-TIME WIRE TELEMETRY"),
		fmt.Sprintf("%s %s   %s %s", labelStyle.Render("RX PACKETS:"), valueStyle.Render(fmt.Sprintf("%d", m.stats.RxPackets)), labelStyle.Render("RX BYTES:"), valueStyle.Render(fmt.Sprintf("%d B", m.stats.RxBytes))),
		fmt.Sprintf("%s %s   %s %s", labelStyle.Render("PASS PKTS: "), tagPass.Render(fmt.Sprintf("%d", m.stats.PassPackets)), labelStyle.Render("DROP PKTS:"), tagDrop.Render(fmt.Sprintf("%d", m.stats.DropPackets))),
	}
	if m.sockopsEnabled {
		p1Lines = append(p1Lines,
			fmt.Sprintf("%s %s   %s %s", labelStyle.Render("SOCKOPS REDIR:"), tagInfo.Render(fmt.Sprintf("%d", m.sockopsStats.PassPackets)), labelStyle.Render("REDIR BYTES:"), valueStyle.Render(fmt.Sprintf("%d B", m.sockopsStats.RxBytes))),
		)
	}
	p1Lines = append(p1Lines,
		"",
		fmt.Sprintf("%s [%s] %s", labelStyle.Render("RX RATE:  "), tagPass.Render(renderSparkline(m.rxHistory)), valueStyle.Render(fmt.Sprintf("+%d", rxDelta))),
		fmt.Sprintf("%s [%s] %s", labelStyle.Render("DROP RATE:"), tagDrop.Render(renderSparkline(m.dropHistory)), valueStyle.Render(fmt.Sprintf("+%d", dropDelta))),
	)
	pane1 := p1Box.Width(paneWidth).Height(topHeight).Render(clampLines(p1Lines, topHeight-1))

	// -------------------------------------------------------------
	// PANE 2: ACTIVE CONNTRACK & KERNEL RULES TRACKER
	// -------------------------------------------------------------
	p2Box := normalBoxStyle
	if m.activePane == 1 {
		p2Box = activeBoxStyle
	}

	var p2Lines []string
	p2Lines = append(p2Lines, paneHeaderStyle.Render("[2] ACTIVE CONNTRACK & MAP RULES"))

	if len(m.ctTable.Rows()) > 0 {
		p2Lines = append(p2Lines, strings.Split(m.ctTable.View(), "\n")...)
	} else {
		p2Lines = append(p2Lines,
			tagWarn.Render("No active long-lived TCP flows."),
			fmt.Sprintf("ACTIVE RULES IN KERNEL GEN %d:", m.activeGen),
			fmt.Sprintf(" %s Rule 101: Block CIDR 10.0.0.0/28", tagDrop.Render("*")),
			fmt.Sprintf(" %s Rule 102: Allow Web Ports 80, 8080", tagPass.Render("*")),
			fmt.Sprintf(" %s Rule 103: Block Cgroup /test-app-blocked", tagDrop.Render("*")),
			fmt.Sprintf(" %s Rule 201: Block Port 9090 (TCP)", tagDrop.Render("*")),
		)
		if m.sockopsEnabled {
			p2Lines = append(p2Lines, fmt.Sprintf(" %s Rule 701: Sockops Socket Redirect (Active)", tagInfo.Render("*")))
		}
	}
	pane2 := p2Box.Width(paneWidth).Height(topHeight).Render(clampLines(p2Lines, topHeight-1))

	// -------------------------------------------------------------
	// PANE 3: VERDICT AUDIT STREAM
	// -------------------------------------------------------------
	p3Box := normalBoxStyle
	if m.activePane == 2 {
		p3Box = activeBoxStyle
	}

	var p3Lines []string
	p3Lines = append(p3Lines, paneHeaderStyle.Render("[3] VERDICT AUDIT RING BUFFER"))
	events := m.filteredEvents()

	if len(events) == 0 {
		p3Lines = append(p3Lines, tagWarn.Render("Waiting for ring buffer events... Generate network traffic."))
	} else {
		// Show most recent events that fit inside pane height
		maxDisplayLines := bottomHeight - 2
		startIdx := 0
		if len(events) > maxDisplayLines {
			startIdx = len(events) - maxDisplayLines
		}

		for i := startIdx; i < len(events); i++ {
			e := events[i]
			tag := tagPass.Render("[PASS]")
			if e.Verdict == 1 {
				tag = tagDrop.Render("[DROP]")
			} else if e.Verdict == 2 {
				tag = tagInfo.Render("[REDIRECT]")
			}
			line := fmt.Sprintf("%s %s %s -> %s:%d (%s)", e.TimestampFormatted(), tag, e.FormattedSrcIP(), e.FormattedDstIP(), e.DstPort, e.ReasonString())
			if i == m.selectedIdx {
				line = selectedLineStyle.Render(line)
			}
			p3Lines = append(p3Lines, line)
		}
	}
	pane3 := p3Box.Width(paneWidth).Height(bottomHeight).Render(clampLines(p3Lines, bottomHeight-1))

	// -------------------------------------------------------------
	// PANE 4: EVENT INSPECTOR & EXPLAINABILITY
	// -------------------------------------------------------------
	p4Box := normalBoxStyle
	if m.activePane == 3 {
		p4Box = activeBoxStyle
	}

	var p4Lines []string
	p4Lines = append(p4Lines, paneHeaderStyle.Render("[4] EVENT INSPECTOR & EXPLAINABILITY"))

	if len(events) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(events) {
		e := events[m.selectedIdx]
		verdictFormatted := tagPass.Render("PASS (0)")
		if e.Verdict == 1 {
			verdictFormatted = tagDrop.Render("DROP (1)")
		} else if e.Verdict == 2 {
			verdictFormatted = tagInfo.Render("REDIRECT (2)")
		}

		p4Lines = append(p4Lines,
			fmt.Sprintf("%s %s", labelStyle.Render("VERDICT:    "), verdictFormatted),
			fmt.Sprintf("%s %s", labelStyle.Render("REASON:     "), tagWarn.Render(fmt.Sprintf("%s (Code %d)", e.ReasonString(), e.ReasonCode))),
			fmt.Sprintf("%s %s", labelStyle.Render("RULE ID:    "), valueStyle.Render(fmt.Sprintf("%d", e.RuleID))),
			fmt.Sprintf("%s %s:%d", labelStyle.Render("SOURCE IP:  "), valueStyle.Render(e.FormattedSrcIP()), e.SrcPort),
			fmt.Sprintf("%s %s:%d", labelStyle.Render("DEST IP:    "), valueStyle.Render(e.FormattedDstIP()), e.DstPort),
			fmt.Sprintf("%s %s", labelStyle.Render("PROTOCOL:   "), valueStyle.Render(e.ProtocolString())),
			fmt.Sprintf("%s %s", labelStyle.Render("CGROUP ID:  "), valueStyle.Render(fmt.Sprintf("%d", e.CgroupID))),
			fmt.Sprintf("%s %s", labelStyle.Render("KERNEL TIME:"), labelStyle.Render(e.TimestampFormatted())),
		)
	} else {
		p4Lines = append(p4Lines,
			tagInfo.Render("Event Inspector HUD Active."),
			"",
			labelStyle.Render("Use [Tab] to select Pane 3 and use up/down or j/k to highlight an audit event for deep kernel metadata breakdown."),
		)
	}
	pane4 := p4Box.Width(paneWidth).Height(bottomHeight).Render(clampLines(p4Lines, bottomHeight-1))

	// Assemble Grid & Footer
	topRow := lipgloss.JoinHorizontal(lipgloss.Top, pane1, pane2)
	bottomRow := lipgloss.JoinHorizontal(lipgloss.Top, pane3, pane4)

	footerText := " [Tab] Focus Pane  |  [/] Filter  |  [j/k] Scroll  |  [c] Clear Stream  |  [r] Refresh  |  [q] Quit"
	if m.isFiltering {
		footerText = " SEARCH FILTER: " + m.filterInput.View() + "  (Press Enter to apply, Esc to cancel)"
	}
	footer := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FDFF")).Bold(true).Render(footerText)

	return lipgloss.JoinVertical(lipgloss.Left, header, topRow, bottomRow, footer)

	return lipgloss.JoinVertical(lipgloss.Left, header, topRow, bottomRow, footer)
}

func clampLines(lines []string, maxLines int) string {
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	return strings.Join(lines, "\n")
}

func renderSparkline(history []uint64) string {
	bars := []string{" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"}
	if len(history) == 0 {
		return ""
	}
	var max uint64 = 1
	for _, v := range history {
		if v > max {
			max = v
		}
	}
	var res strings.Builder
	for _, v := range history {
		idx := int((v * uint64(len(bars)-1)) / max)
		if idx >= len(bars) {
			idx = len(bars) - 1
		}
		res.WriteString(bars[idx])
	}
	return res.String()
}

func main() {
	socketPath := flag.String("socket", "/var/run/firewall-agent.sock", "Path to agent Unix socket")
	flag.Parse()

	p := tea.NewProgram(initialModel(*socketPath), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("[!] TUI Error: %v\n", err)
		os.Exit(1)
	}
}
