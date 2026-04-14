package dashboard

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/watchblind/agent/internal/alert"
	"github.com/watchblind/agent/internal/collector"
	"github.com/watchblind/agent/internal/sender"
	"github.com/watchblind/agent/internal/wal"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type Dashboard struct {
	app          *tview.Application
	metricsTable *tview.Table
	processTable *tview.Table
	alertsView   *tview.TextView
	senderView   *tview.TextView
	statusBar    *tview.TextView

	snapCh     <-chan collector.Snapshot
	alertCh    <-chan alert.AlertEvent
	alertState *alert.StateTracker
	sender     *sender.MockSender
	procCol    *collector.ProcessCollector
	wal        *wal.WAL
	lastAckTS  atomic.Int64
}

func New(
	snapCh <-chan collector.Snapshot,
	alertCh <-chan alert.AlertEvent,
	alertState *alert.StateTracker,
	snd *sender.MockSender,
	procCol *collector.ProcessCollector,
	w *wal.WAL,
) *Dashboard {
	return &Dashboard{
		snapCh:     snapCh,
		alertCh:    alertCh,
		alertState: alertState,
		sender:     snd,
		procCol:    procCol,
		wal:        w,
	}
}

// NoteAck records that a server ack was received now. Used by the dashboard to
// display "seconds since last ack" as a reconnection / data-flow indicator.
func (d *Dashboard) NoteAck() { d.lastAckTS.Store(time.Now().Unix()) }

func (d *Dashboard) Run() error {
	d.app = tview.NewApplication()

	// Use terminal's native background instead of tview's default
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault

	// Metrics table
	d.metricsTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(false, false)
	d.metricsTable.SetBorder(true).SetTitle(" System Metrics ")
	d.metricsTable.SetBackgroundColor(tcell.ColorDefault)

	// Process table
	d.processTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(false, false).
		SetFixed(1, 0)
	d.processTable.SetBorder(true).SetTitle(" Processes (by CPU) ")
	d.processTable.SetBackgroundColor(tcell.ColorDefault)

	// Alerts view
	d.alertsView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	d.alertsView.SetBorder(true).SetTitle(" Alerts ")
	d.alertsView.SetBackgroundColor(tcell.ColorDefault)

	// Sender log
	d.senderView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	d.senderView.SetBorder(true).SetTitle(" Sender Log ")
	d.senderView.SetBackgroundColor(tcell.ColorDefault)

	// Status bar
	d.statusBar = tview.NewTextView().
		SetDynamicColors(true)
	d.statusBar.SetBackgroundColor(tcell.ColorDefault)
	d.statusBar.SetText("[yellow]blind.watch agent[white] | Press [green]q[white] to quit")

	// Layout: left column = system metrics + alerts, right = processes
	leftCol := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(d.metricsTable, 0, 2, false).
		AddItem(d.alertsView, 6, 0, false)

	topRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(leftCol, 0, 1, false).
		AddItem(d.processTable, 0, 2, false)

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(topRow, 0, 4, false).
		AddItem(d.senderView, 8, 0, false).
		AddItem(d.statusBar, 1, 0, false)

	d.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Key() == tcell.KeyCtrlC {
			d.app.Stop()
			return nil
		}
		return event
	})

	// Start update goroutines
	go d.watchSnapshots()
	go d.watchAlerts()
	go d.watchSender()

	return d.app.SetRoot(layout, true).Run()
}

func (d *Dashboard) watchSnapshots() {
	for snap := range d.snapCh {
		s := snap
		// Collect process info on each tick
		procs := d.procCol.CollectProcesses(context.Background())
		d.app.QueueUpdateDraw(func() {
			d.updateMetrics(s)
			d.updateProcesses(procs)
		})
	}
}

func (d *Dashboard) watchAlerts() {
	for range d.alertCh {
		d.app.QueueUpdateDraw(func() {
			d.updateAlerts()
		})
	}
}

func (d *Dashboard) watchSender() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		d.app.QueueUpdateDraw(func() {
			d.updateSender()
		})
	}
}

func (d *Dashboard) updateMetrics(snap collector.Snapshot) {
	d.metricsTable.Clear()

	// Headers
	headers := []string{"Metric", "Value", "Labels"}
	for i, h := range headers {
		cell := tview.NewTableCell(h).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false).
			SetExpansion(1)
		d.metricsTable.SetCell(0, i, cell)
	}

	// Sort metrics for stable display, exclude process_count from system table
	metrics := make([]collector.Metric, 0, len(snap.Metrics))
	for _, m := range snap.Metrics {
		metrics = append(metrics, m)
	}
	sort.Slice(metrics, func(i, j int) bool {
		ki := metrics[i].Name + labelKey(metrics[i].Labels)
		kj := metrics[j].Name + labelKey(metrics[j].Labels)
		return ki < kj
	})

	for i, m := range metrics {
		row := i + 1
		d.metricsTable.SetCell(row, 0,
			tview.NewTableCell(m.Name).SetTextColor(tcell.ColorWhite))
		d.metricsTable.SetCell(row, 1,
			tview.NewTableCell(formatValue(m.Name, m.Value)).SetTextColor(colorForValue(m.Name, m.Value)))
		d.metricsTable.SetCell(row, 2,
			tview.NewTableCell(formatLabels(m.Labels)).SetTextColor(tcell.ColorGray))
	}

	files := d.wal.Count()
	bytes := d.wal.PendingBytes()
	last := d.lastAckTS.Load()
	since := "never"
	if last > 0 {
		since = fmt.Sprintf("%ds", time.Now().Unix()-last)
	}
	d.statusBar.SetText(fmt.Sprintf(
		"[yellow]blind.watch agent[white] | [green]%d[white] metrics | WAL [green]%d[white] files / [green]%s[white] | last ack [green]%s[white] | %s | [green]q[white]=quit",
		len(metrics), files, formatBytes(float64(bytes)), since, snap.Timestamp.Format("15:04:05"),
	))
}

func (d *Dashboard) updateProcesses(procs []collector.ProcessInfo) {
	d.processTable.Clear()

	headers := []string{"PID", "User", "CPU%", "MEM%", "RSS", "Threads", "IO R", "IO W", "State", "Name", "Command"}
	for i, h := range headers {
		cell := tview.NewTableCell(h).
			SetTextColor(tcell.ColorYellow).
			SetSelectable(false)
		if i >= 9 { // Name and Command columns expand
			cell.SetExpansion(1)
		}
		d.processTable.SetCell(0, i, cell)
	}

	for i, p := range procs {
		row := i + 1
		d.processTable.SetCell(row, 0,
			tview.NewTableCell(fmt.Sprintf("%d", p.PID)).SetTextColor(tcell.ColorWhite))
		d.processTable.SetCell(row, 1,
			tview.NewTableCell(truncate(p.User, 10)).SetTextColor(tcell.ColorWhite))
		d.processTable.SetCell(row, 2,
			tview.NewTableCell(fmt.Sprintf("%.1f", p.CPU)).SetTextColor(cpuColor(p.CPU)))
		d.processTable.SetCell(row, 3,
			tview.NewTableCell(fmt.Sprintf("%.1f", p.MemPct)).SetTextColor(pctColor(float64(p.MemPct))))
		d.processTable.SetCell(row, 4,
			tview.NewTableCell(formatBytes(float64(p.MemRSS))).SetTextColor(tcell.ColorWhite))
		d.processTable.SetCell(row, 5,
			tview.NewTableCell(fmt.Sprintf("%d", p.Threads)).SetTextColor(tcell.ColorWhite))
		d.processTable.SetCell(row, 6,
			tview.NewTableCell(formatBytes(float64(p.IORead))).SetTextColor(tcell.ColorWhite))
		d.processTable.SetCell(row, 7,
			tview.NewTableCell(formatBytes(float64(p.IOWrite))).SetTextColor(tcell.ColorWhite))
		d.processTable.SetCell(row, 8,
			tview.NewTableCell(processStateLabel(p.Status)).SetTextColor(processStateColor(p.Status)))
		d.processTable.SetCell(row, 9,
			tview.NewTableCell(truncate(p.Name, 20)).SetTextColor(tcell.ColorGreen))
		d.processTable.SetCell(row, 10,
			tview.NewTableCell(truncate(p.Cmdline, 60)).SetTextColor(tcell.ColorGray))
	}
}

func (d *Dashboard) updateAlerts() {
	var b strings.Builder
	states := d.alertState.All()
	if len(states) == 0 {
		b.WriteString("[gray]No alert rules configured")
	}
	for _, s := range states {
		var color string
		switch s.Status {
		case alert.StatusOK:
			color = "green"
		case alert.StatusPending:
			color = "yellow"
		case alert.StatusFiring:
			color = "red"
		}
		b.WriteString(fmt.Sprintf("[%s]%-8s[white] %s: %.1f (threshold: %.1f)\n",
			color, s.Status, s.RuleName, s.CurrentValue, s.Threshold))
	}
	d.alertsView.SetText(b.String())
}

func (d *Dashboard) updateSender() {
	logs := d.sender.RecentLogs(10)
	var b strings.Builder
	if len(logs) == 0 {
		b.WriteString("[gray]No payloads sent yet")
	}
	for _, l := range logs {
		b.WriteString(fmt.Sprintf("[blue]%s[white] -> %s [gray](%d bytes)[white]\n  %s\n",
			l.Timestamp.Format("15:04:05"), l.Endpoint, l.PayloadSize, l.Encrypted))
	}
	d.senderView.SetText(b.String())
}

func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(labels[k])
		b.WriteString(",")
	}
	return b.String()
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func formatValue(name string, value float64) string {
	switch {
	case strings.HasSuffix(name, "_percent"):
		return fmt.Sprintf("%.1f%%", value)
	case strings.HasSuffix(name, "_bytes"):
		return formatBytes(value)
	case strings.HasSuffix(name, "_per_sec"):
		return formatBytes(value) + "/s"
	case strings.HasSuffix(name, "_celsius"):
		return fmt.Sprintf("%.0f°C", value)
	case name == "process_count":
		return fmt.Sprintf("%.0f", value)
	default:
		return fmt.Sprintf("%.2f", value)
	}
}

func formatBytes(b float64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%.0f B", b)
	}
	div, exp := float64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", b/div, "KMGTPE"[exp])
}

func colorForValue(name string, value float64) tcell.Color {
	if strings.HasSuffix(name, "_percent") {
		return pctColor(value)
	}
	return tcell.ColorWhite
}

func pctColor(value float64) tcell.Color {
	switch {
	case value > 90:
		return tcell.ColorRed
	case value > 70:
		return tcell.ColorYellow
	default:
		return tcell.ColorGreen
	}
}

func cpuColor(value float64) tcell.Color {
	switch {
	case value > 50:
		return tcell.ColorRed
	case value > 20:
		return tcell.ColorYellow
	case value > 1:
		return tcell.ColorGreen
	default:
		return tcell.ColorWhite
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}

func processStateLabel(status string) string {
	switch status {
	case "R":
		return "Run"
	case "S":
		return "Sleep"
	case "D":
		return "DiskW"
	case "Z":
		return "Zombi"
	case "T":
		return "Stop"
	case "I":
		return "Idle"
	default:
		return status
	}
}

func processStateColor(status string) tcell.Color {
	switch status {
	case "R":
		return tcell.ColorGreen
	case "S", "I":
		return tcell.ColorGray
	case "D":
		return tcell.ColorYellow
	case "Z":
		return tcell.ColorRed
	case "T":
		return tcell.ColorOrange
	default:
		return tcell.ColorWhite
	}
}
