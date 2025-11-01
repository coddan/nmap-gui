package main

import (
	"context"
	"fmt"
	"strings"
	
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/Ullaakut/nmap/v3"
)

// Global UI components to update from the scan goroutine
var (
	scanButton   *widget.Button
	progressBar  *widget.ProgressBar
	resultOutput *widget.Entry
)

func main() {
	a := app.New()
	w := a.NewWindow("Nmap")
	w.Resize(fyne.NewSize(800, 600))

	// --- Input Fields ---
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("Enter Target IP (e.g., localhost, 127.0.0.1)")
	ipEntry.SetText("localhost")

	portsEntry := widget.NewEntry()
	portsEntry.SetPlaceHolder("Enter Ports (e.g., 1-1000, 80,443)")
	portsEntry.SetText("1-1000")

	// --- Progress & Output ---
	progressBar = widget.NewProgressBar()
	progressBar.Hide() // Start hidden

	resultOutput = widget.NewMultiLineEntry()
	resultOutput.SetPlaceHolder("Scan results will appear here...")
	resultOutput.Wrapping = fyne.TextWrapBreak
    
	// --- Scan Button ---
	scanButton = widget.NewButton("Start Scan", func() {
		scanButton.Disable()
		progressBar.SetValue(0)
		progressBar.Show()
		resultOutput.SetText("Starting Nmap scan...")

		go runNmapScan(ipEntry.Text, portsEntry.Text)
	})

	// --- Layout Setup ---
	inputForm := container.New(layout.NewGridLayout(2),
		widget.NewLabel("Target IP:"), ipEntry,
		widget.NewLabel("Ports:"), portsEntry,
	)

	// Combine all elements
	topContent := container.NewVBox(
		widget.NewLabelWithStyle("Nmap Scan Configuration", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		inputForm,
		container.NewHBox(layout.NewSpacer(), scanButton, layout.NewSpacer()),
		widget.NewLabel("Progress:"),
		progressBar,
		widget.NewLabel("Results:"),
	)

	bottomContent := container.NewMax(
		container.NewScroll(resultOutput),
	)


	split := container.NewVSplit(
		topContent,    // Top pane gets the fixed-size controls
		bottomContent, // Bottom pane gets the flexible, scrollable results
	)

	split.SetOffset(0.3) 

	w.SetContent(split)
	w.ShowAndRun()
	}

// nmap executes the nmap scan and updates the GUI
func runNmapScan(targetIP, ports string) {
	defer func() {
		scanButton.Enable()
		progressBar.Hide()
	}()

	updateResult("\nTarget: " + targetIP + ", Ports: " + ports)
	updateResult("This may take a moment...")

	// Create Scanner
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets(targetIP),
		nmap.WithPorts(ports),
		nmap.WithServiceInfo(),
	)
	if err != nil {
		updateResult(fmt.Sprintf("\nERROR: Failed to create nmap scanner: %v", err))
		return
	}

	progressChannel := make(chan float32, 1)
	go func() {
		for p := range progressChannel {
			progressBar.SetValue(float64(p) / 100.0)
		}
	}()

	result, warnings, err := scanner.Progress(progressChannel).Run()

	if len(*warnings) > 0 {
		updateResult(fmt.Sprintf("\nWARNINGS: Scan finished with warnings: %s", *warnings))
	}
	if err != nil {
		updateResult(fmt.Sprintf("\nERROR: Unable to run nmap scan: %v", err))
		return
	}

	formatResults(result)
}

// updateResult safely appends text to the resultOutput widget
func updateResult(text string) {
	resultOutput.Append(text)
}

// formatResults processes the nmap result structure into a readable string for the GUI
func formatResults(result *nmap.Run) {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("\n\n--- Nmap Scan Complete ---\n"))
	builder.WriteString(fmt.Sprintf("Scan finished: %d hosts up, in %.2f seconds.\n\n", len(result.Hosts), result.Stats.Finished.Elapsed))

	for _, host := range result.Hosts {
		builder.WriteString(fmt.Sprintf("Host: %s (%s)\n", host.Addresses[0].Addr, host.Hostnames[0].Name))
		builder.WriteString("  Status: " + host.Status.State + "\n")

		if len(host.Ports) > 0 {
			builder.WriteString("  Open Ports:\n")
			for _, port := range host.Ports {
				builder.WriteString(fmt.Sprintf("    Port %d/%s - State: %s, Service: %s, Version: %s\n",
					port.ID, port.Protocol, port.State.State, port.Service.Name, port.Service.Product))
			}
		} else {
			builder.WriteString("  No open ports found.\n")
		}
		builder.WriteString("\n")
	}

	updateResult(builder.String())
}