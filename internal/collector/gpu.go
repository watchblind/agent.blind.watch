package collector

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// nvidiaSMIPath is the absolute path to nvidia-smi.
// Using an absolute path prevents PATH-based binary substitution.
var nvidiaSMIPath = func() string {
	if runtime.GOOS == "windows" {
		return `C:\Windows\System32\nvidia-smi.exe`
	}
	return "/usr/bin/nvidia-smi"
}()

type GPUCollector struct {
	available bool
	checked   bool
}

func NewGPUCollector() *GPUCollector {
	return &GPUCollector{}
}

func (c *GPUCollector) Name() string { return "gpu" }

type nvidiaSMILog struct {
	GPUs []nvGPU `xml:"gpu"`
}

type nvGPU struct {
	ID          string      `xml:"id,attr"`
	ProductName string      `xml:"product_name"`
	Utilization nvGPUUtil   `xml:"utilization"`
	FBMemory    nvFBMemory  `xml:"fb_memory_usage"`
	Temperature nvGPUTemp   `xml:"temperature"`
}

type nvGPUUtil struct {
	GPUUtil    string `xml:"gpu_util"`
	MemoryUtil string `xml:"memory_util"`
}

type nvFBMemory struct {
	Total string `xml:"total"`
	Used  string `xml:"used"`
	Free  string `xml:"free"`
}

type nvGPUTemp struct {
	GPUTemp string `xml:"gpu_temp"`
}

func (c *GPUCollector) Collect(ctx context.Context) ([]Metric, error) {
	if !c.checked {
		c.checked = true
		_, err := os.Stat(nvidiaSMIPath)
		c.available = err == nil
	}
	if !c.available {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, nvidiaSMIPath, "-q", "-x")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nvidia-smi: %w", err)
	}

	var log nvidiaSMILog
	if err := xml.Unmarshal(out, &log); err != nil {
		return nil, fmt.Errorf("parsing nvidia-smi xml: %w", err)
	}

	now := time.Now()
	var metrics []Metric

	for i, gpu := range log.GPUs {
		labels := map[string]string{
			"gpu":  fmt.Sprintf("%d", i),
			"name": gpu.ProductName,
		}

		if v, err := parseNvidiaPercent(gpu.Utilization.GPUUtil); err == nil {
			metrics = append(metrics, Metric{
				Name: "gpu_utilization_percent", Value: v, Labels: labels, Timestamp: now,
			})
		}
		if v, err := parseNvidiaPercent(gpu.Utilization.MemoryUtil); err == nil {
			metrics = append(metrics, Metric{
				Name: "gpu_memory_util_percent", Value: v, Labels: labels, Timestamp: now,
			})
		}
		if v, err := parseNvidiaMiB(gpu.FBMemory.Used); err == nil {
			metrics = append(metrics, Metric{
				Name: "gpu_memory_used_bytes", Value: v * 1024 * 1024, Labels: labels, Timestamp: now,
			})
		}
		if v, err := parseNvidiaMiB(gpu.FBMemory.Total); err == nil {
			metrics = append(metrics, Metric{
				Name: "gpu_memory_total_bytes", Value: v * 1024 * 1024, Labels: labels, Timestamp: now,
			})
		}
		if v, err := parseNvidiaTemp(gpu.Temperature.GPUTemp); err == nil {
			metrics = append(metrics, Metric{
				Name: "gpu_temperature_celsius", Value: v, Labels: labels, Timestamp: now,
			})
		}
	}

	return metrics, nil
}

func parseNvidiaPercent(s string) (float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " %")
	return strconv.ParseFloat(s, 64)
}

func parseNvidiaMiB(s string) (float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " MiB")
	return strconv.ParseFloat(s, 64)
}

func parseNvidiaTemp(s string) (float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " C")
	return strconv.ParseFloat(s, 64)
}
