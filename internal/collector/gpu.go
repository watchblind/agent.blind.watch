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

// nvidiaSMICandidates lists absolute paths to probe for nvidia-smi before
// falling back to a PATH lookup. Absolute paths are preferred to avoid
// PATH-based binary substitution; PATH is only consulted as a last resort.
var nvidiaSMICandidates = func() []string {
	if runtime.GOOS == "windows" {
		return []string{
			// Modern drivers (R450+) drop nvidia-smi in System32.
			`C:\Windows\System32\nvidia-smi.exe`,
			// Older / non-DCH drivers keep it under Program Files.
			`C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe`,
		}
	}
	return []string{
		"/usr/bin/nvidia-smi",
		"/usr/local/bin/nvidia-smi",
		// NixOS exposes system binaries here.
		"/run/current-system/sw/bin/nvidia-smi",
	}
}()

func findNvidiaSMI() string {
	for _, p := range nvidiaSMICandidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	bin := "nvidia-smi"
	if runtime.GOOS == "windows" {
		bin = "nvidia-smi.exe"
	}
	if p, err := exec.LookPath(bin); err == nil {
		return p
	}
	return ""
}

type GPUCollector struct {
	smiPath string
	checked bool
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
		c.smiPath = findNvidiaSMI()
	}
	if c.smiPath == "" {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, c.smiPath, "-q", "-x")
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
