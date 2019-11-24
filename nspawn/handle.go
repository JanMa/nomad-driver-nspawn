package nspawn

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/containerd/cgroups"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/stats"
	"github.com/hashicorp/nomad/plugins/drivers"
)

var (
	NspawnMeasuredCpuStats = []string{"System Mode", "User Mode", "Percent"}

	NspawnMeasuredMemStats = []string{"RSS", "Cache"}
)

type taskHandle struct {
	machine *MachineProps
	logger  hclog.Logger

	totalCpuStats  *stats.CpuStats
	userCpuStats   *stats.CpuStats
	systemCpuStats *stats.CpuStats

	// stateLock syncs access to all fields below
	stateLock sync.RWMutex

	cgroup      cgroups.Cgroup
	taskConfig  *drivers.TaskConfig
	procState   drivers.TaskState
	startedAt   time.Time
	completedAt time.Time
	exitResult  *drivers.ExitResult
}

func (h *taskHandle) TaskStatus() *drivers.TaskStatus {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()

	return &drivers.TaskStatus{
		ID:          h.taskConfig.ID,
		Name:        h.taskConfig.Name,
		State:       h.procState,
		StartedAt:   h.startedAt,
		CompletedAt: h.completedAt,
		ExitResult:  h.exitResult,
		DriverAttributes: map[string]string{
			"pid": strconv.FormatUint(uint64(h.machine.Leader), 10),
		},
	}
}

func (h *taskHandle) IsRunning() bool {
	h.stateLock.RLock()
	defer h.stateLock.RUnlock()
	return h.procState == drivers.TaskStateRunning
}

func (h *taskHandle) run() {
	h.stateLock.Lock()
	if h.exitResult == nil {
		h.exitResult = &drivers.ExitResult{}
	}
	h.stateLock.Unlock()

	if ok, err := waitTillStopped(h.machine); !ok {
		h.logger.Error("failed to find container process", "error", err)
		return
	}

	h.stateLock.Lock()
	defer h.stateLock.Unlock()

	h.procState = drivers.TaskStateExited
	h.exitResult.ExitCode = 0
	h.exitResult.Signal = 0
	h.completedAt = time.Now()
	h.logger.Debug("run() exited successful")

	// TODO: detect if the task OOMed
}

func (h *taskHandle) stats(ctx context.Context, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	ch := make(chan *drivers.TaskResourceUsage)
	go h.handleStats(ctx, ch, interval)
	return ch, nil
}

func (h *taskHandle) handleStats(ctx context.Context, ch chan *drivers.TaskResourceUsage, interval time.Duration) {
	defer close(ch)
	timer := time.NewTimer(0)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-ctx.Done():
			return

		case <-timer.C:
			timer.Reset(interval)
		}

		h.stateLock.RLock()
		state := h.cgroup.State()
		h.stateLock.RUnlock()
		if state == cgroups.Deleted {
			return
		}

		h.stateLock.RLock()
		t := time.Now()
		stat, err := h.cgroup.Stat()
		h.stateLock.RUnlock()
		if err != nil {
			h.logger.Error("failed to get container cgroup stats", "error", err)
			return
		}

		// Get the cpu stats
		system := stat.CPU.Usage.Kernel
		user := stat.CPU.Usage.User
		total := stat.CPU.Usage.Total
		totalPercent := h.totalCpuStats.Percent(float64(total))
		cs := &drivers.CpuStats{
			SystemMode: h.systemCpuStats.Percent(float64(system)),
			UserMode:   h.userCpuStats.Percent(float64(user)),
			Percent:    totalPercent,
			TotalTicks: h.totalCpuStats.TicksConsumed(totalPercent),
			Measured:   NspawnMeasuredCpuStats,
		}
		h.logger.Debug("systemCpuStats", "percent", cs.SystemMode)
		h.logger.Debug("userCpuStats", "percent", cs.UserMode)
		h.logger.Debug("totalCpuStats", "percent", cs.Percent)
		h.logger.Debug("total", "percent", cs.TotalTicks)

		// Get the Memory Stats
		memory := stat.Memory
		measured := NspawnMeasuredMemStats
		ms := &drivers.MemoryStats{
			RSS:   memory.RSS,
			Cache: memory.Cache,
		}

		h.logger.Debug("memory", "rss", ms.RSS)
		h.logger.Debug("memory", "cache", ms.Cache)

		if memory.Swap != nil {
			ms.Swap = memory.Swap.Usage
			h.logger.Debug("memory", "swap", ms.Swap)
			measured = append(measured, "Swap")
		} else {
			h.logger.Error("failed to get swap usage", "error", err)
		}

		if memory.Usage != nil {
			ms.Usage = memory.Usage.Usage
			h.logger.Debug("memory", "usage", ms.Usage)
			ms.MaxUsage = memory.Usage.Max
			h.logger.Debug("memory", "max-usage", ms.Usage)
			measured = append(measured, "Usage", "Max Usage")
		} else {
			h.logger.Error("failed to get max memory usage", "error", err)
		}

		if memory.Kernel != nil {
			ms.KernelUsage = memory.Kernel.Usage
			ms.KernelMaxUsage = memory.Kernel.Max
			h.logger.Debug("memory", "kernel-usage", ms.KernelUsage)
			h.logger.Debug("memory", "kernel-max", ms.KernelMaxUsage)
			measured = append(measured, "Kernel Usage", "Kernel Max Usage")
		} else {
			h.logger.Error("failed to get kernel memory usage", "error", err)
		}

		ms.Measured = measured

		taskResUsage := drivers.TaskResourceUsage{
			ResourceUsage: &drivers.ResourceUsage{
				CpuStats:    cs,
				MemoryStats: ms,
			},
			Timestamp: t.UTC().UnixNano(),
		}
		select {
		case <-ctx.Done():
			return
		case ch <- &taskResUsage:
		}
	}
}

func (h *taskHandle) shutdown(timeout time.Duration) error {
	return shutdown(h.machine.Name, timeout, h.logger)
}
