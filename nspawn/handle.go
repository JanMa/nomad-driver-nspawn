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
		case <-ctx.Done():
			return

		case <-timer.C:
			timer.Reset(interval)
		}

		control, err := cgroups.Load(cgroups.Systemd, cgroups.Slice("machine.slice", h.machine.Unit))
		if err != nil {
			h.logger.Error("failed to get container cgroup", "error", err)
			return
		}
		stat, err := control.Stat()
		if err != nil {
			h.logger.Error("failed to get container cgroup stats", "error", err)
			return
		}

		t := time.Now()

		// Get the cpu stats
		system := stat.CPU.Usage.Kernel
		user := stat.CPU.Usage.User
		total := stat.CPU.Usage.Total
		cs := &drivers.CpuStats{
			SystemMode: h.systemCpuStats.Percent(float64(system)),
			UserMode:   h.systemCpuStats.Percent(float64(user)),
			Percent:    h.totalCpuStats.Percent(float64(total)),
			TotalTicks: float64(total),
			Measured:   NspawnMeasuredCpuStats,
		}

		// Get the Memory Stats
		memory := stat.Memory
		measured := NspawnMeasuredMemStats
		ms := &drivers.MemoryStats{
			RSS:   memory.RSS,
			Cache: memory.Cache,
		}

		if memory.Swap != nil {
			ms.Swap = memory.Swap.Usage
			measured = append(measured, "Swap")
		} else {
			h.logger.Error("failed to get swap usage", "error", err)
		}

		if memory.Usage != nil {
			ms.Usage = memory.Usage.Usage
			measured = append(measured, "Max Usage")
		} else {
			h.logger.Error("failed to get max memory usage", "error", err)
		}

		if memory.Kernel != nil {
			ms.KernelUsage = memory.Kernel.Usage
			ms.KernelMaxUsage = memory.Kernel.Max
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
