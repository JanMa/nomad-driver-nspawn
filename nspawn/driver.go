package nspawn

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/client/lib/fifo"
	"github.com/hashicorp/nomad/client/stats"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	driversUtil "github.com/hashicorp/nomad/plugins/drivers/utils"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	pstructs "github.com/hashicorp/nomad/plugins/shared/structs"
)

const (
	// pluginName is the name of the plugin
	pluginName = "nspawn"

	// fingerprintPeriod is the interval at which the driver will send fingerprint responses
	fingerprintPeriod = 30 * time.Second

	// taskHandleVersion is the version of task handle which this driver sets
	// and understands how to decode driver state
	taskHandleVersion = 1

	// startup timeouts
	machinePropertiesTimeout = 30 * time.Second
	machineAddressTimeout    = 30 * time.Second
)

var (
	// pluginInfo is the response returned for the PluginInfo RPC
	pluginInfo = &base.PluginInfoResponse{
		Type:              base.PluginTypeDriver,
		PluginApiVersions: []string{drivers.ApiVersion010},
		PluginVersion:     "0.0.1",
		Name:              pluginName,
	}

	// configSpec is the hcl specification returned by the ConfigSchema RPC
	configSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"enabled": hclspec.NewDefault(
			hclspec.NewAttr("enabled", "bool", false),
			hclspec.NewLiteral("true"),
		),
	})

	// taskConfigSpec is the hcl specification for the driver config section of
	// a task within a job. It is returned in the TaskConfigSchema RPC
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"boot": hclspec.NewDefault(
			hclspec.NewAttr("boot", "bool", false),
			hclspec.NewLiteral("true"),
		),
		"ephemeral": hclspec.NewAttr("ephemeral", "bool", false),
		"network_veth": hclspec.NewDefault(
			hclspec.NewAttr("network_veth", "bool", false),
			hclspec.NewLiteral("true"),
		),
		"process_two": hclspec.NewAttr("process_two", "bool", false),
		"read_only":   hclspec.NewAttr("read_only", "bool", false),
		"user_namespacing": hclspec.NewDefault(
			hclspec.NewAttr("user_namespacing", "bool", false),
			hclspec.NewLiteral("true"),
		),
		"command": hclspec.NewAttr("command", "list(string)", false),
		"console": hclspec.NewAttr("console", "string", false),
		"image":   hclspec.NewAttr("image", "string", true),
		// "machine":           hclspec.NewAttr("machine", "string", false),
		"pivot_root":        hclspec.NewAttr("pivot_root", "string", false),
		"resolv_conf":       hclspec.NewAttr("resolv_conf", "string", false),
		"user":              hclspec.NewAttr("user", "string", false),
		"volatile":          hclspec.NewAttr("volatile", "string", false),
		"working_directory": hclspec.NewAttr("working_directory", "string", false),
		"bind":              hclspec.NewAttr("bind", "list(map(string))", false),
		"bind_read_only":    hclspec.NewAttr("bind_read_only", "list(map(string))", false),
		"environment":       hclspec.NewAttr("environment", "list(map(string))", false),
		"port_map":          hclspec.NewAttr("port_map", "list(map(number))", false),
	})

	// capabilities is returned by the Capabilities RPC and indicates what
	// optional features this driver supports
	capabilities = &drivers.Capabilities{
		SendSignals: false,
		Exec:        false,
		FSIsolation: drivers.FSIsolationImage,
	}
)

// Driver is a driver for running nspawn containers
type Driver struct {
	// eventer is used to handle multiplexing of TaskEvents calls such that an
	// event can be broadcast to all callers
	eventer *eventer.Eventer

	// config is the driver configuration set by the SetConfig RPC
	config *Config

	// nomadConfig is the client config from nomad
	nomadConfig *base.ClientDriverConfig

	// tasks is the in memory datastore mapping taskIDs to rawExecDriverHandles
	tasks *taskStore

	// ctx is the context for the driver. It is passed to other subsystems to
	// coordinate shutdown
	ctx context.Context

	// signalShutdown is called when the driver is shutting down and cancels the
	// ctx passed to any subsystems
	signalShutdown context.CancelFunc

	// logger will log to the Nomad agent
	logger hclog.Logger
}

// Config is the driver configuration set by the SetConfig RPC call
type Config struct {
	// Enabled is set to true to enable the nspawn driver
	Enabled bool `codec:"enabled"`
}

// TaskState is the state which is encoded in the handle returned in
// StartTask. This information is needed to rebuild the task state and handler
// during recovery.
type TaskState struct {
	TaskConfig  *drivers.TaskConfig
	MachineName string
	StartedAt   time.Time
}

// NewNspawnDriver returns a new nspawn driver object
func NewNspawnDriver(logger hclog.Logger) drivers.DriverPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named(pluginName)
	return &Driver{
		eventer:        eventer.NewEventer(ctx, logger),
		config:         &Config{},
		tasks:          newTaskStore(),
		ctx:            ctx,
		signalShutdown: cancel,
		logger:         logger,
	}
}

func (d *Driver) TaskConfigSchema() (*hclspec.Spec, error) {
	return taskConfigSpec, nil
}
func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return capabilities, nil
}

func (d *Driver) Fingerprint(ctx context.Context) (<-chan *drivers.Fingerprint, error) {
	ch := make(chan *drivers.Fingerprint)
	go d.handleFingerprint(ctx, ch)
	return ch, nil
}

func (d *Driver) handleFingerprint(ctx context.Context, ch chan<- *drivers.Fingerprint) {
	defer close(ch)
	ticker := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			ticker.Reset(fingerprintPeriod)
			ch <- d.buildFingerprint()
		}
	}
}

func (d *Driver) buildFingerprint() *drivers.Fingerprint {
	var health drivers.HealthState
	var desc string
	attrs := map[string]*pstructs.Attribute{}

	err := isInstalled()
	version, vErr := systemdVersion()

	if d.config.Enabled && err == nil && vErr == nil &&
		driversUtil.IsUnixRoot() {
		health = drivers.HealthStateHealthy
		desc = "ready"
		attrs["driver.nspawn"] = pstructs.NewBoolAttribute(true)
		attrs["driver.nspawn.version"] = pstructs.NewStringAttribute(version)
	} else {
		health = drivers.HealthStateUndetected
		desc = "disabled"
	}

	return &drivers.Fingerprint{
		Attributes:        attrs,
		Health:            health,
		HealthDescription: desc,
	}
}

func (d *Driver) RecoverTask(handle *drivers.TaskHandle) error {
	if handle == nil {
		return fmt.Errorf("error: handle cannot be nil")
	}

	if _, ok := d.tasks.Get(handle.Config.ID); ok {
		return nil
	}

	var taskState TaskState
	if err := handle.GetDriverState(&taskState); err != nil {
		return fmt.Errorf("failed to decode task state from handle: %v", err)
	}

	p, e := DescribeMachine(taskState.TaskConfig.AllocID, machinePropertiesTimeout)
	if e != nil {
		d.logger.Error("failed to get machine information", "error", e)
		return e
	}
	control, err := cgroups.Load(cgroups.Systemd, cgroups.Slice("machine.slice", p.Unit))
	if err != nil {
		d.logger.Error("failed to get container cgroup", "error", err)
		return err
	}

	h := &taskHandle{
		machine: p,
		logger:  d.logger,

		totalCpuStats:  stats.NewCpuStats(),
		userCpuStats:   stats.NewCpuStats(),
		systemCpuStats: stats.NewCpuStats(),

		cgroup:     control,
		taskConfig: taskState.TaskConfig,
		procState:  drivers.TaskStateRunning,
		startedAt:  taskState.StartedAt,
	}

	d.tasks.Set(taskState.TaskConfig.ID, h)

	go h.run()

	return nil
}

func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	var driverConfig MachineConfig
	if err := cfg.DecodeDriverConfig(&driverConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config: %v", err)
	}

	d.logger.Info("starting nspawn task", "driver_cfg", hclog.Fmt("%+v", driverConfig))
	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	driverConfig.Machine = cfg.AllocID
	driverConfig.Port = make(map[string]string)

	// Setup port mapping and exposed ports
	if len(cfg.Resources.NomadResources.Networks) == 0 {
		d.logger.Debug("no network interfaces are available")
		if len(driverConfig.PortMap) > 0 {
			d.logger.Error("Trying to map ports but no network interface is available")
		}
	} else {
		network := cfg.Resources.NomadResources.Networks[0]
		for _, port := range network.ReservedPorts {
			// By default we will map the allocated port 1:1 to the container
			machinePort := port.Value

			// If the user has mapped a port using port_map we'll change it here
			if mapped, ok := driverConfig.PortMap[port.Label]; ok {
				machinePort = mapped
			}

			hostPort := port.Value
			driverConfig.Port[port.Label] = fmt.Sprintf("%d:%d", hostPort, machinePort)

			d.logger.Debug("allocated static port", "ip", network.IP, "port", hostPort)
			d.logger.Debug("exposed port", "port", machinePort)
		}

		for _, port := range network.DynamicPorts {
			// By default we will map the allocated port 1:1 to the container
			machinePort := port.Value

			// If the user has mapped a port using port_map we'll change it here
			if mapped, ok := driverConfig.PortMap[port.Label]; ok {
				machinePort = mapped
			}

			hostPort := port.Value
			driverConfig.Port[port.Label] = fmt.Sprintf("%d:%d", hostPort, machinePort)

			d.logger.Debug("allocated mapped port", "ip", network.IP, "port", hostPort)
			d.logger.Debug("exposed port", "port", machinePort)
		}

	}

	args, err := driverConfig.ConfigArray()
	if err != nil {
		d.logger.Error("Error generating machine config", "error", err)
		return nil, nil, err
	}

	d.logger.Info("commad arguments", "args", args)

	cmd := exec.Command("systemd-nspawn", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	var stdout io.WriteCloser
	var stderr io.WriteCloser

	if cfg.StdoutPath != "" {
		f, err := fifo.OpenWriter(cfg.StdoutPath)
		if err != nil {
			d.logger.Error("failed to create stdout", "error", err)
		}
		stdout = f
	}

	if stdout != nil {
		cmd.Stdout = stdout
	}

	if cfg.StderrPath != "" {
		f, err := fifo.OpenWriter(cfg.StderrPath)
		if err != nil {
			d.logger.Error("failed to create stderr", "error", err)
		}
		stderr = f
	}

	if stderr != nil {
		cmd.Stderr = stderr
	}

	err = cmd.Start()
	defer cmd.Process.Release()
	if err != nil {
		d.logger.Error("failed to start task, error starting container", "error", err)
		return nil, nil, fmt.Errorf("failed to start task: %v", err)
	}

	// wait for boot
	p, e := DescribeMachine(cfg.AllocID, machinePropertiesTimeout)
	if e != nil {
		d.logger.Error("failed to get machine information", "error", e)
		return nil, nil, e
	}
	d.logger.Debug("gathered information about new machine", "name", p.Name, "leader", p.Leader)

	addr, err := MachineAddresses(cfg.AllocID, machineAddressTimeout)
	if err != nil {
		d.logger.Error("failed to get machine addresses", "error", e)
	}

	d.logger.Debug("gathered address of new machine", "name", p.Name, "ip", addr.IPv4.String())
	network := &drivers.DriverNetwork{
		PortMap:       driverConfig.PortMap,
		IP:            addr.IPv4.String(),
		AutoAdvertise: false,
	}

	control, err := cgroups.Load(cgroups.Systemd, cgroups.Slice("machine.slice", p.Unit))
	if err != nil {
		d.logger.Error("failed to get container cgroup", "error", err)
		return nil, nil, err
	}

	err = p.ConfigureIPTablesRules(false)
	if err != nil {
		d.logger.Error("Failed to set up IPTables rules", "error", err)
	}

	h := &taskHandle{
		machine: p,
		logger:  d.logger,

		totalCpuStats:  stats.NewCpuStats(),
		userCpuStats:   stats.NewCpuStats(),
		systemCpuStats: stats.NewCpuStats(),

		cgroup:     control,
		taskConfig: cfg,
		procState:  drivers.TaskStateRunning,
		startedAt:  time.Unix(int64(p.Timestamp)/1000000, 0),
	}

	driverState := TaskState{
		MachineName: cfg.AllocID,
		TaskConfig:  cfg,
		StartedAt:   h.startedAt,
	}

	if err := handle.SetDriverState(&driverState); err != nil {
		d.logger.Error("failed to start task, error setting driver state", "error", err)
		return nil, nil, fmt.Errorf("failed to set driver state: %v", err)
	}

	d.tasks.Set(cfg.ID, h)

	go h.run()

	return handle, network, nil
}

func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	ch := make(chan *drivers.ExitResult)
	go d.handleWait(ctx, handle, ch)

	return ch, nil
}

func (d *Driver) handleWait(ctx context.Context, handle *taskHandle, ch chan *drivers.ExitResult) {
	defer close(ch)

	//
	// Wait for process completion by polling status from handler.
	// We cannot use the following alternatives:
	//   * Process.Wait() requires LXC container processes to be children
	//     of self process; but LXC runs container in separate PID hierarchy
	//     owned by PID 1.
	//   * lxc.Container.Wait() holds a write lock on container and prevents
	//     any other calls, including stats.
	//
	// Going with simplest approach of polling for handler to mark exit.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			s := handle.TaskStatus()
			if s.State == drivers.TaskStateExited {
				ch <- handle.exitResult
			}
		}
	}
}

func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if err := handle.shutdown(timeout); err != nil {
		return fmt.Errorf("executor shutdown failed: %v", err)
	}

	err := handle.machine.ConfigureIPTablesRules(true)
	if err != nil {
		d.logger.Error("Failed to remove IPTables rules", "error", err)
	}

	return nil
}

func (d *Driver) DestroyTask(taskID string, force bool) error {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if handle.IsRunning() && !force {
		return fmt.Errorf("cannot destroy running task")
	}

	if handle.IsRunning() {
		// grace period is chosen arbitrary here
		if err := handle.shutdown(1 * time.Minute); err != nil {
			handle.logger.Error("failed to destroy executor", "err", err)
		}
	}

	d.tasks.Delete(taskID)
	return nil
}

func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	return handle.TaskStatus(), nil
}

func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *drivers.TaskResourceUsage, error) {
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	return handle.stats(ctx, interval)
}

func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

func (d *Driver) SignalTask(taskID string, signal string) error {
	return fmt.Errorf("Nspawn driver does not support signals")
}

func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	return nil, fmt.Errorf("Nspawn driver does not support exec")
}

func (d *Driver) PluginInfo() (*base.PluginInfoResponse, error) {
	return pluginInfo, nil
}

func (d *Driver) ConfigSchema() (*hclspec.Spec, error) {
	return configSpec, nil
}

func (d *Driver) SetConfig(cfg *base.Config) error {
	var config Config
	if len(cfg.PluginConfig) != 0 {
		if err := base.MsgPackDecode(cfg.PluginConfig, &config); err != nil {
			return err
		}
	}

	d.config = &config
	if cfg.AgentConfig != nil {
		d.nomadConfig = cfg.AgentConfig.Driver
	}

	return nil
}

func (d *Driver) Shutdown(ctx context.Context) error {
	d.signalShutdown()
	return nil
}
