package nspawn

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/consul-template/signals"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/drivers/shared/executor"
	"github.com/hashicorp/nomad/helper/pluginutils/hclutils"
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
		"volumes": hclspec.NewDefault(
			hclspec.NewAttr("volumes", "bool", false),
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
		//TODO: Ensure we can handle containers without private networking?
		// "network_veth": hclspec.NewDefault(
		// 	hclspec.NewAttr("network_veth", "bool", false),
		// 	hclspec.NewLiteral("true"),
		// ),
		"process_two": hclspec.NewAttr("process_two", "bool", false),
		"read_only":   hclspec.NewAttr("read_only", "bool", false),
		"user_namespacing": hclspec.NewDefault(
			hclspec.NewAttr("user_namespacing", "bool", false),
			hclspec.NewLiteral("true"),
		),
		"command": hclspec.NewAttr("command", "list(string)", false),
		"console": hclspec.NewAttr("console", "string", false),
		"image":   hclspec.NewAttr("image", "string", true),
		"image_download": hclspec.NewBlock("image_download", false,
			hclspec.NewObject(map[string]*hclspec.Spec{
				"url": hclspec.NewAttr("url", "string", true),
				"type": hclspec.NewDefault(
					hclspec.NewAttr("type", "string", false),
					hclspec.NewLiteral(`"tar"`),
				),
				"force": hclspec.NewDefault(
					hclspec.NewAttr("force", "bool", false),
					hclspec.NewLiteral("false"),
				),
				"verify": hclspec.NewDefault(
					hclspec.NewAttr("verify", "string", false),
					hclspec.NewLiteral(`"no"`),
				),
			})),
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
		"capability":        hclspec.NewAttr("capability", "list(string)", false),
	})

	// capabilities is returned by the Capabilities RPC and indicates what
	// optional features this driver supports
	capabilities = &drivers.Capabilities{
		SendSignals: true,
		Exec:        true,
		FSIsolation: drivers.FSIsolationImage,
		NetIsolationModes: []drivers.NetIsolationMode{
			drivers.NetIsolationModeHost,
			drivers.NetIsolationModeGroup,
		},
		MountConfigs: drivers.MountConfigSupportAll,
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
	Volumes bool `codec:"volumes"`
}

// TaskState is the state which is encoded in the handle returned in
// StartTask. This information is needed to rebuild the task state and handler
// during recovery.
type TaskState struct {
	ReattachConfig *pstructs.ReattachConfig
	TaskConfig     *drivers.TaskConfig
	MachineName    string
	StartedAt      time.Time
}

// NewNspawnDriver returns a new nspawn driver object
func NewNspawnDriver(logger hclog.Logger) drivers.DriverPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	logger = logger.Named(pluginName)
	return &Driver{
		eventer: eventer.NewEventer(ctx, logger),
		config: &Config{
			Enabled: true,
			Volumes: true,
		},
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
		attrs["driver.nspawn.volumes"] = pstructs.NewBoolAttribute(d.config.Volumes)
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
	d.logger.Debug("RecoverTask called")
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

	var driverConfig drivers.TaskConfig
	if err := taskState.TaskConfig.DecodeDriverConfig(&driverConfig); err != nil {
		return fmt.Errorf("failed to decode driver config: %v", err)
	}

	plugRC, err := pstructs.ReattachConfigToGoPlugin(taskState.ReattachConfig)
	if err != nil {
		return fmt.Errorf("failed to build ReattachConfig from taskConfig state: %v", err)
	}

	execImpl, pluginClient, err := executor.ReattachToExecutor(plugRC, d.logger)
	if err != nil {
		return fmt.Errorf("failed to reattach to executor: %v", err)
	}

	p, e := DescribeMachine(taskState.MachineName, machinePropertiesTimeout)
	if e != nil {
		d.logger.Error("failed to get machine information", "error", e)
		return e
	}

	h := &taskHandle{
		machine: p,
		logger:  d.logger,

		exec:         execImpl,
		pluginClient: pluginClient,
		taskConfig:   taskState.TaskConfig,
		procState:    drivers.TaskStateRunning,
		startedAt:    taskState.StartedAt,
	}

	d.tasks.Set(taskState.TaskConfig.ID, h)

	go h.run()

	return nil
}

func (d *Driver) StartTask(cfg *drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	d.logger.Debug("StartTask called")
	if _, ok := d.tasks.Get(cfg.ID); ok {
		return nil, nil, fmt.Errorf("task with ID %q already started", cfg.ID)
	}

	var driverConfig MachineConfig
	if err := cfg.DecodeDriverConfig(&driverConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to decode driver config: %v", err)
	}

	handle := drivers.NewTaskHandle(taskHandleVersion)
	handle.Config = cfg

	driverConfig.Machine = cfg.Name + "-" + cfg.AllocID
	driverConfig.Port = make(map[string]string)
	//TODO: Ensure we can handle containers without private networking?
	if cfg.NetworkIsolation == nil {
		driverConfig.NetworkVeth = true
	} else {
		driverConfig.NetworkNamespace = cfg.NetworkIsolation.Path
		driverConfig.UserNamespacing = false
	}
	// pass predefined environment vars
	if driverConfig.Environment == nil {
		driverConfig.Environment = make(hclutils.MapStrStr)
	}
	for k, v := range cfg.Env {
		driverConfig.Environment[k] = v
	}

	// bind Task Directories into container
	taskDirs := cfg.TaskDir()
	if driverConfig.Bind == nil {
		driverConfig.Bind = make(hclutils.MapStrStr)
	}
	driverConfig.Bind[taskDirs.SharedAllocDir] = cfg.Env["NOMAD_ALLOC_DIR"]
	driverConfig.Bind[taskDirs.LocalDir] = cfg.Env["NOMAD_TASK_DIR"]
	driverConfig.Bind[taskDirs.SecretsDir] = cfg.Env["NOMAD_SECRETS_DIR"]

	//bind volumes into container
	if cfg.Mounts != nil && len(cfg.Mounts) > 0 {
		if !d.config.Volumes {
			d.logger.Error("volumes are not enabled; cannot mount host paths")
			return nil, nil, fmt.Errorf("volumes are not enabled; cannot mount host paths")
		}
		if driverConfig.BindReadOnly == nil {
			driverConfig.BindReadOnly = make(hclutils.MapStrStr)
		}
		for _, m := range cfg.Mounts {
			if m.Readonly {
				driverConfig.BindReadOnly[m.HostPath] = m.TaskPath
			} else {
				driverConfig.Bind[m.HostPath] = m.TaskPath
			}
		}
	}

	if driverConfig.Properties == nil {
		driverConfig.Properties = make(hclutils.MapStrStr)
	}
	driverConfig.Properties["MemoryMax"] = strconv.Itoa(int(cfg.Resources.LinuxResources.MemoryLimitBytes))

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

	// Validate config
	if err := driverConfig.Validate(); err != nil {
		return nil, nil, fmt.Errorf("failed to validate task config: %v", err)
	}

	// Download image
	if driverConfig.ImageDownload != nil {
		d.eventer.EmitEvent(&drivers.TaskEvent{
			TaskID:    cfg.ID,
			AllocID:   cfg.AllocID,
			TaskName:  cfg.Name,
			Timestamp: time.Now(),
			Message:   "Downloading image",
			Annotations: map[string]string{
				"image": driverConfig.Image,
				"url":   driverConfig.ImageDownload.URL,
			},
		})
		err := DownloadImage(driverConfig.ImageDownload.URL,
			driverConfig.Image, driverConfig.ImageDownload.Verify,
			driverConfig.ImageDownload.Type,
			driverConfig.ImageDownload.Force, d.logger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to download image: %v", err)
		}
	}

	// Gather image path
	imagePath, err := driverConfig.GetImagePath()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to gather image path: %v", err)
	}

	driverConfig.imagePath = imagePath

	// Get nspawn arguments
	args, err := driverConfig.ConfigArray()
	if err != nil {
		d.logger.Error("Error generating machine config", "error", err)
		return nil, nil, err
	}

	d.logger.Info("starting nspawn task", "driver_cfg", hclog.Fmt("%+v", driverConfig))
	d.logger.Debug("resources", "nomad", fmt.Sprintf("%+v", cfg.Resources.NomadResources), "linux", fmt.Sprintf("%+v", cfg.Resources.LinuxResources))
	d.logger.Info("commad arguments", "args", args)

	executorConfig := &executor.ExecutorConfig{
		LogFile:  filepath.Join(cfg.TaskDir().Dir, "executor.out"),
		LogLevel: "debug",
	}

	exec, pluginClient, err := executor.CreateExecutor(d.logger, d.nomadConfig, executorConfig)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create executor: %v", err)
	}

	execCmd := &executor.ExecCommand{
		Cmd:        "systemd-nspawn",
		Args:       args,
		StdoutPath: cfg.StdoutPath,
		StderrPath: cfg.StderrPath,
		Resources:  cfg.Resources,
	}

	ps, err := exec.Launch(execCmd)
	if err != nil {
		pluginClient.Kill()
		return nil, nil, fmt.Errorf("failed to launch command with executor: %v", err)
	}

	printErr := func() {
		logDir := cfg.TaskDir().LogDir
		logs, err := filepath.Glob(filepath.Join(logDir, cfg.Name+"*"))
		if err != nil {
			d.logger.Error("error finding log files", err)
			return
		}

		for _, l := range logs {
			out, err := ioutil.ReadFile(l)
			if err != nil {
				continue
			}
			lines := strings.Split(strings.Trim(string(out), "\n"), "\n")
			// Continue if there's no output
			if len(lines) == 0 || len(lines[len(lines)-1]) == 0 {
				continue
			}
			d.logger.Error("systemd-nspawn failed", "file", filepath.Base(l), "out", lines[len(lines)-1])
			d.eventer.EmitEvent(&drivers.TaskEvent{
				TaskID:    cfg.ID,
				AllocID:   cfg.AllocID,
				TaskName:  cfg.Name,
				Timestamp: time.Now(),
				Message:   lines[len(lines)-1],
				Err:       fmt.Errorf("Systemd-Nspawn failed"),
			})
		}
	}

	p, err := DescribeMachine(driverConfig.Machine, machinePropertiesTimeout)
	if err != nil {
		d.logger.Error("failed to get machine information", "error", err)
		if ps.ExitCode != 0 {
			printErr()
			err = fmt.Errorf("systemd-nspawn failed to start task")
		}
		if !pluginClient.Exited() {
			if err := exec.Shutdown("", 0); err != nil {
				d.logger.Error("destroying executor failed", "err", err)
			}

			pluginClient.Kill()
		}
		return nil, nil, err
	}
	d.logger.Debug("gathered information about new machine", "name", p.Name, "leader", p.Leader)

	addr, err := MachineAddresses(driverConfig.Machine, machineAddressTimeout)
	if err != nil {
		d.logger.Error("failed to get machine addresses", "error", err, "addresses", addr)
		if ps.ExitCode != 0 {
			printErr()
			err = fmt.Errorf("systemd-nspawn failed to start task")
		}
		if !pluginClient.Exited() {
			if err := exec.Shutdown("", 0); err != nil {
				d.logger.Error("destroying executor failed", "err", err)
			}

			pluginClient.Kill()
		}
		return nil, nil, err
	}

	d.logger.Debug("gathered address of new machine", "name", p.Name, "ip", addr.IPv4.String())
	network := &drivers.DriverNetwork{
		PortMap:       driverConfig.PortMap,
		IP:            addr.IPv4.String(),
		AutoAdvertise: false,
	}

	if cfg.NetworkIsolation == nil {
		err = p.ConfigureIPTablesRules(false)
		if err != nil {
			d.logger.Error("Failed to set up IPTables rules", "error", err)
		}
	}

	h := &taskHandle{
		machine: p,
		logger:  d.logger,

		exec:         exec,
		pluginClient: pluginClient,
		taskConfig:   cfg,
		procState:    drivers.TaskStateRunning,
		startedAt:    time.Now().Round(time.Millisecond),
	}

	driverState := TaskState{
		ReattachConfig: pstructs.ReattachConfigFromGoPlugin(pluginClient.ReattachConfig()),
		MachineName:    driverConfig.Machine,
		TaskConfig:     cfg,
		StartedAt:      h.startedAt,
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
	d.logger.Debug("WaitTask called")
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
	var result *drivers.ExitResult

	ps, err := handle.exec.Wait(ctx)
	if err != nil {
		result = &drivers.ExitResult{
			Err: fmt.Errorf("executor: error waiting on process: %v", err),
		}
	} else {
		result = &drivers.ExitResult{
			ExitCode: ps.ExitCode,
			Signal:   ps.Signal,
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.ctx.Done():
			return
		case ch <- result:
		}
	}
}

func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	d.logger.Debug("StopTask called")
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if handle.taskConfig.NetworkIsolation == nil {
		if err := handle.machine.ConfigureIPTablesRules(true); err != nil {
			d.logger.Error("StopTask: Failed to remove IPTables rules", "error", err)
		}
	}

	if err := handle.exec.Shutdown(signal, timeout); err != nil {
		if handle.pluginClient.Exited() {
			return nil
		}
		return fmt.Errorf("StopTask: executor Shutdown failed: %v", err)
	}

	return nil
}

func (d *Driver) DestroyTask(taskID string, force bool) error {
	d.logger.Debug("DestroyTask called")
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if handle.IsRunning() && !force {
		return fmt.Errorf("cannot destroy running task")
	}

	if !handle.pluginClient.Exited() {
		handle.pluginClient.Kill()
	}

	d.tasks.Delete(taskID)
	return nil
}

func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	d.logger.Debug("InspectTask called")
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

	return handle.exec.Stats(ctx, interval)
}

func (d *Driver) TaskEvents(ctx context.Context) (<-chan *drivers.TaskEvent, error) {
	return d.eventer.TaskEvents(ctx)
}

func (d *Driver) SignalTask(taskID string, signal string) error {
	d.logger.Debug("SignalTask called")
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}
	sig := os.Interrupt
	if s, ok := signals.SignalLookup[signal]; ok {
		sig = s
	} else {
		d.logger.Warn("unknown signal to send to task, using SIGINT instead", "signal", signal, "task_id", handle.taskConfig.ID)

	}
	return handle.exec.Signal(sig)
}

// var _ drivers.ExecTaskStreamingDriver = (*Driver)(nil)
var _ drivers.ExecTaskStreamingRawDriver = (*Driver)(nil)

func (d *Driver) ExecTaskStreamingRaw(ctx context.Context,
	taskID string,
	command []string,
	tty bool,
	stream drivers.ExecTaskStream) error {

	if len(command) == 0 {
		return fmt.Errorf("error cmd must have at least one value")
	}
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return drivers.ErrTaskNotFound
	}

	if err := execSupported(handle); err != nil {
		return err
	}

	cmd := []string{"systemd-run", "--wait", "--service-type=exec",
		"--collect", "--quiet", "--machine", handle.machine.Name}
	if tty {
		cmd = append(cmd, "--pty", "--send-sighup")
	} else {
		cmd = append(cmd, "--pipe")
	}
	cmd = append(cmd, command...)

	return handle.exec.ExecStreaming(ctx, cmd, tty, stream)
}

func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	if len(cmd) == 0 {
		return nil, fmt.Errorf("error cmd must have at least one value")
	}
	handle, ok := d.tasks.Get(taskID)
	if !ok {
		return nil, drivers.ErrTaskNotFound
	}

	if err := execSupported(handle); err != nil {
		return nil, err
	}

	command := []string{"systemd-run", "--wait", "--service-type=exec",
		"--collect", "--quiet", "--machine", handle.machine.Name, "--pipe"}
	command = append(command, cmd...)

	out, exitCode, err := handle.exec.Exec(time.Now().Add(timeout), command[0], command[1:])
	if err != nil {
		return nil, err
	}

	return &drivers.ExecTaskResult{
		Stdout: out,
		ExitResult: &drivers.ExitResult{
			ExitCode: exitCode,
		},
	}, nil
}

// execSupported checks if container was stared with boot parameter, otherwise
// systemd-run does not work
func execSupported(handle *taskHandle) error {
	var driverConfig MachineConfig
	if err := handle.taskConfig.DecodeDriverConfig(&driverConfig); err != nil {
		return fmt.Errorf("failed to decode driver config: %v", err)
	}
	if !driverConfig.Boot {
		return fmt.Errorf("cannot exec command in task started without boot parameter")
	}
	return nil
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
