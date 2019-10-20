package nspawn

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	// "github.com/hashicorp/nomad/client/stats"
	systemdDbus "github.com/coreos/go-systemd/dbus"
	// machined "github.com/coreos/go-systemd/machine1"
	systemdUtil "github.com/coreos/go-systemd/util"
	// "github.com/godbus/dbus"
	cstructs "github.com/hashicorp/nomad/client/structs"
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
		// "volumes_enabled": hclspec.NewDefault(
		// 	hclspec.NewAttr("volumes_enabled", "bool", false),
		// 	hclspec.NewLiteral("true"),
		// ),
		// "lxc_path": hclspec.NewAttr("lxc_path", "string", false),
	})

	// taskConfigSpec is the hcl specification for the driver config section of
	// a task within a job. It is returned in the TaskConfigSchema RPC
	taskConfigSpec = hclspec.NewObject(map[string]*hclspec.Spec{
		"image": hclspec.NewAttr("image", "string", true),
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

func (d *Driver) RecoverTask(*drivers.TaskHandle) error {
	return nil
}
func (d *Driver) StartTask(*drivers.TaskConfig) (*drivers.TaskHandle, *drivers.DriverNetwork, error) {
	return nil, nil, nil
}
func (d *Driver) WaitTask(ctx context.Context, taskID string) (<-chan *drivers.ExitResult, error) {
	return nil, nil
}
func (d *Driver) StopTask(taskID string, timeout time.Duration, signal string) error {
	return nil
}
func (d *Driver) DestroyTask(taskID string, force bool) error {
	return nil
}
func (d *Driver) InspectTask(taskID string) (*drivers.TaskStatus, error) {
	return nil, nil
}
func (d *Driver) TaskStats(ctx context.Context, taskID string, interval time.Duration) (<-chan *cstructs.TaskResourceUsage, error) {
	return nil, nil
}
func (d *Driver) TaskEvents(context.Context) (<-chan *drivers.TaskEvent, error) {
	return nil, nil
}
func (d *Driver) SignalTask(taskID string, signal string) error {
	return nil
}
func (d *Driver) ExecTask(taskID string, cmd []string, timeout time.Duration) (*drivers.ExecTaskResult, error) {
	return nil, nil
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

func isInstalled() error {
	_, err := exec.LookPath("systemd-nspawn")
	if err != nil {
		return err
	}
	_, err = exec.LookPath("machinectl")
	if err != nil {
		return err
	}
	return nil
}

// systemdVersion uses dbus to check which version of systemd is installed.
func systemdVersion() (string, error) {
	// check if systemd is running
	if !systemdUtil.IsRunningSystemd() {
		return "null", fmt.Errorf("systemd is not running")
	}
	bus, err := systemdDbus.NewSystemdConnection()
	if err != nil {
		return "null", err
	}
	defer bus.Close()
	// get the systemd version
	verString, err := bus.GetManagerProperty("Version")
	if err != nil {
		return "null", err
	}
	// lose the surrounding quotes
	verNumString, err := strconv.Unquote(verString)
	if err != nil {
		return "null", err
	}
	// trim possible version suffix like in "242.19-1"
	verNum := strings.Split(verNumString, ".")[0]
	return verNum, nil
}
