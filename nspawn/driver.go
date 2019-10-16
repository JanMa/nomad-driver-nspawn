package nspawn

import (
	"context"
	// "fmt"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	// "github.com/hashicorp/nomad/client/stats"
	"github.com/hashicorp/nomad/drivers/shared/eventer"
	"github.com/hashicorp/nomad/plugins/base"
	"github.com/hashicorp/nomad/plugins/drivers"
	"github.com/hashicorp/nomad/plugins/shared/hclspec"
	// pstructs "github.com/hashicorp/nomad/plugins/shared/structs"
	cstructs "github.com/hashicorp/nomad/client/structs"
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
	return nil, nil
}
func (d *Driver) Capabilities() (*drivers.Capabilities, error) {
	return nil, nil
}
func (d *Driver) Fingerprint(context.Context) (<-chan *drivers.Fingerprint, error) {
	return nil, nil
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
	return nil, nil
}

func (d *Driver) SetConfig(cfg *base.Config) error {
	return nil
}
