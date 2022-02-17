package nspawn

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ctestutils "github.com/hashicorp/nomad/client/testutil"
	"github.com/hashicorp/nomad/helper/pluginutils/hclutils"
	"github.com/hashicorp/nomad/helper/testlog"
	"github.com/hashicorp/nomad/helper/uuid"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/plugins/drivers"
	dtestutil "github.com/hashicorp/nomad/plugins/drivers/testutils"
	"github.com/hashicorp/nomad/testutil"
	"github.com/stretchr/testify/require"
)

var testResources = &drivers.Resources{
	NomadResources: &structs.AllocatedTaskResources{
		Memory: structs.AllocatedMemoryResources{
			MemoryMB: 128,
		},
		Cpu: structs.AllocatedCpuResources{
			CpuShares: 100,
		},
	},
	LinuxResources: &drivers.LinuxResources{
		MemoryLimitBytes: 134217728,
		CPUShares:        100,
	},
}

func alpineConfig(cmd string) *MachineConfig {
	if len(cmd) == 0 {
		cmd = "sleep 5"
	}

	return &MachineConfig{
		Boot:      false,
		Command:   []string{"/bin/sh", "-c", "ip link set host0 up; udhcpc -i host0; " + cmd},
		Ephemeral: true,
		Image:     "alpine",
		ImageDownload: &ImageDownloadOpts{
			URL:    "http://dl-cdn.alpinelinux.org/alpine/v3.12/releases/x86_64/alpine-minirootfs-3.12.0-x86_64.tar.gz",
			Type:   "tar",
			Verify: "checksum",
		},
		ProcessTwo:  true,
		ResolvConf:  "copy-host",
		NetworkVeth: true,
	}
}

func alpineDockerConfig(cmd string) *MachineConfig {
	if len(cmd) == 0 {
		cmd = "sleep 5"
	}

	return &MachineConfig{
		Boot:      false,
		Command:   []string{"/bin/sh", "-c", "ip link set host0 up; udhcpc -i host0; " + cmd},
		Ephemeral: true,
		Image:     "alpine-docker",
		ImageDownload: &ImageDownloadOpts{
			URL:    "alpine:latest",
			Type:   "docker",
			Verify: "no",
		},
		ProcessTwo:  true,
		ResolvConf:  "copy-host",
		NetworkVeth: true,
	}
}

func debianConfig() *MachineConfig {
	return &MachineConfig{
		Boot:      true,
		Ephemeral: true,
		Image:     "debian",
		ImageDownload: &ImageDownloadOpts{
			URL:    "https://nspawn.org/storage/debian/buster/tar/image.tar.xz",
			Type:   "tar",
			Verify: "no",
		},
		ResolvConf:  "copy-host",
		NetworkVeth: true,
	}
}

func TestNspawnDriver_Fingerprint(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)

	fingerCh, err := harness.Fingerprint(context.Background())
	require.NoError(err)
	select {
	case finger := <-fingerCh:
		require.Equal(drivers.HealthStateHealthy, finger.Health)
		require.True(finger.Attributes["driver.nspawn"].GetBool())
	case <-time.After(time.Duration(testutil.TestMultiplier()*5) * time.Second):
		require.Fail("timeout receiving fingerprint")
	}
}

func TestNspawnDriver_StartWait(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "test",
		Resources: testResources,
	}

	require.NoError(task.EncodeConcreteDriverConfig(alpineDockerConfig("")))

	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(err)

	ch, err := harness.WaitTask(context.Background(), handle.Config.ID)
	require.NoError(err)
	result := <-ch
	require.Zero(result.ExitCode)

	require.NoError(harness.StopTask(task.ID, 10*time.Second, ""))
	require.NoError(harness.DestroyTask(task.ID, true))
}

func TestNspawnDriver_StartWaitStopKill(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "test",
		Resources: testResources,
	}

	require.NoError(task.EncodeConcreteDriverConfig(alpineConfig("sleep 600")))

	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(err)
	defer harness.DestroyTask(task.ID, true)

	ch, err := harness.WaitTask(context.Background(), handle.Config.ID)
	require.NoError(err)

	require.NoError(harness.WaitUntilStarted(task.ID, 1*time.Second))

	go func() {
		harness.StopTask(task.ID, 2*time.Second, "SIGINT")
	}()

	select {
	case result := <-ch:
		require.False(result.Successful())
	case <-time.After(10 * time.Second):
		require.Fail("timeout waiting for task to shutdown")
	}

	// Ensure that the task is marked as dead, but account
	// for WaitTask() closing channel before internal state is updated
	testutil.WaitForResult(func() (bool, error) {
		status, err := harness.InspectTask(task.ID)
		if err != nil {
			return false, fmt.Errorf("inspecting task failed: %v", err)
		}
		if status.State != drivers.TaskStateExited {
			return false, fmt.Errorf("task hasn't exited yet; status: %v", status.State)
		}

		return true, nil
	}, func(err error) {
		require.NoError(err)
	})

	require.NoError(harness.DestroyTask(task.ID, true))
}

func TestNspawnDriver_StartWaitRecover(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "test",
		Resources: testResources,
	}

	require.NoError(task.EncodeConcreteDriverConfig(alpineConfig("")))

	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(err)

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := harness.WaitTask(ctx, handle.Config.ID)
	require.NoError(err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := <-ch
		require.Error(result.Err)
	}()

	require.NoError(harness.WaitUntilStarted(task.ID, 1*time.Second))
	cancel()

	waitCh := make(chan struct{})
	go func() {
		defer close(waitCh)
		wg.Wait()
	}()

	select {
	case <-waitCh:
		status, err := harness.InspectTask(task.ID)
		require.NoError(err)
		require.Equal(drivers.TaskStateRunning, status.State)
	case <-time.After(1 * time.Second):
		require.Fail("timeout waiting for task wait to cancel")
	}

	// Loose task
	d.(*Driver).tasks.Delete(task.ID)
	_, err = harness.InspectTask(task.ID)
	require.Error(err)

	require.NoError(harness.RecoverTask(handle))
	status, err := harness.InspectTask(task.ID)
	require.NoError(err)
	require.Equal(drivers.TaskStateRunning, status.State)

	require.NoError(harness.StopTask(task.ID, 0, ""))
	require.NoError(harness.DestroyTask(task.ID, true))
}

func TestNspawnDriver_Stats(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "test",
		Resources: testResources,
	}
	require.NoError(task.EncodeConcreteDriverConfig(alpineConfig("")))

	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	handle, _, err := harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)

	require.NoError(harness.WaitUntilStarted(task.ID, 1*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statsCh, err := harness.TaskStats(ctx, task.ID, time.Second*10)
	require.NoError(err)
	select {
	case stats := <-statsCh:
		require.NotZero(stats.ResourceUsage.MemoryStats.RSS)
		require.NotZero(stats.Timestamp)
		require.WithinDuration(time.Now(), time.Unix(0, stats.Timestamp), time.Second)
	case <-time.After(time.Second):
		require.Fail("timeout receiving from channel")
	}

	require.NoError(harness.StopTask(task.ID, 0, ""))
	require.NoError(harness.DestroyTask(task.ID, true))
}

func TestNspawnDriver_Start_Wait_AllocDir(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "sleep",
		Resources: testResources,
	}
	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	exp := []byte{'w', 'i', 'n'}
	file := "output.txt"
	require.NoError(task.EncodeConcreteDriverConfig(alpineConfig(fmt.Sprintf(`sleep 1; echo -n %s > /alloc/%s`, string(exp), file))))

	handle, _, err := harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)

	// Task should terminate quickly
	waitCh, err := harness.WaitTask(context.Background(), task.ID)
	require.NoError(err)
	select {
	case res := <-waitCh:
		require.True(res.Successful(), "task should have exited successfully: %v", res)
	case <-time.After(time.Duration(testutil.TestMultiplier()*5) * time.Second):
		require.Fail("timeout waiting for task")
	}

	// Check that data was written to the shared alloc directory.
	outputFile := filepath.Join(task.TaskDir().SharedAllocDir, file)
	act, err := ioutil.ReadFile(outputFile)
	require.NoError(err)
	require.Exactly(exp, act)

	require.NoError(harness.StopTask(task.ID, 10*time.Second, ""))
	require.NoError(harness.DestroyTask(task.ID, true))
}

// TestNspawnDriver_HandlerExec ensures the exec driver's handle properly
// executes commands inside the container.
func TestNspawnDriver_HandlerExec(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "sleep",
		Resources: testResources,
	}
	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	require.NoError(task.EncodeConcreteDriverConfig(debianConfig()))

	handle, _, err := harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)

	// Exec a command that should succeed
	res, err := harness.ExecTask(task.ID, []string{"/bin/cat", "/etc/os-release"}, time.Second)
	require.NoError(err)
	require.True(res.ExitResult.Successful())

	// Exec a command that should fail
	res, err = harness.ExecTask(task.ID, []string{"/usr/bin/stat", "lkjhdsaflkjshowaisxmcvnlia"}, time.Second)
	require.NoError(err)
	require.False(res.ExitResult.Successful())
	if expected := "No such file or directory"; !bytes.Contains(res.Stdout, []byte(expected)) {
		t.Fatalf("expected output to contain %q but found: %q", expected, res.Stdout)
	}

	require.NoError(harness.StopTask(task.ID, 10*time.Second, ""))
	require.NoError(harness.DestroyTask(task.ID, true))
}

func TestNspawnDriver_PortMap(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "port-map",
		Resources: testResources,
	}
	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	taskCfg := alpineConfig("")
	taskCfg.PortMap = make(hclutils.MapStrInt)
	taskCfg.PortMap["foo"] = 8080
	taskCfg.PortMap["bar"] = 9090

	require.NoError(task.EncodeConcreteDriverConfig(taskCfg))

	// Test should fail because no network resources are defined
	handle, _, err := harness.StartTask(task)
	require.Error(err)
	require.Nil(handle)

	task.Resources.NomadResources.Networks = []*structs.NetworkResource{
		{
			IP: "127.0.0.1",
			DynamicPorts: []structs.Port{
				{Label: "foo", Value: 8080},
				{Label: "bar", Value: 9090},
			},
		},
	}

	// Now the test should pass
	handle, _, err = harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)
	require.NoError(harness.StopTask(task.ID, 10*time.Second, ""))
	require.NoError(harness.DestroyTask(task.ID, true))
}

func TestNspawnDriver_Ports(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "ports",
		Resources: testResources,
	}
	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	taskCfg := alpineConfig("")
	taskCfg.Ports = []string{"foo", "bar"}

	require.NoError(task.EncodeConcreteDriverConfig(taskCfg))

	// Test should fail because no network resources are defined
	handle, _, err := harness.StartTask(task)
	require.Error(err)
	require.Nil(handle)

	task.Resources.Ports = &structs.AllocatedPorts{
		{
			Label:  "foo",
			HostIP: "127.0.0.1",
			Value:  54321,
			To:     8080,
		},
		{
			Label:  "bar",
			HostIP: "127.0.0.1",
			Value:  54320,
			To:     9090,
		},
	}

	// Now the test should pass
	handle, _, err = harness.StartTask(task)
	require.NoError(err)
	require.NotNil(handle)
	require.NoError(harness.StopTask(task.ID, 10*time.Second, ""))
	require.NoError(harness.DestroyTask(task.ID, true))
}

func TestNspawnDriver_PortsAndPortMap(t *testing.T) {
	t.Parallel()
	require := require.New(t)
	ctestutils.ExecCompatible(t)

	d := NewNspawnDriver(testlog.HCLogger(t))
	harness := dtestutil.NewDriverHarness(t, d)
	task := &drivers.TaskConfig{
		ID:        uuid.Generate(),
		AllocID:   uuid.Generate(),
		Name:      "ports-port-map",
		Resources: testResources,
	}
	cleanup := harness.MkAllocDir(task, true)
	defer cleanup()

	taskCfg := alpineConfig("")
	taskCfg.Ports = []string{"foo", "bar"}
	taskCfg.PortMap = make(hclutils.MapStrInt)
	taskCfg.PortMap["foo"] = 8080
	taskCfg.PortMap["bar"] = 9090

	require.NoError(task.EncodeConcreteDriverConfig(taskCfg))

	// Test should fail because no network resources are defined
	handle, _, err := harness.StartTask(task)
	require.Error(err)
	require.Nil(handle)
}
