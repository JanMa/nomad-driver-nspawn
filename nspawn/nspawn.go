package nspawn

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	systemdDbus "github.com/coreos/go-systemd/dbus"
	"github.com/coreos/go-systemd/machine1"
	systemdUtil "github.com/coreos/go-systemd/util"
)

type MachineProps struct {
	Name               string
	TimestampMonotonic uint64
	Timestamp          uint64
	NetworkInterfaces  []int32
	ID                 []uint8
	Class              string
	Leader             uint32
	RootDirectory      string
	Service            string
	State              string
	Unit               string
}

func DescribeMachine(name string) (*MachineProps, error) {
	c, e := machine1.New()
	if e != nil {
		return nil, e
	}
	p, e := c.DescribeMachine(name)
	if e != nil {
		return nil, e
	}
	return &MachineProps{
		Name:               p["Name"].(string),
		TimestampMonotonic: p["TimestampMonotonic"].(uint64),
		Timestamp:          p["Timestamp"].(uint64),
		NetworkInterfaces:  p["NetworkInterfaces"].([]int32),
		ID:                 p["Id"].([]uint8),
		Class:              p["Class"].(string),
		Leader:             p["Leader"].(uint32),
		RootDirectory:      p["RootDirectory"].(string),
		Service:            p["Service"].(string),
		State:              p["State"].(string),
		Unit:               p["Unit"].(string),
	}, nil
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
