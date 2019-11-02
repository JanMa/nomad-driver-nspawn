package nspawn

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	systemdDbus "github.com/coreos/go-systemd/dbus"
	"github.com/coreos/go-systemd/machine1"
	systemdUtil "github.com/coreos/go-systemd/util"
	"github.com/godbus/dbus"
)

const (
	machineMonitorIntv = 2 * time.Second
	dbusInterface      = "org.freedesktop.machine1.Manager"
	dbusPath           = "/org/freedesktop/machine1"
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

type MachineAddrs struct {
	IPv4         net.IP
	LocalUnicast net.IP
	//TODO: add parsing for IPv6
	// IPv6         net.IP
}

func DescribeMachine(name string, timeout time.Duration) (*MachineProps, error) {
	c, e := machine1.New()
	if e != nil {
		return nil, e
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	done := make(chan bool)
	go func() {
		time.Sleep(timeout)
		done <- true
	}()

	for {
		select {
		case <-done:
			ticker.Stop()
			return nil, fmt.Errorf("timed out while getting machine properties")
		case <-ticker.C:
			p, e := c.DescribeMachine(name)
			if e == nil {
				ticker.Stop()
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
		}
	}
}

func MachineAddresses(name string, timeout time.Duration) (*MachineAddrs, error) {
	dbusConn, err := setupPrivateSystemBus()
	if err != nil {
		return nil, err
	}
	defer dbusConn.Close()

	obj := dbusConn.Object("org.freedesktop.machine1", dbus.ObjectPath(dbusPath))
	ticker := time.NewTicker(500 * time.Millisecond)
	done := make(chan bool)
	go func() {
		time.Sleep(timeout)
		done <- true
	}()

	for {
		select {
		case <-done:
			ticker.Stop()
			return nil, fmt.Errorf("timed out while getting machine addresses")
		case <-ticker.C:
			result := obj.Call(fmt.Sprintf("%s.%s", dbusInterface, "GetMachineAddresses"), 0, name)
			if result.Err != nil {
				return nil, result.Err
			}

			addrs := MachineAddrs{}

			for _, v := range result.Body[0].([][]interface{}) {
				t := v[0].(int32)
				a := v[1].([]uint8)
				if t == 2 {
					ip := net.IP{}
					for _, o := range a {
						ip = append(ip, byte(o))
					}
					if ip.IsLinkLocalUnicast() {
						addrs.LocalUnicast = ip
					} else {
						addrs.IPv4 = ip
					}
				}
			}

			if len(addrs.IPv4) > 0 && len(addrs.LocalUnicast) > 0 {
				ticker.Stop()
				return &addrs, nil
			}
		}
	}

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

// waitTillStopped blocks and returns true when container stops;
// returns false with an error message if the container processes cannot be identified.
func waitTillStopped(m *MachineProps) (bool, error) {
	ps, err := os.FindProcess(int(m.Leader))
	if err != nil {
		return false, err
	}

	for {
		if err := ps.Signal(syscall.Signal(0)); err != nil {
			return true, nil
		}

		time.Sleep(machineMonitorIntv)
	}
}

func setupPrivateSystemBus() (conn *dbus.Conn, err error) {
	conn, err = dbus.SystemBusPrivate()
	if err != nil {
		return nil, err
	}
	methods := []dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}
	if err = conn.Auth(methods); err != nil {
		conn.Close()
		conn = nil
		return
	}
	if err = conn.Hello(); err != nil {
		conn.Close()
		conn = nil
	}
	return conn, nil
}
