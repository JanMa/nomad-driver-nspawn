package nspawn

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	systemdDbus "github.com/coreos/go-systemd/dbus"
	"github.com/coreos/go-systemd/machine1"
	systemdUtil "github.com/coreos/go-systemd/util"
	"github.com/godbus/dbus"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/ugorji/go/codec"
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
	IPv4 net.IP
	//TODO: add parsing for IPv6
	// IPv6         net.IP
}

type MachineConfig struct {
	Boot             bool      `codec:"boot"`
	Ephemeral        bool      `codec:"ephemeral"`
	NetworkVeth      bool      `codec:"network_veth"`
	ProcessTwo       bool      `codec:"process_two"`
	ReadOnly         bool      `codec:"read_only"`
	UserNamespacing  bool      `codec:"user_namespacing"`
	Command          []string  `codec:"command"`
	Console          string    `codec:"console"`
	Image            string    `codec:"image"`
	Machine          string    `codec:"machine"`
	PivotRoot        string    `codec:"pivot_root"`
	ResolvConf       string    `codec:"resolv_conf"`
	User             string    `codec:"user"`
	Volatile         string    `codec:"volatile"`
	WorkingDirectory string    `codec:"working_directory"`
	Bind             MapStrStr `codec:"bind"`
	BindReadOnly     MapStrStr `codec:"bind_read_only"`
	Environment      MapStrStr `codec:"environment"`
	Port             MapStrStr `codec:"port"`
	PortMap          MapStrInt `codec:"port_map"`
}

func (c *MachineConfig) ConfigArray() ([]string, error) {
	if c.Image == "" {
		return nil, fmt.Errorf("no image configured")
	}
	// check if image exists
	imagePath := c.Image
	if !filepath.IsAbs(c.Image) {
		pwd, e := os.Getwd()
		if e != nil {
			return nil, e
		}
		imagePath = filepath.Join(pwd, c.Image)
	}
	imageStat, err := os.Stat(imagePath)
	if err != nil {
		return nil, err
	}
	imageType := "-i"
	if imageStat.IsDir() {
		imageType = "-D"
	}
	args := []string{imageType, c.Image}

	if c.Boot {
		args = append(args, "--boot")
	}
	if c.Ephemeral {
		args = append(args, "--ephemeral")
	}
	if c.NetworkVeth {
		args = append(args, "--network-veth")
	}
	if c.ProcessTwo {
		args = append(args, "--as-pid2")
	}
	if c.ReadOnly {
		args = append(args, "--read-only")
	}
	if c.UserNamespacing {
		args = append(args, "-U")
	}
	if c.Console != "" {
		args = append(args, "--console", c.Console)
	}
	if c.Machine != "" {
		args = append(args, "--machine", c.Machine)
	}
	if c.PivotRoot != "" {
		args = append(args, "--pivot-root", c.PivotRoot)
	}
	if c.ResolvConf != "" {
		args = append(args, "--resolv-conf", c.ResolvConf)
	}
	if c.User != "" {
		args = append(args, "--user", c.User)
	}
	if c.Volatile != "" {
		args = append(args, "--volatile", c.Volatile)
	}
	if c.WorkingDirectory != "" {
		args = append(args, "--chdir", c.WorkingDirectory)
	}
	for k, v := range c.Bind {
		args = append(args, "--bind", k+":"+v)
	}
	for k, v := range c.BindReadOnly {
		args = append(args, "--bind-ro", k+":"+v)
	}
	for k, v := range c.Environment {
		args = append(args, "-E", k+"="+v)
	}
	for _, v := range c.Port {
		args = append(args, "-p", v)
	}
	if len(c.Command) > 0 {
		args = append(args, c.Command...)
	}
	return args, nil
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

	var p map[string]interface{}
	for {
		select {
		case <-done:
			ticker.Stop()
			return nil, fmt.Errorf("timed out while getting machine properties: %+v", e)
		case <-ticker.C:
			p, e = c.DescribeMachine(name)
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

func (p *MachineProps) ConfigureIPTablesRules(delete bool) error {
	t, e := iptables.New()
	if e != nil {
		return e
	}

	iFace, e := net.InterfaceByIndex(int(p.NetworkInterfaces[0]))
	if e != nil {
		return e
	}

	rules := [][]string{[]string{"-o", iFace.Name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		[]string{"-i", iFace.Name, "!", "-o", iFace.Name, "-j", "ACCEPT"},
		[]string{"-i", iFace.Name, "-o", iFace.Name, "-j", "ACCEPT"},
	}

	for _, r := range rules {
		switch ok, err := t.Exists("filter", "FORWARD", r...); {
		case err == nil && !ok:
			e := t.Append("filter", "FORWARD", r...)
			if e != nil {
				return e
			}
		case err == nil && ok && delete:
			e := t.Delete("filter", "FORWARD", r...)
			if e != nil {
				return e
			}
		case err != nil:
			return err
		}
	}

	return nil
}

func MachineAddresses(name string, timeout time.Duration) (*MachineAddrs, error) {
	dbusConn, err := setupPrivateSystemBus()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to dbus: %+v", err)
	}
	defer dbusConn.Close()

	obj := dbusConn.Object("org.freedesktop.machine1", dbus.ObjectPath(dbusPath))
	ticker := time.NewTicker(500 * time.Millisecond)
	done := make(chan bool)
	go func() {
		time.Sleep(timeout)
		done <- true
	}()

	var result *dbus.Call
	for {
		select {
		case <-done:
			ticker.Stop()
			return nil, fmt.Errorf("timed out while getting machine addresses: %+v", result.Err)
		case <-ticker.C:
			result = obj.Call(fmt.Sprintf("%s.%s", dbusInterface, "GetMachineAddresses"), 0, name)
			if result.Err != nil {
				return nil, fmt.Errorf("failed to call dbus: %+v", result.Err)
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
					if !ip.IsLinkLocalUnicast() {
						addrs.IPv4 = ip
					}
				}
			}

			if len(addrs.IPv4) > 0 {
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

type MapStrInt map[string]int

func (s *MapStrInt) CodecEncodeSelf(enc *codec.Encoder) {
	v := []map[string]int{*s}
	enc.MustEncode(v)
}

func (s *MapStrInt) CodecDecodeSelf(dec *codec.Decoder) {
	ms := []map[string]int{}
	dec.MustDecode(&ms)

	r := map[string]int{}
	for _, m := range ms {
		for k, v := range m {
			r[k] = v
		}
	}
	*s = r
}

type MapStrStr map[string]string

func (s *MapStrStr) CodecEncodeSelf(enc *codec.Encoder) {
	v := []map[string]string{*s}
	enc.MustEncode(v)
}

func (s *MapStrStr) CodecDecodeSelf(dec *codec.Decoder) {
	ms := []map[string]string{}
	dec.MustDecode(&ms)

	r := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			r[k] = v
		}
	}
	*s = r
}

func shutdown(name string, timeout time.Duration, logger hclog.Logger) error {
	cmd := exec.Command("machinectl", "stop", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("error shutting down", "error", strings.TrimSpace(string(out)), "machine", name)
		return err
	}
	ticker := time.NewTicker(2 * time.Second)
	done := make(chan bool)
	go func() {
		time.Sleep(timeout - 2*time.Second)
		done <- true
	}()
	for {
		select {
		case <-done:
			ticker.Stop()
			e := exec.Command("machinectl", "kill", name, "-s", "SIGKILL").Run()
			if e != nil {
				logger.Error("error killing machine", "error", e, "machine", name)
				return fmt.Errorf("failed to kill machine: %+v", e)
			}
			_, e = DescribeMachine(name, time.Second)
			if e == nil {
				logger.Error("failed to shut down machine in time", "machine", name)
				return fmt.Errorf("failed to shutdown machine in time")
			}
			logger.Debug("shutdown successful", "machine", name)
			return nil
		case <-ticker.C:
			_, e := DescribeMachine(name, time.Second)
			if e != nil {
				ticker.Stop()
				logger.Debug("shutdown successful", "machine", name)
				return nil
			}
		}
	}
}
