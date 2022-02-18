package nspawn

import (
	"fmt"
	"io"
	"math"
	"net"
	nUrl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/coreos/go-iptables/iptables"
	systemdDbus "github.com/coreos/go-systemd/dbus"
	"github.com/coreos/go-systemd/import1"
	"github.com/coreos/go-systemd/machine1"
	systemdUtil "github.com/coreos/go-systemd/util"
	"github.com/godbus/dbus"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/helper/pluginutils/hclutils"
)

const (
	machineMonitorIntv = 2 * time.Second
	dbusInterface      = "org.freedesktop.machine1.Manager"
	dbusPath           = "/org/freedesktop/machine1"

	DockerImage string = "docker"
	TarImage    string = "tar"
	RawImage    string = "raw"

	ImagePath string = "/var/lib/machines"
)

var (
	transferMut sync.Mutex
	mutMap      = make(map[string]*sync.Mutex)
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
	Bind             hclutils.MapStrStr `codec:"bind"`
	BindReadOnly     hclutils.MapStrStr `codec:"bind_read_only"`
	Boot             bool               `codec:"boot"`
	Capability       []string           `codec:"capability"`
	Command          []string           `codec:"command"`
	Console          string             `codec:"console"`
	Environment      hclutils.MapStrStr `codec:"environment"`
	Ephemeral        bool               `codec:"ephemeral"`
	Image            string             `codec:"image"`
	ImageDownload    *ImageDownloadOpts `codec:"image_download,omitempty"`
	Machine          string             `codec:"machine"`
	NetworkNamespace string             `codec:"network_namespace"`
	NetworkVeth      bool               `codec:"network_veth"`
	NetworkZone      string             `codec:"network_zone"`
	PivotRoot        string             `codec:"pivot_root"`
	Port             hclutils.MapStrStr `codec:"port"`
	Ports            []string           `codec:"ports"` // :-(
	// Deprecated: Nomad dropped support for task network resources in 0.12
	PortMap               hclutils.MapStrInt `codec:"port_map"`
	PrivateUsers          string             `codec:"private_users"`
	PrivateUsersOwnership string             `codec:"private_users_ownership"`
	ProcessTwo            bool               `codec:"process_two"`
	Properties            hclutils.MapStrStr `codec:"properties"`
	ReadOnly              bool               `codec:"read_only"`
	ResolvConf            string             `codec:"resolv_conf"`
	User                  string             `codec:"user"`
	UserNamespacing       bool               `codec:"user_namespacing"`
	Volatile              string             `codec:"volatile"`
	WorkingDirectory      string             `codec:"working_directory"`
	imagePath             string             `codec:"-"`
}

type ImageType string

type ImageProps struct {
	CreationTimestamp     uint64
	Limit                 uint64
	LimitExclusive        uint64
	ModificationTimestamp uint64
	Name                  string
	Path                  string
	ReadOnly              bool
	Type                  string
	Usage                 uint64
	UsageExclusive        uint64
}

type ImageDownloadOpts struct {
	URL    string `codec:"url"`
	Type   string `codec:"type"`
	Force  bool   `codec:"force"`
	Verify string `codec:"verify"`
}

func (c *MachineConfig) ConfigArray() ([]string, error) {
	if c.Image == "" {
		return nil, fmt.Errorf("no image configured")
	}
	// check if image exists
	imageStat, err := os.Stat(c.imagePath)
	if err != nil {
		return nil, err
	}
	imageType := "-i"
	if imageStat.IsDir() {
		imageType = "-D"
	}
	args := []string{imageType, c.imagePath}

	if c.Boot {
		args = append(args, "--boot")
	}
	if c.Ephemeral {
		args = append(args, "--ephemeral")
	}
	if c.NetworkVeth {
		args = append(args, "--network-veth")
	}
	if c.NetworkNamespace != "" {
		args = append(args, "--network-namespace-path="+c.NetworkNamespace)
	}
	if c.ProcessTwo {
		args = append(args, "--as-pid2")
	}
	if c.ReadOnly {
		args = append(args, "--read-only")
	}
	if c.UserNamespacing {
		if c.PrivateUsers == "" {
			c.PrivateUsers = "pick"
		}
		if c.PrivateUsersOwnership == "" {
			c.PrivateUsers = "auto"
		}
		args = append(args, fmt.Sprintf("--private-users=%s", c.PrivateUsers))
		args = append(args, fmt.Sprintf("--private-users-ownership=%s", c.PrivateUsersOwnership))
	}
	if c.Console != "" {
		args = append(args, fmt.Sprintf("--console=%s", c.Console))
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
		args = append(args, fmt.Sprintf("--volatile=%s", c.Volatile))
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
	for k, v := range c.Properties {
		args = append(args, "--property="+k+"="+v)
	}
	if len(c.Capability) > 0 {
		args = append(args, "--capability", strings.Join(c.Capability, ","))
	}
	if len(c.NetworkZone) > 0 {
		args = append(args, fmt.Sprintf("--network-zone=%s", c.NetworkZone))
	}
	if len(c.Command) > 0 {
		args = append(args, c.Command...)
	}
	return args, nil
}

func (c *MachineConfig) Validate() error {
	if c.Volatile != "" {
		switch c.Volatile {
		case "yes", "state", "overlay", "no":
		default:
			return fmt.Errorf("invalid parameter for volatile")
		}
	}
	if c.Console != "" {
		switch c.Console {
		case "interactive", "read-only", "passive", "pipe":
		default:
			return fmt.Errorf("invalid parameter for console")
		}
	}
	if c.ResolvConf != "" {
		switch c.ResolvConf {
		case "off", "copy-host", "copy-static", "copy-uplink", "copy-stub",
			"replace-host", "replace-static", "replace-uplink", "replace-stub",
			"bind-host", "bind-static", "bind-uplink", "bind-stub", "delete", "auto":
		default:
			return fmt.Errorf("invalid parameter for resolv_conf")
		}
	}
	if c.PrivateUsers != "" {
		switch c.PrivateUsers {
		case "yes", "no", "pick", "identity":
		default:
			// Check for single UID
			_, err := strconv.Atoi(c.PrivateUsers)
			if err != nil {
				// Check for colon separated UIDs
				uIDs := strings.Split(c.PrivateUsers, ":")
				if len(uIDs) != 2 {
					return fmt.Errorf("invalid parameter for private_users")
				}
				_, err = strconv.Atoi(uIDs[0])
				if err != nil {
					return fmt.Errorf("invalid parameter for private_users")
				}
				_, err = strconv.Atoi(uIDs[1])
				if err != nil {
					return fmt.Errorf("invalid parameter for private_users")
				}
			}
		}
	}
	if c.PrivateUsersOwnership != "" {
		switch c.PrivateUsersOwnership {
		case "auto", "map", "chown":
		default:
			return fmt.Errorf("invalid parameter for private_users_ownership")
		}
	}
	if c.Boot && c.ProcessTwo {
		return fmt.Errorf("boot and process_two may not be combined")
	}
	if c.Volatile != "" && c.PrivateUsersOwnership == "chown" {
		return fmt.Errorf("volatile and private_users_ownership=chown may not be combined")
	}
	if c.ReadOnly && c.PrivateUsersOwnership == "chown" {
		return fmt.Errorf("read_only and private_users_ownership=chown may not be combined")
	}
	if c.WorkingDirectory != "" && !filepath.IsAbs(c.WorkingDirectory) {
		return fmt.Errorf("working_directory is not an absolute path")
	}
	if c.PivotRoot != "" {
		for _, p := range strings.Split(c.PivotRoot, ":") {
			if !filepath.IsAbs(p) {
				return fmt.Errorf("pivot_root is not an absolute path")
			}
		}
	}
	if c.Image == "/" && !(c.Ephemeral || c.Volatile == "yes" || c.Volatile == "state") {
		return fmt.Errorf("starting a container from the root directory is not supported. Use ephemeral or volatile")
	}

	if c.ImageDownload != nil {
		switch c.ImageDownload.Type {
		case DockerImage, RawImage, TarImage:
		default:
			return fmt.Errorf("invalid parameter for image_download.type")
		}
		switch c.ImageDownload.Verify {
		case "no", "checksum", "signature":
		default:
			return fmt.Errorf("invalid parameter for image_download.verify")
		}
	}

	return nil
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

func ConfigureIPTablesRules(delete bool, interfaces []string) error {
	if len(interfaces) == 0 {
		return fmt.Errorf("no network interfaces configured")
	}

	t, e := iptables.New()
	if e != nil {
		return e
	}

	for _, i := range interfaces {
		rules := [][]string{[]string{"-o", i, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			[]string{"-i", i, "!", "-o", i, "-j", "ACCEPT"},
			[]string{"-i", i, "-o", i, "-j", "ACCEPT"},
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
	}

	return nil
}

func (p *MachineProps) GetNetworkInterfaces() ([]string, error) {
	if len(p.NetworkInterfaces) == 0 {
		return nil, fmt.Errorf("machine has no network interfaces assigned")
	}

	n := []string{}
	for _, i := range p.NetworkInterfaces {
		iFace, err := net.InterfaceByIndex(int(i))
		if err != nil {
			return []string{}, err
		}
		n = append(n, iFace.Name)
	}
	return n, nil
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

func isSystemdInstalled() error {
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

func DescribeImage(name string) (*ImageProps, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	img := conn.Object("org.freedesktop.machine1", "/org/freedesktop/machine1")
	var path dbus.ObjectPath

	err = img.Call("org.freedesktop.machine1.Manager.GetImage", 0, name).Store(&path)
	if err != nil {
		return nil, err
	}

	obj := conn.Object("org.freedesktop.machine1", path)
	props := make(map[string]interface{})

	err = obj.Call("org.freedesktop.DBus.Properties.GetAll", 0, "").Store(&props)
	if err != nil {
		return nil, err
	}

	return &ImageProps{
		CreationTimestamp:     props["CreationTimestamp"].(uint64),
		Limit:                 props["Limit"].(uint64),
		LimitExclusive:        props["LimitExclusive"].(uint64),
		ModificationTimestamp: props["ModificationTimestamp"].(uint64),
		Name:                  props["Name"].(string),
		Path:                  props["Path"].(string),
		ReadOnly:              props["ReadOnly"].(bool),
		Type:                  props["Type"].(string),
		Usage:                 props["Usage"].(uint64),
		UsageExclusive:        props["UsageExclusive"].(uint64),
	}, nil
}

func DownloadImage(url, name, verify, imageType string, force bool, logger hclog.Logger) error {
	c, err := import1.New()
	if err != nil {
		return err
	}

	switch imageType {
	case DockerImage, RawImage, TarImage:
	default:
		return fmt.Errorf("unsupported image type")
	}

	// systemd-importd only allows one transfer for each unique URL at a
	// time. To not run into API errors, we need to ensure we do not try to
	// download an image from the same URL multiple times at one. We do this
	// by creating a simple map containing a Mutex for each URL and only
	// start our download if we can hold the lock for a given URL. This
	// naively assumes we are the only process making regular use of the
	// systemd-importd api on the host.
	//
	// In the future it would probably be better to make use of the built-in
	// signals in systemd-importd as described here:
	// https://www.freedesktop.org/wiki/Software/systemd/importd/

	// get global lock
	logger.Debug("waiting on global download lock")
	transferMut.Lock()
	// get lock for given remote
	l, ok := mutMap[url]
	if !ok {
		// create it if it does not exist
		var m sync.Mutex
		l = &m
		mutMap[url] = &m
	} else {
		logger.Debug("remote lock exists", "remote", url)
	}
	// release global lock
	transferMut.Unlock()
	// get lock for remote
	logger.Debug("waiting on remote lock", "remote", url)
	l.Lock()
	// release lock for remote when done
	defer l.Unlock()

	var t *import1.Transfer
	switch imageType {
	case DockerImage:
		t, err = PullDocker(c, url, name, force)
	case TarImage:
		t, err = c.PullTar(url, name, verify, force)
	case RawImage:
		t, err = c.PullRaw(url, name, verify, force)
	default:
		return fmt.Errorf("unsupported image type")
	}
	if err != nil {
		return err
	}

	// wait until transfer is finished
	logger.Info("downloading image", "image", name)
	done := false
	ticker := time.NewTicker(2 * time.Second)
	for !done {
		select {
		case <-ticker.C:
			tf, _ := c.ListTransfers()
			if len(tf) == 0 {
				done = true
				ticker.Stop()
				continue
			}
			found := false
			for _, v := range tf {
				if v.Id == t.Id {
					found = true
					if !(math.IsNaN(v.Progress) || math.IsInf(v.Progress, 0) || math.Abs(v.Progress) == math.MaxFloat64) {
						logger.Info("downloading image", "image", name, "progress", v.Progress)
					}
				}
			}
			if !found {
				done = true
				ticker.Stop()
			}
		}
	}

	logger.Info("downloaded image", "image", name)
	return nil
}

func (c *MachineConfig) GetImagePath() (string, error) {
	// check if image is absolute or relative path
	imagePath := c.Image
	if !filepath.IsAbs(c.Image) {
		pwd, e := os.Getwd()
		if e != nil {
			return "", e
		}
		imagePath = filepath.Join(pwd, c.Image)
	}
	// check if image exists
	_, err := os.Stat(imagePath)
	if err == nil {
		return imagePath, err
	}
	// check if image is known to machinectl
	p, err := DescribeImage(c.Image)
	if err != nil {
		return "", err
	}
	return p.Path, nil
}

func PullDocker(c *import1.Conn, url, image string, force bool) (*import1.Transfer, error) {
	// validate image referece
	ref, err := name.ParseReference(url)
	if err != nil {
		return nil, err
	}

	// check if image exists
	img, err := remote.Image(ref)
	if err != nil {
		return nil, err
	}

	// create temporary download dir
	tmpDir := ImagePath + "/.tar-docker:" + nUrl.PathEscape(url)
	err = os.MkdirAll(tmpDir, 0755)
	if err != nil {
		return nil, err
	}
	tmpPath := tmpDir + "/" + image + ".tar"

	//check if archive already exists
	_, err = os.Stat(tmpPath)
	if !os.IsNotExist(err) && force {
		// archive exists and force
		// remove existing archive
		remErr := os.Remove(tmpPath)
		if remErr != nil {
			return nil, remErr
		}
	} else if !os.IsNotExist(err) && !force {
		// archive exists and not force
		// import existing archive
		f, err := os.Open(tmpPath)
		if err != nil {
			return nil, err
		}
		return c.ImportTar(f, image, force, false)
	}

	// archive does not exist
	// extract docker image to flattened tar archive
	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(f, mutate.Extract(img))
	if err != nil {
		return nil, err
	}
	f.Close()

	// reopen archive read-only
	f, err = os.Open(tmpPath)
	if err != nil {
		return nil, err
	}

	// import tar archive
	return c.ImportTar(f, image, force, false)
}
