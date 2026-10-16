// Package rig runs portable-smb-server's end-to-end tests on the test rig: real SMB clients
// (Windows `net use`, Linux mount.cifs and smbclient, macOS mount_smbfs) on real machines, against
// the server under test on another machine, for every client OS x server OS pair, under standard
// and stressful conditions.
//
// The machines come from the rig's settings.yml ("portable-smb-server local\provisioning" beside
// the repo, or $PSMB_RIG_DIR), which is also what Vagrant builds them from. Without that file, or
// when a machine can't be reached, the tests that need it skip rather than fail: the rig is
// optional, the unit and loopback tests are not.
//
//	cd test
//	go test ./rig -run TestMatrix -v -timeout 3h                  # every pair, every condition
//	go test ./rig -run 'TestMatrix/linux->windows' -v              # one pair
//	go test ./rig -run 'TestMatrix/.*/rename' -v                   # one condition, every pair
//	PSMB_PAIRS=macos>linux,linux>macos go test ./rig -run TestMatrix -v
//	go test ./rig -run TestMultiClient -v                          # every client at once, per server
//	PSMB_STRESS_SECONDS=300 go test ./rig -run TestStress -v       # the barrage, per server OS
package rig

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// OS is a test machine's operating system, which decides the SMB client it runs and the shell its
// commands are written in (bash, PowerShell, zsh/bash).
type OS string

const (
	Linux   OS = "linux"
	Windows OS = "windows"
	MacOS   OS = "macos"
)

// AllOS lists the operating systems, in the order the matrix walks them.
var AllOS = []OS{Linux, Windows, MacOS}

// Machine is one test machine, as the tests reach it: over SSH at its LAN address, with the rig's key.
type Machine struct {
	Name    string
	OS      OS
	IP      string
	User    string
	KeyFile string
}

// Settings is what the tests read from the rig's settings.yml.
type Settings struct {
	Path     string    // the settings.yml the machines came from
	Port     int       // the port the server under test listens on
	Machines []Machine // in the order the tests use them: per OS, the first is the client
}

// DirVariable names the provisioning folder when it isn't at the default location.
const DirVariable = "PSMB_RIG_DIR"

// RigDir is the provisioning folder: $PSMB_RIG_DIR, or "<repo> local\provisioning" beside the repo.
func RigDir() string {
	if d := os.Getenv(DirVariable); d != "" {
		return d
	}
	_, file, _, _ := runtime.Caller(0)
	repo := filepath.Dir(filepath.Dir(filepath.Dir(file))) // test/rig/rig.go -> the repo
	return filepath.Join(filepath.Dir(repo), filepath.Base(repo)+" local", "provisioning")
}

// The parts of settings.yml the tests read; the rest is for Vagrant and the provisioners.
type settingsYML struct {
	SSHKey string `yaml:"ssh_key"`
	SMB    struct {
		Port int `yaml:"port"`
	} `yaml:"smb"`
	Machines []struct {
		Name string `yaml:"name"`
		OS   string `yaml:"os"`
		IP   string `yaml:"ip"`
		User string `yaml:"user"`
	} `yaml:"machines"`
	Mac *struct {
		Name     string `yaml:"name"`
		Host     string `yaml:"host"`
		User     string `yaml:"user"`
		Machines []struct {
			Name string `yaml:"name"`
			IP   string `yaml:"ip"`
			User string `yaml:"user"`
		} `yaml:"machines"`
	} `yaml:"mac"`
}

// LoadSettings reads the machines from a settings.yml: the VirtualBox VMs under machines:, then the
// Mac itself and the VMs it runs, under mac:.
func LoadSettings(path string) (*Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var y settingsYML
	if err := yaml.Unmarshal(data, &y); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	key := expandHome(y.SSHKey)
	s := &Settings{Path: path, Port: y.SMB.Port}
	if s.Port == 0 {
		s.Port = 1445
	}
	for _, m := range y.Machines {
		osName := OS(strings.ToLower(m.OS))
		if osName != Linux && osName != Windows && osName != MacOS {
			return nil, fmt.Errorf("%s: machine %s has unknown os %q", path, m.Name, m.OS)
		}
		user := m.User
		if user == "" {
			user = "vagrant" // Vagrant's boxes log in as vagrant unless an entry says otherwise
		}
		s.Machines = append(s.Machines, Machine{Name: m.Name, OS: osName, IP: m.IP, User: user, KeyFile: key})
	}
	if y.Mac != nil {
		s.Machines = append(s.Machines, Machine{Name: y.Mac.Name, OS: MacOS, IP: y.Mac.Host, User: y.Mac.User, KeyFile: key})
		for _, m := range y.Mac.Machines {
			s.Machines = append(s.Machines, Machine{Name: m.Name, OS: MacOS, IP: m.IP, User: m.User, KeyFile: key})
		}
	}
	return s, nil
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

var (
	loadOnce sync.Once
	loaded   *Settings
	loadErr  error
)

// Load reads the rig's settings once per test run.
func Load() (*Settings, error) {
	loadOnce.Do(func() {
		loaded, loadErr = LoadSettings(filepath.Join(RigDir(), "settings.yml"))
	})
	return loaded, loadErr
}

// Of lists the machines of one OS, in the order the tests use them.
func (s *Settings) Of(o OS) []Machine {
	var out []Machine
	for _, m := range s.Machines {
		if m.OS == o {
			out = append(out, m)
		}
	}
	return out
}

// Pair picks the machines for a client OS / server OS pair: the client is the first machine of its
// OS, the server the second when it's the same OS, else the first. Every pair is two machines.
func (s *Settings) Pair(client, server OS) (c, srv Machine, err error) {
	cs, ss := s.Of(client), s.Of(server)
	if len(cs) == 0 {
		return c, srv, fmt.Errorf("%s has no %s machine", s.Path, client)
	}
	idx := 0
	if client == server {
		idx = 1
	}
	if len(ss) <= idx {
		return c, srv, fmt.Errorf("%s has no %s machine #%d (a %s->%s pair needs two)", s.Path, server, idx+1, client, server)
	}
	return cs[0], ss[idx], nil
}

// Find looks a machine up by name.
func (s *Settings) Find(name string) (Machine, bool) {
	for _, m := range s.Machines {
		if m.Name == name {
			return m, true
		}
	}
	return Machine{}, false
}
