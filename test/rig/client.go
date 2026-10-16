package rig

import (
	"fmt"
	"strings"
	"time"
)

// Client is a native SMB client mounting a share of the server under test: Windows `net use` with
// a drive letter (TCP port via /TCPPORT, Windows 11 24H2+), Linux `mount -t cifs` (the kernel's
// client), or macOS `mount_smbfs`. It hands back the local path of the mount, Root, so file
// operations can be driven through it with ops.go.
type Client struct {
	Host     *Host
	ServerIP string
	Share    string
	Port     int
	Guest    bool
	User     string
	Pass     string

	// Linux only: the dialect mount.cifs asks for (vers=), "" to let it negotiate; and any further
	// mount options (sign, seal, ...).
	Vers    string
	Options string

	// Tag keeps concurrent mounts on one host apart: it suffixes the Unix mount point and picks the
	// Windows drive letter ("" is Z:, otherwise the tag's first letter, so use "Y".."Q").
	Tag string

	// Root is the mount's local path once Mount has succeeded.
	Root string
}

func (c *Client) mountPoint() string {
	switch c.Host.OS {
	case Windows:
		letter := "Z"
		if c.Tag != "" {
			letter = strings.ToUpper(c.Tag[:1])
		}
		return letter + ":"
	case Linux:
		return "/mnt/psmb-" + c.Share + c.suffix()
	default:
		return c.Host.Join(c.Host.RigDir(), "mnt-"+c.Share+c.suffix())
	}
}

func (c *Client) suffix() string {
	if c.Tag == "" {
		return ""
	}
	return "-" + c.Tag
}

// MountCommand is the command Mount runs, for the record.
func (c *Client) MountCommand() string {
	mp := c.mountPoint()
	h := c.Host
	switch h.OS {
	case Linux:
		creds := "guest"
		if !c.Guest {
			creds = fmt.Sprintf("username=%s,password=%s", c.User, c.Pass)
		}
		opts := fmt.Sprintf("port=%d,%s,uid=$(id -u),gid=$(id -g),file_mode=0777,dir_mode=0777", c.Port, creds)
		if c.Vers != "" {
			opts += ",vers=" + c.Vers
		}
		if c.Options != "" {
			opts += "," + c.Options
		}
		return fmt.Sprintf(`sudo mkdir -p %s && sudo mount -t cifs //%s/%s %s -o %s`, h.Q(mp), c.ServerIP, c.Share, h.Q(mp), opts)
	case MacOS:
		// mount_smbfs takes an SMB URL and honours the port in it. Guest is the special "guest"
		// account with an empty password; -N suppresses the password prompt. A user may mount to a
		// directory it owns, so no sudo.
		url := fmt.Sprintf("//guest:@%s:%d/%s", c.ServerIP, c.Port, c.Share)
		if !c.Guest {
			url = fmt.Sprintf("//%s:%s@%s:%d/%s", c.User, c.Pass, c.ServerIP, c.Port, c.Share)
		}
		return fmt.Sprintf(`mkdir -p %s && mount_smbfs -N %s %s`, h.Q(mp), h.Q(url), h.Q(mp))
	default:
		creds := ""
		if !c.Guest {
			creds = fmt.Sprintf(` /USER:%s %s`, c.User, c.Pass)
		}
		return fmt.Sprintf(`net use %s \\%s\%s /TCPPORT:%d%s`, mp, c.ServerIP, c.Share, c.Port, creds)
	}
}

// TryMount mounts the share and returns the command's result instead of failing: for the rows
// where the mount is expected to be refused.
func (c *Client) TryMount() Result {
	c.Unmount()
	r := c.Host.Run(c.MountCommand(), 90*time.Second)
	if r.OK() {
		c.Root = c.mountPoint()
		if c.Host.OS == Windows {
			c.Root += `\`
		}
	}
	return r
}

// Mount mounts the share, after unmounting anything left at the mount point by an earlier run.
func (c *Client) Mount() error {
	r := c.TryMount()
	return r.Err("mount " + c.describe())
}

func (c *Client) describe() string {
	auth := "as " + c.User
	if c.Guest {
		auth = "as guest"
	}
	extra := ""
	if c.Vers != "" || c.Options != "" {
		extra = " (" + strings.Trim(c.Vers+" "+c.Options, " ") + ")"
	}
	return fmt.Sprintf("//%s:%d/%s %s on %s%s", c.ServerIP, c.Port, c.Share, auth, c.Host.Name, extra)
}

// Unmount unmounts the share (lazily or forcibly if it has to). Best effort.
func (c *Client) Unmount() {
	mp := c.mountPoint()
	h := c.Host
	switch h.OS {
	case Linux:
		h.RunLax(fmt.Sprintf(`if mountpoint -q %s; then sudo umount %s 2>/dev/null || sudo umount -f -l %s; fi; true`, h.Q(mp), h.Q(mp), h.Q(mp)), 60*time.Second)
	case MacOS:
		h.RunLax(fmt.Sprintf(`if /sbin/mount | grep -q " on %s "; then umount %s 2>/dev/null || diskutil unmount force %s >/dev/null 2>&1; fi; true`, mp, h.Q(mp), h.Q(mp)), 60*time.Second)
	default:
		h.RunLax(fmt.Sprintf(`net use %s /delete /yes 2>$null`, mp), 60*time.Second)
	}
	c.Root = ""
}

// ForceUnmountAll gets rid of every mount this harness has left on the host, even one whose server
// has gone away, without ever waiting on it (unmounting a wedged macOS mount can hang for minutes),
// and only ever under the harness's own mount-point prefix: the machines may carry their owner's
// SMB mounts, which are none of our business.
func ForceUnmountAll(h *Host) {
	switch h.OS {
	case Linux:
		h.RunLax(`for m in $(awk '$2 ~ "^/mnt/psmb-" {print $2}' /proc/mounts); do sudo umount -f -l "$m" 2>/dev/null; done; true`, 60*time.Second)
	case MacOS:
		prefix := h.Join(h.RigDir(), "mnt-")
		h.RunLax(fmt.Sprintf(`for m in $(/sbin/mount | awk '$3 ~ "^(/private)?%s" {print $3}'); do (/sbin/umount -f "$m" >/dev/null 2>&1 &); done; true`, prefix), 60*time.Second)
	default:
		h.RunLax(`foreach ($d in 'Z:','Y:','X:','W:','V:','U:','T:','S:','R:','Q:') { net use $d /delete /yes 2>$null }`, 60*time.Second)
	}
}

// SmbClient runs Samba's smbclient against the share with a script of its commands (Linux hosts
// only): a second SMB client implementation beside the kernel's.
func SmbClient(h *Host, serverIP string, port int, share, user, pass, script string, timeout time.Duration) Result {
	auth := fmt.Sprintf(`-U %s`, h.Q(user+"%"+pass))
	if user == "" {
		auth = "-N -U guest"
	}
	return h.Run(fmt.Sprintf(`smbclient //%s/%s -p %d %s -m SMB3 -c %s`, serverIP, share, port, auth, h.Q(script)), timeout)
}
