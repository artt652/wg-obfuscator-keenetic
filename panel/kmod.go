package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Built-in obfuscator: the patched wireguard.ko installed by the
// wgobfs bundle (/opt/lib/wgobfs, init script S05wgobfs).

const (
	kmodDir   = "/opt/lib/wgobfs"
	kmodVar   = "/opt/var/lib/wgobfs"
	kmodInit  = "/opt/etc/init.d/S05wgobfs"
	kmodState = "/tmp/wgobfs-swap"
	kmodMode  = kmodDir + "/wgobfs-mode.sh"
	kmodTun   = "/opt/etc/wgobfs-tunnels.conf"
)

type KmodTunnel struct {
	ID          string `json:"id"`
	Kernel      string `json:"kernel"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Connected   bool   `json:"connected"`
	UptimeSec   int64  `json:"uptimeSec"`
	// From the router configuration (I5).
	Wgobfs   bool   `json:"wgobfs"`
	Masking  string `json:"masking"`
	MaxDummy int    `json:"maxDummy"`
	Key      string `json:"key"`
	// From the module log: last "wg-obfuscator mode on/off" line.
	KernelMode string `json:"kernelMode"` // "on" | "off" | ""
	// Mode switching (wgobfs-mode.sh): "" = not managed.
	Mode      string `json:"mode"`      // auto | internal | external
	Section   string `json:"section"`   // linked wg-obfuscator section
	Effective string `json:"effective"` // internal | external
	Suggested string `json:"suggested"` // section whose port the endpoint points at
	PeerKey   string `json:"peerKey"`
	Endpoint  string `json:"endpoint"`
	Handshake int64  `json:"handshakeAgo"`
	Online    bool   `json:"online"`
	RxBytes   int64  `json:"rxBytes"`
	TxBytes   int64  `json:"txBytes"`
}

type KmodStatus struct {
	Installed      bool         `json:"installed"` // package wgobfs-kmod in /opt/lib/wgobfs
	Fits           bool         `json:"fits"`      // it has a module for this firmware
	Module         string       `json:"module"`    // patched | stock | other | none
	Srcversion     string       `json:"srcversion"`
	GenlID         int          `json:"genlId"`
	Autostart      string       `json:"autostart"` // enabled | disabled | none
	DisabledReason string       `json:"disabledReason"`
	KernelMatch    bool         `json:"kernelMatch"` // firmware kernel = the one enabled for
	Pending        bool         `json:"pending"`
	LastLog        []string     `json:"lastLog"`
	Tunnels        []KmodTunnel `json:"tunnels"`
	NdmcAvailable  bool         `json:"ndmcAvailable"`
	ModeTool       bool         `json:"modeTool"`
	Sections       []ObfSection `json:"sections"`
	Error          string       `json:"error,omitempty"`
}

type ObfSection struct {
	Name   string `json:"name"`
	Port   string `json:"port"`
	Target string `json:"target"`
}

type tunnelMode struct{ Mode, Section string }

func readTunnelModes() map[string]tunnelMode {
	res := map[string]tunnelMode{}
	b, err := os.ReadFile(kmodTun)
	if err != nil {
		return res
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && !strings.HasPrefix(f[0], "#") {
			res[f[0]] = tunnelMode{f[1], f[2]}
		}
	}
	return res
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

// runningConfigBlocks returns "interface WireguardN" blocks of the running
// configuration, keyed by interface name.
func runningConfigBlocks() (map[string]string, error) {
	out, err := ndmc("show running-config")
	if err != nil {
		return nil, err
	}
	blocks := map[string]string{}
	cur := ""
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "interface ") {
			if cur != "" {
				blocks[cur] = b.String()
			}
			cur = strings.TrimSpace(strings.TrimPrefix(l, "interface "))
			b.Reset()
			continue
		}
		if cur != "" {
			if l == "!" {
				blocks[cur] = b.String()
				cur = ""
				continue
			}
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	if cur != "" {
		blocks[cur] = b.String()
	}
	return blocks, nil
}

var reModeLine = regexp.MustCompile(`(nwg\d+): wg-obfuscator mode (on|off)`)

func kernelModes() map[string]string {
	res := map[string]string{}
	out, _ := run(5*time.Second, "dmesg")
	for _, m := range reModeLine.FindAllStringSubmatch(out, -1) {
		res[m[1]] = m[2] // later lines win
	}
	return res
}

func kmodStatus() KmodStatus {
	st := KmodStatus{
		Installed:     exists(kmodDir + "/wgobfs-swap.sh"),
		Fits:          exists(kmodDir + "/wireguard.ko"), // link to the module picked for this firmware
		NdmcAvailable: ndmcBinary() != "",
		Tunnels:       []KmodTunnel{},
		LastLog:       []string{},
	}
	switch {
	case !exists("/sys/module/wireguard"):
		st.Module = "none"
	case exists("/sys/module/wireguard/parameters/genl_id"):
		st.Module = "patched"
	default:
		// Without the genl_id parameter it is the firmware's own module,
		// whatever its revision.
		st.Module = "stock"
	}
	st.Srcversion = readTrim("/sys/module/wireguard/srcversion")
	if out, err := run(3*time.Second, kmodDir+"/genlid", "wireguard"); err == nil {
		st.GenlID, _ = strconv.Atoi(strings.TrimSpace(out))
	}
	switch {
	case !exists(kmodInit):
		st.Autostart = "none"
	case exists(kmodVar + "/disabled"):
		st.Autostart, st.DisabledReason = "disabled", readTrim(kmodVar+"/disabled")
	default:
		st.Autostart = "enabled"
	}
	st.KernelMatch = readTrim(kmodVar+"/kernel") != "" && readTrim(kmodVar+"/kernel") == readTrim("/proc/version")
	st.Pending = exists(kmodVar + "/pending")
	if l, _, err := tailFile(kmodVar+"/last.log", 20); err == nil && l != nil {
		st.LastLog = l
	}

	ifaces, err := rciWireguard()
	if err != nil {
		st.Error = "RCI: " + err.Error()
		return st
	}
	blocks, berr := runningConfigBlocks()
	if berr != nil {
		st.Error = "конфигурация роутера: " + berr.Error()
	}
	modes := kernelModes()
	st.ModeTool = exists(kmodMode)
	st.Sections = []ObfSection{}
	if b, err := os.ReadFile(defaultObfConfig); err == nil {
		list, _ := ParseObfConfig(string(b))
		for _, in := range list {
			st.Sections = append(st.Sections, ObfSection{in.Name, in.SourceLport, in.Target})
		}
	}
	tmodes := readTunnelModes()
	for _, i := range ifaces {
		t := KmodTunnel{ID: i.ID, Kernel: i.Kernel, Description: i.Description, Enabled: i.Enabled,
			Connected: i.Connected, UptimeSec: i.UptimeSec, KernelMode: modes[i.Kernel], Handshake: -1}
		if s, ok := ParseI5(blocks[i.ID]); ok {
			t.Wgobfs, t.Masking, t.MaxDummy, t.Key = true, s.Masking, s.MaxDummy, s.Key
		}
		if len(i.Peers) > 0 {
			p := i.Peers[0]
			t.PeerKey, t.Endpoint, t.Handshake, t.Online, t.RxBytes, t.TxBytes =
				p.PublicKey, p.Endpoint, p.HandshakeAgo, p.Online, p.RxBytes, p.TxBytes
		}
		if m, ok := tmodes[i.ID]; ok {
			t.Mode, t.Section = m.Mode, m.Section
			t.Effective = m.Mode
			if m.Mode == "auto" {
				t.Effective = "external"
				if st.Module == "patched" {
					t.Effective = "internal"
				}
			}
		}
		if h, p, err := net.SplitHostPort(t.Endpoint); err == nil && (h == "127.0.0.1" || h == "localhost") {
			for _, sec := range st.Sections {
				if sec.Port == p {
					t.Suggested = sec.Name
				}
			}
		}
		st.Tunnels = append(st.Tunnels, t)
	}
	return st
}

// --- actions ---------------------------------------------------------------

var kmodMu sync.Mutex

var reWGIface = regexp.MustCompile(`^Wireguard[0-9]{1,3}$`)

// ndmcOK runs CLI commands and treats an "error" in the reply as failure:
// ndmc does not always set its exit status.
func ndmcOK(cmds ...string) (string, error) {
	var all []string
	for _, c := range cmds {
		out, err := ndmc(c)
		all = append(all, out)
		if err == nil && strings.Contains(strings.ToLower(out), "error") {
			err = errors.New("роутер отклонил команду")
		}
		if err != nil {
			return strings.Join(all, "\n"), err
		}
	}
	return strings.Join(all, "\n"), nil
}

// ASC sets tried in turn: the router validates them itself, and with WGOB in
// I5 the module ignores all of them, so the first accepted one is fine.
var ascCandidates = []string{
	`0 0 0 0 0 1 2 3 4 0 0 "" "" "" ""`,
	`4 40 70 0 0 1 2 3 4 0 0 "" "" "" ""`,
	`3 10 50 15 20 100 200 300 400 0 0 "" "" "" ""`,
}

func setASC(iface, i5 string) (string, error) {
	var log []string
	for _, a := range ascCandidates {
		out, err := ndmcOK(fmt.Sprintf(`interface %s wireguard asc %s "%s"`, iface, a, i5))
		log = append(log, out)
		if err == nil {
			return strings.Join(log, "\n"), nil
		}
	}
	return strings.Join(log, "\n"), errors.New("роутер не принял параметры ASC")
}

type KmodApply struct {
	Iface    string `json:"iface"`
	Key      string `json:"key"`
	Masking  string `json:"masking"`
	MaxDummy int    `json:"maxDummy"`
	Endpoint string `json:"endpoint"` // server obfuscator host:port; empty = keep
}

func kmodEnable(req KmodApply) (string, error) {
	if !reWGIface.MatchString(req.Iface) {
		return "", errors.New("некорректное имя интерфейса")
	}
	i5, err := BuildI5(WgobSpec{Masking: req.Masking, MaxDummy: req.MaxDummy, Key: req.Key})
	if err != nil {
		return "", err
	}
	var peer string
	if req.Endpoint != "" {
		host, port, err := net.SplitHostPort(req.Endpoint)
		if p, _ := strconv.Atoi(port); err != nil || host == "" || p < 1 || p > 65535 ||
			strings.ContainsAny(host, " \"'") {
			return "", errors.New("адрес сервера: нужен адрес:порт")
		}
		ifaces, err := rciWireguard()
		if err != nil {
			return "", err
		}
		for _, i := range ifaces {
			if i.ID == req.Iface {
				if len(i.Peers) != 1 {
					return "", fmt.Errorf("у %s пиров: %d, нужен ровно один", req.Iface, len(i.Peers))
				}
				peer = i.Peers[0].PublicKey
			}
		}
		if peer == "" {
			return "", errors.New("туннель не найден")
		}
	}
	kmodMu.Lock()
	defer kmodMu.Unlock()
	out, err := setASC(req.Iface, i5)
	if err != nil {
		return out, err
	}
	if peer != "" {
		o, err := ndmcOK(fmt.Sprintf("interface %s wireguard peer %s endpoint %s", req.Iface, peer, req.Endpoint))
		out += "\n" + o
		if err != nil {
			return out, err
		}
	}
	o, err := ndmcOK("system configuration save")
	return out + "\n" + o, err
}

func kmodDisable(iface, endpoint string) (string, error) {
	if !reWGIface.MatchString(iface) {
		return "", errors.New("некорректное имя интерфейса")
	}
	kmodMu.Lock()
	defer kmodMu.Unlock()
	out, err := ndmcOK(fmt.Sprintf(`interface %s wireguard asc 0 0 0 0 0 1 2 3 4 0 0 "" "" "" "" ""`, iface))
	if err != nil {
		o, err2 := ndmcOK(fmt.Sprintf("interface %s no wireguard asc", iface))
		out += "\n" + o
		if err2 != nil {
			return out, errors.New("роутер не принял сброс I5")
		}
	}
	if endpoint != "" {
		ifaces, _ := rciWireguard()
		for _, i := range ifaces {
			if i.ID == iface && len(i.Peers) == 1 {
				o, err := ndmcOK(fmt.Sprintf("interface %s wireguard peer %s endpoint %s", iface, i.Peers[0].PublicKey, endpoint))
				out += "\n" + o
				if err != nil {
					return out, err
				}
			}
		}
	}
	o, err := ndmcOK("system configuration save")
	return out + "\n" + o, err
}

func kmodAutostart(enable bool) (string, error) {
	if !exists(kmodInit) {
		return "", errors.New("автозапуск не установлен")
	}
	act := "disable"
	if enable {
		act = "enable"
	}
	return run(15*time.Second, kmodInit, act)
}

func kmodSwap() (string, error) {
	if !exists(kmodDir + "/wireguard.ko") {
		return "", errors.New("модуль не установлен")
	}
	kmodMu.Lock()
	defer kmodMu.Unlock()
	return run(80*time.Second, "sh", kmodDir+"/wgobfs-swap.sh", "swap", kmodDir+"/wireguard.ko")
}

var reSection = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,60}$`)

func kmodSetMode(iface, mode, section string) (string, error) {
	if !reWGIface.MatchString(iface) {
		return "", errors.New("некорректное имя интерфейса")
	}
	switch mode {
	case "auto", "internal", "external":
		if !reSection.MatchString(section) {
			return "", errors.New("выберите секцию обфускатора")
		}
	case "off":
		section = ""
	default:
		return "", errors.New("режим: auto, internal, external или off")
	}
	if !exists(kmodMode) {
		return "", errors.New("переключение режимов не установлено (пакет wgobfs-kmod)")
	}
	kmodMu.Lock()
	defer kmodMu.Unlock()
	args := []string{kmodMode, "set", iface, mode}
	if section != "" {
		args = append(args, section)
	}
	return run(60*time.Second, "sh", args...)
}

// kmodReapply brings managed tunnels in line with the obfuscator config, e.g.
// a new key or server after the config was saved. No-op when nothing changed.
func kmodReapply() string {
	if !exists(kmodMode) || !exists(kmodTun) {
		return ""
	}
	kmodMu.Lock()
	defer kmodMu.Unlock()
	out, _ := run(60*time.Second, "sh", kmodMode, "apply")
	return out
}
