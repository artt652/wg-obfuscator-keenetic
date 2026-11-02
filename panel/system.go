package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// run executes a command with a timeout. WaitDelay stops a daemon that
// inherited our pipes from blocking the call.
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = append(os.Environ(), "PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("таймаут %s", timeout)
	}
	return stripANSI(out.String()), err
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func stripANSI(s string) string { return strings.TrimSpace(ansiRe.ReplaceAllString(s, "")) }

// --- processes -------------------------------------------------------------

type ProcInfo struct {
	PID       int   `json:"pid"`
	UptimeSec int64 `json:"uptimeSec"`
}

// findProcs scans /proc for processes whose comm equals name.
func findProcs(name string) []ProcInfo {
	res := []ProcInfo{}
	ents, _ := os.ReadDir("/proc")
	sysUp := readUptime()
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != name {
			continue
		}
		pi := ProcInfo{PID: pid}
		if st, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat")); err == nil {
			// fields after ") " : state is field 3, starttime is field 22
			s := string(st)
			if i := strings.LastIndexByte(s, ')'); i > 0 {
				f := strings.Fields(s[i+1:])
				if len(f) > 19 {
					if start, err := strconv.ParseFloat(f[19], 64); err == nil && sysUp > 0 {
						pi.UptimeSec = int64(sysUp - start/100) // USER_HZ is 100 on Linux/MIPS
					}
				}
			}
		}
		res = append(res, pi)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].PID < res[j].PID })
	return res
}

// waitRunning polls until the obfuscator's running state equals want or the
// timeout passes, and returns the last observed state.
func waitRunning(want bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		running := len(findProcs("wg-obfuscator")) > 0
		if running == want || time.Now().After(deadline) {
			return running
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func readUptime() float64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// --- service ---------------------------------------------------------------

var svcMu sync.Mutex

func serviceAction(initScript, action string) (string, error) {
	switch action {
	case "start", "stop", "restart":
	default:
		return "", errors.New("неизвестное действие")
	}
	svcMu.Lock()
	defer svcMu.Unlock()
	return run(40*time.Second, initScript, action)
}

var (
	versionOnce sync.Once
	versionStr  string
	verRe       = regexp.MustCompile(`v(\d+(\.\d+)+[\w.-]*)`)
)

func obfVersion(bin string) string {
	versionOnce.Do(func() {
		out, _ := run(5*time.Second, bin, "--help")
		if m := verRe.FindStringSubmatch(out); m != nil {
			versionStr = m[1]
		}
	})
	return versionStr
}

// --- log -------------------------------------------------------------------

// tailFile returns the last n lines, reading at most 512 KiB from the end.
func tailFile(path string, n int) ([]string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := st.Size()
	const maxRead = 512 * 1024
	off := size - maxRead
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, size, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, size, err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // first line is probably cut
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	return lines, size, nil
}

// --- WireGuard -------------------------------------------------------------

type WGPeer struct {
	PublicKey     string `json:"publicKey"`
	Description   string `json:"description"`
	Endpoint      string `json:"endpoint"`
	RemotePort    int    `json:"remotePort"`
	Via           string `json:"via"`
	HandshakeAgo  int64  `json:"handshakeAgo"` // seconds since last handshake, -1 = never
	RxBytes       int64  `json:"rxBytes"`
	TxBytes       int64  `json:"txBytes"`
	Online        bool   `json:"online"`
	Enabled       bool   `json:"enabled"`
	Keepalive     string `json:"keepalive"`
	ViaObfuscator string `json:"viaObfuscator"` // obfuscator section this peer points at
}

type WGIface struct {
	ID          string   `json:"id"`          // KeeneticOS name, e.g. Wireguard0
	Kernel      string   `json:"kernel"`      // kernel name, e.g. nwg0
	Description string   `json:"description"` // name given in the KeeneticOS web UI
	MTU         int      `json:"mtu"`
	Enabled     bool     `json:"enabled"`    // administratively up
	Connected   bool     `json:"connected"`  // link established
	UptimeSec   int64    `json:"uptimeSec"`  // 0 = unknown or not connected
	UptimeFrom  string   `json:"uptimeFrom"` // "router" or "panel"
	UptimeMin   bool     `json:"uptimeMin"`  // panel saw it already up: "at least"
	Peers       []WGPeer `json:"peers"`
}

type WGStatus struct {
	Source         string    `json:"source"` // rci | wg | sysfs
	ToolsInstalled bool      `json:"toolsInstalled"`
	NdmcAvailable  bool      `json:"ndmcAvailable"`
	Interfaces     []WGIface `json:"interfaces"`
	Error          string    `json:"error,omitempty"`
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func wgBinary() string {
	return firstExisting("/opt/bin/wg", "/opt/sbin/wg", "/usr/bin/wg", "/usr/sbin/wg")
}
func ndmcBinary() string { return firstExisting("/bin/ndmc", "/usr/bin/ndmc", "/sbin/ndmc") }

var nwgRe = regexp.MustCompile(`^nwg(\d+)$`)

// ndmName maps KeeneticOS kernel names (nwgN) to CLI names (WireguardN).
func ndmName(kernel string) string {
	if m := nwgRe.FindStringSubmatch(kernel); m != nil {
		return "Wireguard" + m[1]
	}
	return ""
}

func readIfaceInfo(name string) (mtu int, up bool) {
	if b, err := os.ReadFile("/sys/class/net/" + name + "/mtu"); err == nil {
		mtu, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if b, err := os.ReadFile("/sys/class/net/" + name + "/operstate"); err == nil {
		s := strings.TrimSpace(string(b))
		up = s == "up" || s == "unknown" // WireGuard reports "unknown" when up
	}
	if b, err := os.ReadFile("/sys/class/net/" + name + "/flags"); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 0, 64); err == nil {
			up = up && v&1 == 1
		}
	}
	return
}

// --- KeeneticOS RCI (http://127.0.0.1:79/rci), reachable only on the router.

const rciBase = "http://127.0.0.1:79/rci"

var rciClient = &http.Client{Timeout: 4 * time.Second}

type rciPeer struct {
	PublicKey   string `json:"public-key"`
	Description string `json:"description"`
	RemotePort  int    `json:"remote-port"`
	Via         string `json:"via"`
	RemoteAddr  string `json:"remote-endpoint-address"`
	RxBytes     int64  `json:"rxbytes"`
	TxBytes     int64  `json:"txbytes"`
	LastHS      int64  `json:"last-handshake"`
	Online      bool   `json:"online"`
	Enabled     *bool  `json:"enabled"`
}

type rciIface struct {
	ID          string `json:"id"`
	Index       int    `json:"index"`
	Type        string `json:"type"`
	Description string `json:"description"`
	State       string `json:"state"`
	Link        string `json:"link"`
	Connected   string `json:"connected"`
	MTU         int    `json:"mtu"`
	Uptime      *int64 `json:"uptime"`
	Wireguard   *struct {
		Peer []rciPeer `json:"peer"`
	} `json:"wireguard"`
}

// handshakeAgo normalises KeeneticOS last-handshake: INT32_MAX means never,
// small values are seconds ago; a Unix timestamp is converted just in case.
func handshakeAgo(v int64) int64 {
	switch {
	case v < 0 || v >= 2147483647:
		return -1
	case v > 1_000_000_000:
		if d := time.Now().Unix() - v; d >= 0 {
			return d
		}
		return 0
	}
	return v
}

func rciWireguard() ([]WGIface, error) {
	resp, err := rciClient.Get(rciBase + "/show/interface")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RCI: HTTP %d", resp.StatusCode)
	}
	var all map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&all); err != nil {
		return nil, fmt.Errorf("RCI: %v", err)
	}
	var list []rciIface
	for _, raw := range all {
		var ri rciIface
		if json.Unmarshal(raw, &ri) != nil || !strings.EqualFold(ri.Type, "Wireguard") {
			continue
		}
		list = append(list, ri)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Index < list[j].Index })
	res := []WGIface{}
	for _, ri := range list {
		w := WGIface{
			ID:          ri.ID,
			Kernel:      "nwg" + strconv.Itoa(ri.Index),
			Description: ri.Description,
			MTU:         ri.MTU,
			Enabled:     ri.State == "up",
			Connected:   ri.Connected == "yes" || ri.Link == "up",
			Peers:       []WGPeer{},
		}
		if w.Connected && ri.Uptime != nil && *ri.Uptime > 0 {
			w.UptimeSec, w.UptimeFrom = *ri.Uptime, "router"
		}
		if ri.Wireguard != nil {
			for _, p := range ri.Wireguard.Peer {
				ep := ""
				if p.RemoteAddr != "" && p.RemoteAddr != "0.0.0.0" {
					ep = fmt.Sprintf("%s:%d", p.RemoteAddr, p.RemotePort)
				}
				w.Peers = append(w.Peers, WGPeer{
					PublicKey: p.PublicKey, Description: p.Description, Endpoint: ep,
					RemotePort: p.RemotePort, Via: p.Via, HandshakeAgo: handshakeAgo(p.LastHS),
					RxBytes: p.RxBytes, TxBytes: p.TxBytes, Online: p.Online,
					Enabled: p.Enabled == nil || *p.Enabled,
				})
			}
		}
		res = append(res, w)
	}
	return res, nil
}

// wgToolsStatus is the fallback off KeeneticOS: wireguard-tools, then sysfs.
func wgToolsStatus(st *WGStatus) {
	byName := map[string]*WGIface{}
	var order []string
	add := func(name string) *WGIface {
		if i, ok := byName[name]; ok {
			return i
		}
		mtu, up := readIfaceInfo(name)
		i := &WGIface{ID: ndmName(name), Kernel: name, MTU: mtu, Enabled: up, Connected: up, Peers: []WGPeer{}}
		byName[name] = i
		order = append(order, name)
		return i
	}
	st.Source = "sysfs"
	if wg := wgBinary(); wg != "" {
		st.ToolsInstalled = true
		st.Source = "wg"
		out, err := run(5*time.Second, wg, "show", "all", "dump")
		if err != nil {
			st.Error = out
		}
		now := time.Now().Unix()
		for _, line := range strings.Split(out, "\n") {
			f := strings.Split(line, "\t")
			switch len(f) {
			case 5: // interface line: never expose the private key
				add(f[0])
			case 9:
				i := add(f[0])
				hs, _ := strconv.ParseInt(f[5], 10, 64)
				rx, _ := strconv.ParseInt(f[6], 10, 64)
				tx, _ := strconv.ParseInt(f[7], 10, 64)
				ago := int64(-1)
				if hs > 0 {
					ago = now - hs
				}
				ep := f[3]
				if ep == "(none)" {
					ep = ""
				}
				port := 0
				if k := strings.LastIndexByte(ep, ':'); k > 0 {
					port, _ = strconv.Atoi(ep[k+1:])
				}
				ka := f[8]
				if ka == "off" {
					ka = ""
				}
				i.Peers = append(i.Peers, WGPeer{PublicKey: f[1], Endpoint: ep, RemotePort: port, HandshakeAgo: ago,
					RxBytes: rx, TxBytes: tx, Online: ago >= 0 && ago < 180, Enabled: true, Keepalive: ka})
			}
		}
	} else if ents, err := os.ReadDir("/sys/class/net"); err == nil {
		// Without tools only list interfaces that are up: KeeneticOS keeps
		// idle nwg0..nwg7 devices around.
		for _, e := range ents {
			n := e.Name()
			if nwgRe.MatchString(n) || strings.HasPrefix(n, "wg") {
				if _, up := readIfaceInfo(n); up {
					add(n)
				}
			}
		}
	}
	for _, n := range order {
		st.Interfaces = append(st.Interfaces, *byName[n])
	}
}

func wireguardStatus() WGStatus {
	st := WGStatus{NdmcAvailable: ndmcBinary() != "", ToolsInstalled: wgBinary() != ""}
	if list, err := rciWireguard(); err == nil {
		st.Source = "rci"
		st.Interfaces = list
	} else {
		wgToolsStatus(&st)
	}
	if st.Interfaces == nil {
		st.Interfaces = []WGIface{}
	}
	trackUptime(st.Interfaces)
	return st
}

// Uptime tracking for when the router does not report it: remember when a
// tunnel was first seen connected. A tunnel already up at the panel's first
// look gets UptimeMin, because it may have been up for longer.
var upTrack = struct {
	sync.Mutex
	since   map[string]time.Time
	atLeast map[string]bool
	started bool
}{since: map[string]time.Time{}, atLeast: map[string]bool{}}

func trackUptime(list []WGIface) {
	upTrack.Lock()
	defer upTrack.Unlock()
	now := time.Now()
	first := !upTrack.started
	upTrack.started = true
	seen := map[string]bool{}
	for i := range list {
		w := &list[i]
		key := w.Kernel + "|" + w.ID
		seen[key] = true
		if !w.Connected {
			delete(upTrack.since, key)
			delete(upTrack.atLeast, key)
			continue
		}
		t, ok := upTrack.since[key]
		if !ok {
			t = now
			upTrack.since[key] = t
			upTrack.atLeast[key] = first
		}
		if w.UptimeFrom == "" {
			w.UptimeSec = int64(now.Sub(t).Seconds())
			w.UptimeFrom = "panel"
			w.UptimeMin = upTrack.atLeast[key]
		}
	}
	for k := range upTrack.since {
		if !seen[k] {
			delete(upTrack.since, k)
			delete(upTrack.atLeast, k)
		}
	}
}

// watchTunnels keeps uptime tracking current even when nobody has the panel open.
func watchTunnels() {
	for {
		wireguardStatus()
		time.Sleep(20 * time.Second)
	}
}

// markObfuscatorPeers tags peers whose endpoint is a local obfuscator port.
func markObfuscatorPeers(st *WGStatus, list []*Instance) {
	for i := range st.Interfaces {
		for j := range st.Interfaces[i].Peers {
			p := &st.Interfaces[i].Peers[j]
			host := ""
			if k := strings.LastIndexByte(p.Endpoint, ':'); k > 0 {
				host = p.Endpoint[:k]
			}
			if host != "" && host != "127.0.0.1" && host != "localhost" {
				continue
			}
			for _, in := range list {
				if strconv.Itoa(p.RemotePort) == in.SourceLport {
					p.ViaObfuscator = in.Name
					break
				}
			}
		}
	}
}

var reNDMIface = regexp.MustCompile(`^[A-Za-z]+[0-9]{1,3}$`)

func ndmc(cmds ...string) (string, error) {
	bin := ndmcBinary()
	if bin == "" {
		return "", errors.New("ndmc не найден: команда доступна только на KeeneticOS")
	}
	var all []string
	for _, c := range cmds {
		out, err := run(15*time.Second, bin, "-c", c)
		all = append(all, "> "+c, out)
		if err != nil {
			return strings.Join(all, "\n"), err
		}
	}
	return strings.Join(all, "\n"), nil
}

func setMTU(iface string, mtu int) (string, error) {
	if !reNDMIface.MatchString(iface) {
		return "", errors.New("некорректное имя интерфейса KeeneticOS")
	}
	if mtu < 1000 || mtu > 1500 {
		return "", errors.New("MTU должен быть в диапазоне 1000–1500")
	}
	return ndmc(fmt.Sprintf("interface %s ip mtu %d", iface, mtu), "system configuration save")
}

func reconnectIface(iface string) (string, error) {
	if !reNDMIface.MatchString(iface) {
		return "", errors.New("некорректное имя интерфейса KeeneticOS")
	}
	out1, err := ndmc(fmt.Sprintf("interface %s down", iface))
	if err != nil {
		return out1, err
	}
	time.Sleep(2 * time.Second)
	out2, err := ndmc(fmt.Sprintf("interface %s up", iface))
	return out1 + "\n" + out2, err
}
