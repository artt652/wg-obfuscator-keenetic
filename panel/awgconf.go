package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// The patched Keenetic WireGuard module (wireguard.ko with wg-obfuscator
// support) is switched on by the AmneziaWG I5 parameter:
//   <b 0x57474F42 VV MM DDDD KK..>
// "WGOB" magic, format version 01, masking 00 none / 01 STUN, max dummy
// bytes (big-endian), then the obfuscator key bytes.

const wgobMagic = "57474F42"

type WgobSpec struct {
	Masking  string `json:"masking"` // STUN | NONE
	MaxDummy int    `json:"maxDummy"`
	Key      string `json:"key"`
}

func checkObfKey(key string) error {
	switch {
	case key == "":
		return errors.New("ключ обязателен")
	case len(key) > 255:
		return errors.New("ключ длиннее 255 байт")
	case strings.ContainsAny(key, "#="):
		return errors.New("символы # и = в ключе недопустимы")
	case strings.TrimSpace(key) != key:
		return errors.New("пробелы в начале или конце ключа недопустимы")
	case strings.HasPrefix(key, "<") && strings.HasSuffix(key, ">"):
		return errors.New("укажите сам ключ, без < >")
	}
	return nil
}

// BuildI5 returns the I5 value for the given settings.
func BuildI5(s WgobSpec) (string, error) {
	if err := checkObfKey(s.Key); err != nil {
		return "", err
	}
	m := "00"
	switch strings.ToUpper(s.Masking) {
	case "STUN":
		m = "01"
	case "NONE", "":
	default:
		return "", errors.New("маскировка: STUN или NONE")
	}
	if s.MaxDummy < 0 || s.MaxDummy > 1024 {
		return "", errors.New("max-dummy: от 0 до 1024")
	}
	return fmt.Sprintf("<b 0x%s01%s%04X%s>", wgobMagic, m, s.MaxDummy,
		strings.ToUpper(hex.EncodeToString([]byte(s.Key)))), nil
}

var reWgob = regexp.MustCompile(`(?i)<b\s+0x` + wgobMagic + `([0-9a-f]*)>`)

// ParseI5 finds a WGOB value in text; ok is false when there is none.
func ParseI5(text string) (WgobSpec, bool) {
	m := reWgob.FindStringSubmatch(text)
	if m == nil {
		return WgobSpec{}, false
	}
	raw, err := hex.DecodeString(m[1])
	if err != nil || len(raw) < 5 || raw[0] != 1 || raw[1] > 1 {
		return WgobSpec{}, false
	}
	s := WgobSpec{Masking: "NONE", MaxDummy: int(raw[2])<<8 | int(raw[3]), Key: string(raw[4:])}
	if raw[1] == 1 {
		s.Masking = "STUN"
	}
	return s, true
}

// --- conversion of a wg-obfuscator client config to an AmneziaWG .conf ------

type AWGOptions struct {
	Jc, Jmin, Jmax int
	Masking        string // override; empty = from the obfuscator section
	MaxDummy       *int   // override
}

func DefaultAWGOptions() AWGOptions { return AWGOptions{Jc: 4, Jmin: 40, Jmax: 70} }

type AWGResult struct {
	Conf     string   `json:"conf"`
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint"`
	Masking  string   `json:"masking"`
	MaxDummy int      `json:"maxDummy"`
	Notes    []string `json:"notes"`
}

var awgKeys = map[string]bool{"jc": true, "jmin": true, "jmax": true, "s1": true, "s2": true,
	"s3": true, "s4": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true}

// ConvertToAWG takes what WireGuard Obfuscator Easy gives a client — the
// obfuscator section ([main] with target/key/masking) and the WireGuard
// config, pasted together in any order — and returns one AmneziaWG config:
// the peer goes straight to the server obfuscator, and I5 turns on the
// built-in obfuscator of the patched module.
func ConvertToAWG(text string, opt AWGOptions) (*AWGResult, error) {
	type line struct{ sec, raw, k, v string }
	var lines []line
	obf := map[string]string{}
	obfName := ""
	sec := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), "\r")
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			sec = strings.TrimSpace(t[1 : len(t)-1])
			switch strings.ToLower(sec) {
			case "interface", "peer":
				lines = append(lines, line{sec: sec, raw: t})
			default:
				if obfName == "" {
					obfName = sec
				}
			}
			continue
		}
		k, v := "", ""
		if t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, ";") {
			if a, b, ok := strings.Cut(t, "="); ok {
				k, v = strings.TrimSpace(a), strings.TrimSpace(b)
			}
		}
		ls := strings.ToLower(sec)
		if ls != "interface" && ls != "peer" {
			if k != "" && sec == obfName {
				if i := strings.IndexByte(v, '#'); i >= 0 { // obfuscator syntax: # starts a comment
					v = strings.TrimSpace(v[:i])
				}
				obf[strings.ToLower(k)] = v
			}
			continue
		}
		lines = append(lines, line{sec: sec, raw: raw, k: k, v: v})
	}

	target, key := obf["target"], obf["key"]
	if target == "" || key == "" {
		return nil, errors.New("не найдена секция обфускатора с target и key (например [main])")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return nil, fmt.Errorf("target %q: нужен адрес:порт", target)
	}
	if p, _ := strconv.Atoi(port); p < 1 || p > 65535 {
		return nil, fmt.Errorf("target %q: неверный порт", target)
	}
	res := &AWGResult{Name: obfName, Endpoint: target, Notes: []string{}}

	masking := strings.ToUpper(opt.Masking)
	if masking == "" {
		masking = strings.ToUpper(obf["masking"])
		if masking == "" || masking == "AUTO" {
			masking = "NONE"
			res.Notes = append(res.Notes, "masking не задан или AUTO: выбрано NONE (сервер с AUTO принимает и так)")
		}
	}
	dummy := 4
	if v, ok := obf["max-dummy"]; ok && v != "" {
		if dummy, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("max-dummy %q: нужно число", v)
		}
	}
	if opt.MaxDummy != nil {
		dummy = *opt.MaxDummy
	}
	i5, err := BuildI5(WgobSpec{Masking: masking, MaxDummy: dummy, Key: key})
	if err != nil {
		return nil, err
	}
	res.Masking, res.MaxDummy = masking, dummy

	var out []string
	haveIface, havePeer, endpointSet := false, false, false
	flushIface := func() {
		out = append(out,
			fmt.Sprintf("Jc = %d", opt.Jc), fmt.Sprintf("Jmin = %d", opt.Jmin), fmt.Sprintf("Jmax = %d", opt.Jmax),
			"S1 = 0", "S2 = 0", "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4",
			"I5 = "+i5)
	}
	inIface := false
	for _, l := range lines {
		if l.k == "" && strings.HasPrefix(l.raw, "[") {
			if inIface {
				flushIface()
				out = append(out, "")
			}
			inIface = strings.EqualFold(l.sec, "interface")
			if inIface {
				haveIface = true
			} else {
				havePeer = true
			}
			out = append(out, l.raw)
			continue
		}
		lk := strings.ToLower(l.k)
		if inIface && awgKeys[lk] {
			continue // replaced by ours
		}
		if strings.EqualFold(l.sec, "peer") && lk == "endpoint" {
			out = append(out, "Endpoint = "+target)
			endpointSet = true
			continue
		}
		if l.k == "" && strings.TrimSpace(l.raw) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(l.raw))
	}
	if inIface {
		flushIface()
	}
	if !haveIface || !havePeer {
		return nil, errors.New("не найдены секции [Interface] и [Peer] конфигурации WireGuard")
	}
	if !endpointSet {
		// Insert the endpoint at the end of the peer section.
		out = append(out, "Endpoint = "+target)
	}
	for _, l := range lines {
		if strings.EqualFold(l.sec, "peer") && strings.EqualFold(l.k, "AllowedIPs") {
			for _, n := range strings.Split(l.v, ",") {
				if _, cidr, err := net.ParseCIDR(strings.TrimSpace(n)); err == nil {
					if ip := net.ParseIP(host); ip != nil && cidr.Contains(ip) {
						res.Notes = append(res.Notes, "AllowedIPs включает адрес сервера "+host+
							": KeeneticOS сам направляет endpoint мимо туннеля, но проверьте, что связь есть")
						goto checked
					}
				}
			}
		}
	}
checked:
	res.Conf = strings.Join(out, "\n") + "\n"
	return res, nil
}
