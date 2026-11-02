package main

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Instance is one [section] of wg-obfuscator.conf (v1.6 syntax).
type Instance struct {
	Name            string   `json:"name"`
	SourceIf        string   `json:"sourceIf"`
	SourceLport     string   `json:"sourceLport"`
	Target          string   `json:"target"`
	Key             string   `json:"key"`
	Masking         string   `json:"masking"`
	Verbose         string   `json:"verbose"`
	LogFile         string   `json:"logFile"`
	LogTimestamps   string   `json:"logTimestamps"`
	MaxClients      string   `json:"maxClients"`
	IdleTimeout     string   `json:"idleTimeout"`
	InTimeout       string   `json:"inTimeout"`
	MaxDummy        string   `json:"maxDummy"`
	Fwmark          string   `json:"fwmark"`
	ResolveInterval string   `json:"resolveInterval"`
	AllowClean      bool     `json:"allowClean"`
	StaticBindings  []string `json:"staticBindings"`
	Extra           []KV     `json:"extra"` // legacy keys still accepted by v1.6 (source, target-if, target-lport)
}

type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

type FieldError struct {
	Instance string `json:"instance"`
	Field    string `json:"field"`
	Msg      string `json:"msg"`
}

// Keys accepted by the v1.6 config parser (config.c options table).
var knownKeys = map[string]bool{
	"source-if": true, "source": true, "source-lport": true, "target-if": true,
	"target": true, "target-lport": true, "key": true, "masking": true,
	"static-bindings": true, "max-clients": true, "idle-timeout": true,
	"in-timeout": true, "max-dummy": true, "fwmark": true, "allow-clean": true,
	"verbose": true, "log-file": true, "log-timestamps": true, "resolve-interval": true,
}

// ParseObfConfig mirrors config.c: '#' anywhere starts a comment, lines are
// trimmed, "[name]" opens a section, "key = value" split on the first '='.
func ParseObfConfig(text string) ([]*Instance, []FieldError) {
	var list []*Instance
	var errs []FieldError
	var cur *Instance
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = &Instance{Name: strings.TrimSpace(line[1 : len(line)-1])}
			list = append(list, cur)
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			errs = append(errs, FieldError{Field: "", Msg: fmt.Sprintf("строка %d: нет знака '=': %s", ln, line)})
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:eq]))
		v := strings.TrimSpace(line[eq+1:])
		if cur == nil {
			cur = &Instance{Name: "main"}
			list = append(list, cur)
		}
		if !knownKeys[k] {
			errs = append(errs, FieldError{Instance: cur.Name, Field: k, Msg: fmt.Sprintf("строка %d: неизвестный параметр «%s» — v1.6 с ним не запустится", ln, k)})
			continue
		}
		switch k {
		case "source-if":
			cur.SourceIf = v
		case "source-lport":
			cur.SourceLport = v
		case "target":
			cur.Target = v
		case "key":
			cur.Key = v
		case "masking":
			cur.Masking = strings.ToUpper(v)
		case "verbose":
			cur.Verbose = normVerbose(v)
		case "log-file":
			cur.LogFile = v
		case "log-timestamps":
			cur.LogTimestamps = strings.ToUpper(v)
		case "max-clients":
			cur.MaxClients = v
		case "idle-timeout":
			cur.IdleTimeout = v
		case "in-timeout":
			cur.InTimeout = v
		case "max-dummy":
			cur.MaxDummy = v
		case "fwmark":
			cur.Fwmark = v
		case "resolve-interval":
			cur.ResolveInterval = v
		case "allow-clean":
			cur.AllowClean = parseBool(v)
		case "static-bindings":
			for _, b := range strings.Split(v, ",") {
				if b = strings.TrimSpace(b); b != "" {
					cur.StaticBindings = append(cur.StaticBindings, b)
				}
			}
		default:
			cur.Extra = append(cur.Extra, KV{k, v})
		}
	}
	return list, errs
}

func parseBool(v string) bool {
	switch strings.ToLower(v) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

// normVerbose maps README spellings (ERRORS/WARNINGS) and numbers to what the
// v1.6 parser accepts (error/warn/info/debug/trace).
func normVerbose(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "error", "errors":
		return "ERROR"
	case "1", "warn", "warning", "warnings":
		return "WARN"
	case "2", "info":
		return "INFO"
	case "3", "debug":
		return "DEBUG"
	case "4", "trace":
		return "TRACE"
	}
	return strings.ToUpper(v)
}

var (
	reName    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,60}$`)
	reHost    = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	reBinding = regexp.MustCompile(`^(\d{1,3}(\.\d{1,3}){3}|[A-Za-z0-9.-]+):(\d{1,5}):(\d{1,5})$`)
	reIface   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

func badChars(s string) bool { return strings.ContainsAny(s, "#=\r\n") }

func checkPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

func checkInt(s string, min, max int64) bool {
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n >= min && n <= max
}

// Validate applies the same limits as config.c so a saved file always starts.
func Validate(list []*Instance) []FieldError {
	var errs []FieldError
	add := func(in *Instance, f, m string) { errs = append(errs, FieldError{in.Name, f, m}) }
	if len(list) == 0 {
		return []FieldError{{Msg: "нужен хотя бы один экземпляр"}}
	}
	seen := map[string]bool{}
	ports := map[string]string{}
	for _, in := range list {
		if !reName.MatchString(in.Name) {
			add(in, "name", "имя секции: латиница, цифры, _ . - (до 60 символов)")
		} else if seen[in.Name] {
			add(in, "name", "имя секции повторяется")
		}
		seen[in.Name] = true

		if in.SourceIf != "" && (badChars(in.SourceIf) || !reIface.MatchString(in.SourceIf)) {
			add(in, "sourceIf", "некорректный адрес/интерфейс")
		}
		if !checkPort(in.SourceLport) {
			add(in, "sourceLport", "порт 1–65535 обязателен")
		} else {
			if other, ok := ports[in.SourceLport]; ok {
				add(in, "sourceLport", "порт уже занят секцией «"+other+"»")
			}
			ports[in.SourceLport] = in.Name
		}
		if in.Target == "" {
			add(in, "target", "обязательно: адрес:порт")
		} else {
			i := strings.LastIndexByte(in.Target, ':')
			if i <= 0 || !reHost.MatchString(in.Target[:i]) || !checkPort(in.Target[i+1:]) {
				add(in, "target", "формат адрес:порт, например 203.0.113.5:17379")
			}
		}
		switch {
		case in.Key == "":
			add(in, "key", "ключ обязателен")
		case len(in.Key) > 255:
			add(in, "key", "ключ длиннее 255 символов")
		case badChars(in.Key):
			add(in, "key", "символы # и = в ключе недопустимы: парсер v1.6 их обрезает")
		case strings.TrimSpace(in.Key) != in.Key:
			add(in, "key", "пробелы в начале или конце ключа будут отброшены")
		}
		switch in.Masking {
		case "", "AUTO", "STUN", "NONE":
		default:
			add(in, "masking", "допустимо: AUTO, STUN, NONE")
		}
		switch in.Verbose {
		case "", "ERROR", "WARN", "INFO", "DEBUG", "TRACE":
		default:
			add(in, "verbose", "допустимо: ERROR, WARN, INFO, DEBUG, TRACE")
		}
		if in.LogFile != "" && (badChars(in.LogFile) || !strings.HasPrefix(in.LogFile, "/")) {
			add(in, "logFile", "нужен абсолютный путь без # и =")
		}
		switch in.LogTimestamps {
		case "", "AUTO", "TRUE", "FALSE":
		default:
			add(in, "logTimestamps", "допустимо: AUTO, TRUE, FALSE")
		}
		if in.MaxClients != "" && !checkInt(in.MaxClients, 1, 1<<31-1) {
			add(in, "maxClients", "целое больше 0")
		}
		if in.IdleTimeout != "" && !checkInt(in.IdleTimeout, 1, 1<<31-1) {
			add(in, "idleTimeout", "целое больше 0 (секунды)")
		}
		if in.InTimeout != "" && in.InTimeout != "0" && !checkInt(in.InTimeout, 1, 1<<31-1) {
			add(in, "inTimeout", "целое больше 0 (секунды), пусто — отключено")
		}
		if in.MaxDummy != "" && !checkInt(in.MaxDummy, 0, 1024) {
			add(in, "maxDummy", "целое 0–1024")
		}
		if in.ResolveInterval != "" && !checkInt(in.ResolveInterval, 0, 1<<31-1) {
			add(in, "resolveInterval", "целое 0 или больше (секунды)")
		}
		if in.Fwmark != "" {
			v, err := strconv.ParseInt(in.Fwmark, 0, 64)
			if err != nil || v <= 0 || v > 65535 {
				add(in, "fwmark", "1–65535 или 0x0001–0xFFFF")
			}
		}
		for _, b := range in.StaticBindings {
			m := reBinding.FindStringSubmatch(b)
			if m == nil || !checkPort(m[3]) || !checkPort(m[4]) {
				add(in, "staticBindings", "формат ip:порт_клиента:порт_пересылки — «"+b+"»")
			}
		}
		if in.AllowClean && len(in.StaticBindings) > 0 {
			add(in, "allowClean", "allow-clean несовместим со static-bindings")
		}
		for _, kv := range in.Extra {
			if !knownKeys[kv.K] || badChars(kv.V) || kv.V == "" {
				add(in, "extra", "некорректный параметр «"+kv.K+"»")
			}
		}
	}
	return errs
}

// Serialize writes only non-empty values; zero/empty in-timeout is omitted
// because v1.6 rejects "in-timeout = 0".
func Serialize(list []*Instance) string {
	var b strings.Builder
	b.WriteString("# wg-obfuscator configuration\n# Managed by wg-obfuscator-panel. Manual edits are kept as long as they are valid.\n")
	w := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	for _, in := range list {
		fmt.Fprintf(&b, "\n[%s]\n", in.Name)
		w("source-if", in.SourceIf)
		w("source-lport", in.SourceLport)
		w("target", in.Target)
		w("key", in.Key)
		w("masking", in.Masking)
		for _, sb := range in.StaticBindings {
			w("static-bindings", sb)
		}
		if in.AllowClean {
			w("allow-clean", "true")
		}
		w("verbose", in.Verbose)
		w("log-file", in.LogFile)
		w("log-timestamps", in.LogTimestamps)
		w("max-clients", in.MaxClients)
		w("idle-timeout", in.IdleTimeout)
		if in.InTimeout != "0" {
			w("in-timeout", in.InTimeout)
		}
		w("max-dummy", in.MaxDummy)
		w("fwmark", in.Fwmark)
		w("resolve-interval", in.ResolveInterval)
		for _, kv := range in.Extra {
			w(kv.K, kv.V)
		}
	}
	return b.String()
}
