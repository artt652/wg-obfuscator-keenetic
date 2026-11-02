package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var panelVersion = "dev"

//go:embed web
var webFS embed.FS

type Settings struct {
	Listen     string
	Password   string
	ObfConfig  string
	ObfInit    string
	ObfBin     string
	DefaultLog string
	path       string
	mu         sync.Mutex
}

func loadSettings(path string) (*Settings, error) {
	s := &Settings{
		Listen:     "0.0.0.0:8090",
		ObfConfig:  "/opt/etc/wg-obfuscator.conf",
		ObfInit:    "/opt/etc/init.d/S99wg-obfuscator",
		ObfBin:     "/opt/bin/wg-obfuscator",
		DefaultLog: "/opt/var/log/wg-obfuscator.log",
		path:       path,
	}
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "listen":
			s.Listen = v
		case "password":
			s.Password = v
		case "obf_config":
			s.ObfConfig = v
		case "obf_init":
			s.ObfInit = v
		case "obf_bin":
			s.ObfBin = v
		case "default_log":
			s.DefaultLog = v
		}
	}
	return s, sc.Err()
}

func (s *Settings) save() error {
	body := fmt.Sprintf(`# wg-obfuscator-panel settings
# Change the password with: wg-obfuscator-panel -passwd 'new password'
listen = %s
password = %s
obf_config = %s
obf_init = %s
obf_bin = %s
default_log = %s
`, s.Listen, s.Password, s.ObfConfig, s.ObfInit, s.ObfBin, s.DefaultLog)
	return writeFileAtomic(s.path, []byte(body), 0600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".wgop-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	tmp.Close()
	if err := os.Chmod(name, mode); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// lanAddress picks the KeeneticOS LAN bridge (br0) address so the panel is not
// exposed on WAN; falls back to all interfaces.
func lanAddress(port string) string {
	if ifc, err := net.InterfaceByName("br0"); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					return ipn.IP.String() + ":" + port
				}
			}
		}
	}
	return "0.0.0.0:" + port
}

func main() {
	cfgPath := flag.String("c", "/opt/etc/wg-obfuscator-panel.conf", "settings file")
	initFlag := flag.Bool("init", false, "create the settings file with a random password if it is missing, then exit")
	passwd := flag.String("passwd", "", "set a new panel password, then exit")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println("wg-obfuscator-panel", panelVersion)
		return
	}

	st, err := loadSettings(*cfgPath)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		log.Fatalf("settings: %v", err)
	}

	if *initFlag {
		if !missing && st.Password != "" {
			fmt.Println("Settings already exist:", *cfgPath)
			return
		}
		if missing {
			st.Listen = lanAddress("8090")
		}
		pw := randomPassword()
		if st.Password, err = hashPassword(pw); err != nil {
			log.Fatal(err)
		}
		if err := st.save(); err != nil {
			log.Fatalf("save settings: %v", err)
		}
		host := st.Listen
		if strings.HasPrefix(host, "0.0.0.0:") {
			host = "<IP роутера>:" + strings.TrimPrefix(host, "0.0.0.0:")
		}
		fmt.Printf("\n  Панель: http://%s\n  Пароль: %s\n  Сменить: wg-obfuscator-panel -passwd 'новый пароль'\n\n", host, pw)
		return
	}

	if *passwd != "" {
		if len(*passwd) < 6 {
			log.Fatal("пароль должен быть не короче 6 символов")
		}
		if st.Password, err = hashPassword(*passwd); err != nil {
			log.Fatal(err)
		}
		if err := st.save(); err != nil {
			log.Fatalf("save settings: %v", err)
		}
		fmt.Println("Пароль изменён. Перезапустите панель: /opt/etc/init.d/S98wg-obfuscator-panel restart")
		return
	}

	if missing || st.Password == "" {
		log.Fatalf("нет пароля: выполните wg-obfuscator-panel -init")
	}

	app := &App{st: st, sess: newSessions()}
	go watchTunnels()
	srv := &http.Server{
		Addr:              st.Listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	// At boot the LAN address may not be assigned yet: retry for a minute.
	var ln net.Listener
	for i := 0; i < 30; i++ {
		if ln, err = net.Listen("tcp", st.Listen); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("listen %s: %v", st.Listen, err)
	}
	log.Printf("wg-obfuscator-panel %s listening on %s", panelVersion, st.Listen)
	log.Fatal(srv.Serve(ln))
}

// --- HTTP ------------------------------------------------------------------

type App struct {
	st   *Settings
	sess *sessions
	cfgM sync.Mutex
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(sub))

	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.auth(a.logout))
	mux.HandleFunc("GET /api/status", a.auth(a.status))
	mux.HandleFunc("GET /api/config", a.auth(a.getConfig))
	mux.HandleFunc("POST /api/config", a.auth(a.saveConfig))
	mux.HandleFunc("POST /api/config/raw", a.auth(a.saveRaw))
	mux.HandleFunc("POST /api/config/parse", a.auth(a.parseText))
	mux.HandleFunc("POST /api/service", a.auth(a.service))
	mux.HandleFunc("GET /api/log", a.auth(a.getLog))
	mux.HandleFunc("POST /api/log/clear", a.auth(a.clearLog))
	mux.HandleFunc("POST /api/mtu", a.auth(a.mtu))
	mux.HandleFunc("POST /api/reconnect", a.auth(a.reconnect))
	mux.HandleFunc("POST /api/password", a.auth(a.changePassword))
	return secHeaders(mux)
}

func secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hd.Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

// auth requires a valid session; state-changing requests also need the custom
// header, which a cross-site form or image cannot send (CSRF protection).
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || !a.sess.valid(c.Value) {
			errJSON(w, http.StatusUnauthorized, "нужен вход")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get(csrfHeader) != "1" {
			errJSON(w, http.StatusForbidden, "запрос отклонён (CSRF)")
			return
		}
		next(w, r)
	}
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if r.Header.Get(csrfHeader) != "1" {
		errJSON(w, http.StatusForbidden, "запрос отклонён")
		return
	}
	if a.sess.blocked(ip) {
		errJSON(w, http.StatusTooManyRequests, "слишком много попыток, подождите минуту")
		return
	}
	var req struct{ Password string }
	if err := readJSON(r, &req); err != nil {
		errJSON(w, http.StatusBadRequest, "неверный запрос")
		return
	}
	a.st.mu.Lock()
	stored := a.st.Password
	a.st.mu.Unlock()
	if !checkPassword(stored, req.Password) {
		a.sess.fail(ip)
		time.Sleep(time.Second)
		errJSON(w, http.StatusUnauthorized, "неверный пароль")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: a.sess.create(), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.sess.drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Old, New string }
	if err := readJSON(r, &req); err != nil {
		errJSON(w, 400, "неверный запрос")
		return
	}
	a.st.mu.Lock()
	defer a.st.mu.Unlock()
	if !checkPassword(a.st.Password, req.Old) {
		time.Sleep(time.Second)
		errJSON(w, 403, "текущий пароль неверен")
		return
	}
	if len(req.New) < 6 {
		errJSON(w, 400, "новый пароль: минимум 6 символов")
		return
	}
	h, err := hashPassword(req.New)
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	old := a.st.Password
	a.st.Password = h
	if err := a.st.save(); err != nil {
		a.st.Password = old
		errJSON(w, 500, "не удалось сохранить: "+err.Error())
		return
	}
	a.sess.dropAll()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) readInstances() ([]*Instance, string, []FieldError, error) {
	b, err := os.ReadFile(a.st.ObfConfig)
	if err != nil {
		return nil, "", nil, err
	}
	list, perr := ParseObfConfig(string(b))
	return list, string(b), perr, nil
}

func (a *App) logPath(list []*Instance) string {
	for _, in := range list {
		if in.LogFile != "" {
			return in.LogFile
		}
	}
	return ""
}

func (a *App) status(w http.ResponseWriter, r *http.Request) {
	list, _, perr, err := a.readInstances()
	type instSum struct {
		Name, Listen, Target, Masking string
	}
	var sums []instSum
	for _, in := range list {
		listen := in.SourceIf
		if listen == "" {
			listen = "0.0.0.0"
		}
		m := in.Masking
		if m == "" {
			m = "AUTO"
		}
		sums = append(sums, instSum{in.Name, listen + ":" + in.SourceLport, in.Target, m})
	}
	resp := map[string]any{
		"ok":           true,
		"running":      false,
		"procs":        findProcs("wg-obfuscator"),
		"version":      obfVersion(a.st.ObfBin),
		"panelVersion": panelVersion,
		"instances":    sums,
		"configErrors": perr,
		"logFile":      a.logPath(list),
	}
	wg := wireguardStatus()
	markObfuscatorPeers(&wg, list)
	resp["wireguard"] = wg
	resp["running"] = len(resp["procs"].([]ProcInfo)) > 0
	if err != nil {
		resp["configError"] = err.Error()
	}
	writeJSON(w, 200, resp)
}

func (a *App) getConfig(w http.ResponseWriter, r *http.Request) {
	list, raw, perr, err := a.readInstances()
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, 200, map[string]any{"ok": true, "instances": []*Instance{}, "raw": "", "missing": true, "defaultLog": a.st.DefaultLog})
		return
	}
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	if list == nil {
		list = []*Instance{}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "instances": list, "raw": raw, "parseErrors": perr, "defaultLog": a.st.DefaultLog})
}

func (a *App) parseText(w http.ResponseWriter, r *http.Request) {
	var req struct{ Text string }
	if err := readJSON(r, &req); err != nil {
		errJSON(w, 400, "неверный запрос")
		return
	}
	list, perr := ParseObfConfig(req.Text)
	if list == nil {
		list = []*Instance{}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "instances": list, "parseErrors": perr})
}

func (a *App) saveConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Instances []*Instance `json:"instances"`
		Restart   bool        `json:"restart"`
	}
	if err := readJSON(r, &req); err != nil {
		errJSON(w, 400, "неверный запрос")
		return
	}
	for _, in := range req.Instances {
		in.Masking = strings.ToUpper(strings.TrimSpace(in.Masking))
		in.Verbose = normVerbose(in.Verbose)
		in.LogTimestamps = strings.ToUpper(strings.TrimSpace(in.LogTimestamps))
		var sb []string
		for _, b := range in.StaticBindings {
			if b = strings.TrimSpace(b); b != "" {
				sb = append(sb, b)
			}
		}
		in.StaticBindings = sb
	}
	if errs := Validate(req.Instances); len(errs) > 0 {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "проверьте поля", "fieldErrors": errs})
		return
	}
	a.apply(w, Serialize(req.Instances), req.Restart)
}

func (a *App) saveRaw(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text    string `json:"text"`
		Restart bool   `json:"restart"`
	}
	if err := readJSON(r, &req); err != nil {
		errJSON(w, 400, "неверный запрос")
		return
	}
	list, perr := ParseObfConfig(req.Text)
	errs := append(perr, Validate(list)...)
	if len(errs) > 0 {
		writeJSON(w, 400, map[string]any{"ok": false, "error": "в тексте есть ошибки", "fieldErrors": errs})
		return
	}
	text := req.Text
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	a.apply(w, text, req.Restart)
}

// apply writes the config (keeping a .bak), restarts if asked and rolls back
// automatically when the obfuscator does not come up with the new file.
func (a *App) apply(w http.ResponseWriter, text string, restart bool) {
	a.cfgM.Lock()
	defer a.cfgM.Unlock()
	path := a.st.ObfConfig
	old, oldErr := os.ReadFile(path)
	if oldErr == nil {
		if err := writeFileAtomic(path+".bak", old, 0600); err != nil {
			errJSON(w, 500, "не удалось создать резервную копию: "+err.Error())
			return
		}
	}
	list, _ := ParseObfConfig(text)
	if lp := a.logPath(list); lp != "" {
		os.MkdirAll(filepath.Dir(lp), 0755)
	}
	if err := writeFileAtomic(path, []byte(text), 0600); err != nil {
		errJSON(w, 500, "не удалось записать конфиг: "+err.Error())
		return
	}
	if !restart {
		writeJSON(w, 200, map[string]any{"ok": true, "restarted": false})
		return
	}
	out, _ := serviceAction(a.st.ObfInit, "restart")
	// A bad config makes the obfuscator exit right after start: give it a
	// moment, then require it to still be alive.
	time.Sleep(1500 * time.Millisecond)
	if len(findProcs("wg-obfuscator")) > 0 {
		writeJSON(w, 200, map[string]any{"ok": true, "restarted": true, "output": out})
		return
	}
	// Failed: collect evidence, restore the previous file, start it again.
	var logTail []string
	if lp := a.logPath(list); lp != "" {
		logTail, _, _ = tailFile(lp, 15)
	}
	resp := map[string]any{"ok": false, "error": "обфускатор не запустился с новым конфигом", "output": out, "log": logTail}
	if oldErr == nil {
		if err := writeFileAtomic(path, old, 0600); err == nil {
			out2, _ := serviceAction(a.st.ObfInit, "start")
			resp["rolledBack"] = true
			resp["rollbackOutput"] = out2
			resp["error"] = "обфускатор не запустился с новым конфигом — восстановлен предыдущий"
		}
	}
	writeJSON(w, 200, resp)
}

func (a *App) service(w http.ResponseWriter, r *http.Request) {
	var req struct{ Action string }
	if err := readJSON(r, &req); err != nil {
		errJSON(w, 400, "неверный запрос")
		return
	}
	out, err := serviceAction(a.st.ObfInit, req.Action)
	want := req.Action != "stop"
	running := waitRunning(want, 3*time.Second)
	ok := err == nil && running == want
	resp := map[string]any{"ok": ok, "running": running, "output": out}
	if !ok {
		resp["error"] = "действие не выполнено, смотрите журнал"
	}
	writeJSON(w, 200, resp)
}

func (a *App) getLog(w http.ResponseWriter, r *http.Request) {
	list, _, _, _ := a.readInstances()
	lp := a.logPath(list)
	if lp == "" {
		writeJSON(w, 200, map[string]any{"ok": true, "enabled": false, "lines": []string{}})
		return
	}
	n := 200
	fmt.Sscanf(r.URL.Query().Get("lines"), "%d", &n)
	if n < 10 {
		n = 10
	}
	if n > 2000 {
		n = 2000
	}
	lines, size, err := tailFile(lp, n)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, 200, map[string]any{"ok": true, "enabled": true, "path": lp, "lines": []string{}, "size": 0})
		return
	}
	if err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": true, "path": lp, "lines": lines, "size": size})
}

func (a *App) clearLog(w http.ResponseWriter, r *http.Request) {
	list, _, _, _ := a.readInstances()
	lp := a.logPath(list)
	if lp == "" {
		errJSON(w, 400, "запись журнала в файл не включена")
		return
	}
	// Truncate in place: the obfuscator keeps its O_APPEND descriptor.
	if err := os.Truncate(lp, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		errJSON(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) mtu(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface string
		MTU   int
	}
	if err := readJSON(r, &req); err != nil {
		errJSON(w, 400, "неверный запрос")
		return
	}
	out, err := setMTU(req.Iface, req.MTU)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "output": out})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": out})
}

func (a *App) reconnect(w http.ResponseWriter, r *http.Request) {
	var req struct{ Iface string }
	if err := readJSON(r, &req); err != nil {
		errJSON(w, 400, "неверный запрос")
		return
	}
	out, err := reconnectIface(req.Iface)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "output": out})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": out})
}
