package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pbkdfIter   = 20000 // cheap enough for a MIPS router, still salted+stretched
	sessionTTL  = 12 * time.Hour
	cookieName  = "wgop_sess"
	csrfHeader  = "X-WGOP"
	maxFailures = 5
)

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2$sha256$%d$%s$%s", pbkdfIter, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

func checkPassword(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 5 || p[0] != "pbkdf2" || p[1] != "sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[2])
	if err != nil || iter < 1000 {
		return false
	}
	salt, err1 := hex.DecodeString(p[3])
	want, err2 := hex.DecodeString(p[4])
	if err1 != nil || err2 != nil {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// randomPassword avoids look-alike characters so it can be read off a terminal.
func randomPassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 12)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

type sessions struct {
	mu       sync.Mutex
	m        map[string]time.Time
	failures map[string][]time.Time
}

func newSessions() *sessions {
	return &sessions{m: map[string]time.Time{}, failures: map[string][]time.Time{}}
}

func (s *sessions) create() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, exp := range s.m {
		if now.After(exp) {
			delete(s.m, k)
		}
	}
	t := randomToken(32)
	s.m[t] = now.Add(sessionTTL)
	return t
}

func (s *sessions) valid(t string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[t]
	if !ok || time.Now().After(exp) {
		delete(s.m, t)
		return false
	}
	s.m[t] = time.Now().Add(sessionTTL)
	return true
}

func (s *sessions) drop(t string) {
	s.mu.Lock()
	delete(s.m, t)
	s.mu.Unlock()
}

func (s *sessions) dropAll() {
	s.mu.Lock()
	s.m = map[string]time.Time{}
	s.mu.Unlock()
}

// blocked reports whether ip had maxFailures failed logins in the last minute.
func (s *sessions) blocked(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-time.Minute)
	var keep []time.Time
	for _, t := range s.failures[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.failures[ip] = keep
	return len(keep) >= maxFailures
}

func (s *sessions) fail(ip string) {
	s.mu.Lock()
	s.failures[ip] = append(s.failures[ip], time.Now())
	s.mu.Unlock()
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
