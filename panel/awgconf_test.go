package main

import (
	"strings"
	"testing"
)

const easySample = `[main]
source-lport = 13255
target = 203.0.113.5:17379
key = testKey123
masking = STUN

[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.6.13.3/32
DNS = 1.1.1.1
Jc = 9

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 127.0.0.1:13255
AllowedIPs = 0.0.0.0/2, 64.0.0.0/4
PersistentKeepalive = 25
`

func TestBuildParseI5(t *testing.T) {
	i5, err := BuildI5(WgobSpec{Masking: "STUN", MaxDummy: 4, Key: "K3y!"})
	if err != nil || i5 != "<b 0x57474F42010100044B337921>" {
		t.Fatalf("got %q %v", i5, err)
	}
	s, ok := ParseI5(`wireguard asc 0 0 "" "<b 0x57474f42010100044b337921>"`)
	if !ok || s.Masking != "STUN" || s.MaxDummy != 4 || s.Key != "K3y!" {
		t.Fatalf("parse: %+v %v", s, ok)
	}
	if _, ok := ParseI5(`<b 0x1234>`); ok {
		t.Fatal("non-WGOB accepted")
	}
	for _, bad := range []string{"", "a#b", "a=b", " a", "<abc>"} {
		if _, err := BuildI5(WgobSpec{Key: bad}); err == nil {
			t.Fatalf("key %q accepted", bad)
		}
	}
}

func TestConvertToAWG(t *testing.T) {
	r, err := ConvertToAWG(easySample, DefaultAWGOptions())
	if err != nil {
		t.Fatal(err)
	}
	c := r.Conf
	for _, want := range []string{
		"Endpoint = 203.0.113.5:17379",
		"I5 = <b 0x57474F4201010004746573744B6579313233>",
		"Jc = 4", "PersistentKeepalive = 25", "AllowedIPs = 0.0.0.0/2, 64.0.0.0/4",
		"Address = 10.6.13.3/32",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q in:\n%s", want, c)
		}
	}
	if strings.Contains(c, "Jc = 9") || strings.Contains(c, "127.0.0.1") || strings.Contains(c, "[main]") {
		t.Errorf("leftovers in:\n%s", c)
	}
	if strings.Index(c, "I5 =") > strings.Index(c, "[Peer]") {
		t.Errorf("I5 must be in [Interface]:\n%s", c)
	}
	// WireGuard part first, obfuscator section last.
	swapped := easySample[strings.Index(easySample, "[Interface]"):] + "\n" + easySample[:strings.Index(easySample, "[Interface]")]
	r2, err := ConvertToAWG(swapped, DefaultAWGOptions())
	if err != nil || r2.Endpoint != r.Endpoint || !strings.Contains(r2.Conf, "I5 = ") {
		t.Fatalf("swapped order: %v\n%s", err, r2.Conf)
	}
	if _, err := ConvertToAWG("[Interface]\n[Peer]\n", DefaultAWGOptions()); err == nil {
		t.Fatal("missing obfuscator section accepted")
	}
}
