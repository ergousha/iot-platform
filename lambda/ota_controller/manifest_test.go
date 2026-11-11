package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func TestContractVectorVerifies(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/contract-v1/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	manifest := []byte(strings.TrimRight(string(read("manifest.json")), "\n"))
	key, _ := json.Marshal(map[string]string{"test": string(read("test-key.pub.pem"))})
	ring, err := ParseKeyring(string(key))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ring.Verify(manifest, string(read("manifest.sig")))
	if err != nil || id != "test" {
		t.Fatalf("verify: %q %v", id, err)
	}
	m, err := ParseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	image := read("app.bin")
	sum := sha256.Sum256(image)
	if m.Product != "vaktus" || m.Version != "0.9.0" || m.Size != int64(len(image)) || m.SHA256 != hexString(sum[:]) {
		t.Fatalf("manifest %+v", m)
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func TestManifestMustBeCanonical(t *testing.T) {
	good := `{"contract":1,"factory_sha256":"` + strings.Repeat("ab", 32) + `","product":"vaktus","sha256":"` + strings.Repeat("cd", 32) + `","size":5,"version":"0.9.2"}`
	if _, err := ParseManifest([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"spaced":      strings.ReplaceAll(good, ",", ", "),
		"unsorted":    strings.TrimSuffix(strings.Replace(good, `"contract":1,`, ``, 1), "}") + `,"contract":1}`,
		"newline":     good + "\n",
		"v prefix":    strings.Replace(good, `"0.9.2"`, `"v0.9.2"`, 1),
		"upper hex":   strings.Replace(good, strings.Repeat("cd", 32), strings.Repeat("CD", 32), 1),
		"contract 2":  strings.Replace(good, `"contract":1`, `"contract":2`, 1),
		"no product":  strings.Replace(good, `"product":"vaktus",`, ``, 1),
		"negative":    strings.Replace(good, `"size":5`, `"size":-5`, 1),
		"not an obj":  `[1]`,
		"two objects": good + good,
	} {
		if _, err := ParseManifest([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An additive field is fine, if canonical.
	extra := strings.Replace(good, `"product"`, `"note":"x","product"`, 1)
	if _, err := ParseManifest([]byte(extra)); err != nil {
		t.Errorf("additive field: %v", err)
	}
}

// testKey makes a signing key and its keyring entry.
func testKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func sign(t *testing.T, k *ecdsa.PrivateKey, msg []byte) string {
	t.Helper()
	d := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestKeyringPicksTheSigningKey(t *testing.T) {
	ka, pa := testKey(t)
	kb, pb := testKey(t)
	kc, _ := testKey(t)
	raw, _ := json.Marshal(map[string]string{"p-a": pa, "p-b": pb})
	ring, err := ParseKeyring(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("manifest")
	if id, err := ring.Verify(msg, sign(t, kb, msg)); err != nil || id != "p-b" {
		t.Fatalf("b: %q %v", id, err)
	}
	if id, err := ring.Verify(msg, sign(t, ka, msg)); err != nil || id != "p-a" {
		t.Fatalf("a: %q %v", id, err)
	}
	if _, err := ring.Verify(msg, sign(t, kc, msg)); err == nil {
		t.Fatal("foreign key verified")
	}
	if _, err := ring.Verify([]byte("other"), sign(t, ka, msg)); err == nil {
		t.Fatal("other message verified")
	}
	if _, err := ring.Verify(msg, "!!"); err == nil {
		t.Fatal("garbage verified")
	}
	for _, bad := range []string{`{}`, `not json`, `{"x":"not a pem"}`} {
		if _, err := ParseKeyring(bad); err == nil {
			t.Errorf("keyring %s accepted", bad)
		}
	}
}

func TestVersionsAndJobIDs(t *testing.T) {
	for in, want := range map[string]string{"0.9.1": "0.9.1", "v1.2.3": "1.2.3", "firmware_v0.4.0": "0.4.0"} {
		v, err := ParseVersion(in)
		if err != nil || v.String() != want {
			t.Errorf("%s: %v %v", in, v, err)
		}
	}
	for _, bad := range []string{"", "1.2", "01.2.3", "1.2.3-rc1", "latest", "v1.2.3.4"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	a, _ := ParseVersion("0.9.10")
	b, _ := ParseVersion("0.10.0")
	if !a.Less(b) || b.Less(a) || a.Less(a) {
		t.Error("ordering")
	}

	products := map[string]ProductConfig{"vaktus": {}, "gateway": {}}
	v, _ := ParseVersion("0.9.2")
	for _, j := range []JobID{
		{Product: "vaktus", Version: v, Kind: KindCanary},
		{Product: "vaktus", Version: v, Kind: KindCanary, Rerun: 2},
		{Product: "gateway", Version: v, Kind: KindFleet, Rerun: 1},
		{Product: "vaktus", Version: v, Kind: KindTarget, Thing: "38182B8456F4"},
		{Product: "vaktus", Version: v, Kind: KindTarget, Thing: "38182B8456F4", Rerun: 3},
	} {
		got, ok := ParseJobID(j.String(), products)
		if !ok || got != j || !j.Valid() {
			t.Errorf("%s: %+v %v", j, got, ok)
		}
	}
	if j, ok := ParseJobID("ota-gateway-firmware_v0-4-0-1730000000000", products); !ok || !j.Legacy {
		t.Errorf("legacy: %+v %v", j, ok)
	}
	for _, other := range []string{"ota-other-0_1_0-c", "manual-1", "ota-vaktus-0_1_0-x", "ota-vaktus-garbage"} {
		if _, ok := ParseJobID(other, products); ok {
			t.Errorf("%s parsed", other)
		}
	}
	used := map[string]bool{"ota-vaktus-0_9_2-f": true, "ota-vaktus-0_9_2-f-r1": true}
	if got := nextFree(JobID{Product: "vaktus", Version: v, Kind: KindFleet}, used).String(); got != "ota-vaktus-0_9_2-f-r2" {
		t.Errorf("nextFree: %s", got)
	}
}
