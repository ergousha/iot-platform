package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// manifestContract is the manifest contract this controller verifies
// (iot-device-sdk iot-jobs/src/manifest.rs, contract/v1).
const manifestContract = 1

// Manifest is a release's signed manifest:
//
//	{"contract":1,"factory_sha256":"<hex>","product":"vaktus","sha256":"<hex>","size":1462304,"version":"0.9.0"}
//
// canonical JSON (keys sorted bytewise, no whitespace), signed as
// base64(DER(ECDSA-P256-SHA256(bytes))). It binds product and version, so a
// renamed old image or another product's image is refused.
type Manifest struct {
	Contract      int64
	Product       string
	Version       string
	SHA256        string
	Size          int64
	FactorySHA256 string
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseManifest parses bytes that must be the canonical encoding. Unknown
// fields are tolerated (the contract grows additively; the signature and the
// canonical check cover them), exactly as the device does.
func ParseManifest(b []byte) (Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return Manifest{}, fmt.Errorf("manifest is not a JSON object: %w", err)
	}
	if dec.More() {
		return Manifest{}, errors.New("manifest has trailing data")
	}
	if c, err := canonicalJSON(v); err != nil || !bytes.Equal(c, b) {
		return Manifest{}, errors.New("manifest is not in canonical form")
	}
	text := func(k string) (string, error) {
		s, ok := v[k].(string)
		if !ok {
			return "", fmt.Errorf("manifest has no %s", k)
		}
		return s, nil
	}
	number := func(k string) (int64, error) {
		n, ok := v[k].(json.Number)
		if !ok {
			return 0, fmt.Errorf("manifest has no %s", k)
		}
		i, err := n.Int64()
		if err != nil || i < 0 {
			return 0, fmt.Errorf("manifest %s is not a non-negative integer", k)
		}
		return i, nil
	}
	var m Manifest
	var errs []error
	var err error
	if m.Contract, err = number("contract"); err != nil {
		errs = append(errs, err)
	} else if m.Contract != manifestContract {
		errs = append(errs, fmt.Errorf("manifest contract %d; this controller verifies %d", m.Contract, manifestContract))
	}
	if m.Product, err = text("product"); err != nil {
		errs = append(errs, err)
	}
	if m.Version, err = text("version"); err != nil {
		errs = append(errs, err)
	} else if ver, perr := ParseVersion(m.Version); perr != nil || ver.String() != m.Version {
		errs = append(errs, fmt.Errorf("manifest version %q is not bare X.Y.Z", m.Version))
	}
	if m.SHA256, err = text("sha256"); err != nil {
		errs = append(errs, err)
	} else if !sha256Hex.MatchString(m.SHA256) {
		errs = append(errs, errors.New("manifest sha256 is not lowercase hex"))
	}
	if m.FactorySHA256, err = text("factory_sha256"); err != nil {
		errs = append(errs, err)
	} else if !sha256Hex.MatchString(m.FactorySHA256) {
		errs = append(errs, errors.New("manifest factory_sha256 is not lowercase hex"))
	}
	if m.Size, err = number("size"); err != nil {
		errs = append(errs, err)
	}
	return m, errors.Join(errs...)
}

// canonicalJSON encodes v with object keys sorted bytewise at every level and
// no whitespace, the encoding the device and the release workflow use.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // Go compares strings bytewise
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeScalar(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return writeScalar(buf, t)
	}
	return nil
}

func writeScalar(buf *bytes.Buffer, v any) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false) // serde_json does not escape <, > and &
	if err := enc.Encode(v); err != nil {
		return err
	}
	buf.Truncate(buf.Len() - 1) // Encode appends a newline
	return nil
}

// Keyring is a product's firmware-signing public keys by key id, as SSM
// /iot-platform/products/<p>/signing_keys holds them: a JSON object of key id
// to SubjectPublicKeyInfo PEM.
type Keyring map[string]*ecdsa.PublicKey

// ParseKeyring parses the SSM parameter value.
func ParseKeyring(value string) (Keyring, error) {
	var raw map[string]string
	if err := json.Unmarshal([]byte(value), &raw); err != nil {
		return nil, fmt.Errorf("signing keys are not a JSON object of key id to PEM: %w", err)
	}
	ring := Keyring{}
	for id, p := range raw {
		block, _ := pem.Decode([]byte(strings.TrimSpace(p)))
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("signing key %s is not a PUBLIC KEY PEM", id)
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		ec, ok := key.(*ecdsa.PublicKey)
		if err != nil || !ok || ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("signing key %s is not a P-256 public key", id)
		}
		ring[id] = ec
	}
	if len(ring) == 0 {
		return nil, errors.New("no signing keys")
	}
	return ring, nil
}

// Verify checks sigB64 over message with every key, in key id order, and
// returns the id of the key that made it.
func (k Keyring) Verify(message []byte, sigB64 string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return "", errors.New("the signature is not base64")
	}
	digest := sha256.Sum256(message)
	ids := make([]string, 0, len(k))
	for id := range k {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if ecdsa.VerifyASN1(k[id], digest[:], der) {
			return id, nil
		}
	}
	return "", fmt.Errorf("the signature verifies with none of %s", strings.Join(ids, ", "))
}
