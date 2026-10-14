package ingest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"
	"strings"
)

// sshsigNamespace is the namespace git signs commits in (gpg.ssh, `-n git`).
// A signature made for another namespace, a file signed with `ssh-keygen -Y
// sign -n file` pasted into a commit, does not vouch for the commit.
const sshsigNamespace = "git"

// minRSABits is the smallest RSA modulus a signature is accepted from; ssh-keygen
// refuses to make smaller keys.
const minRSABits = 1024

// sshSignature is a decoded SSHSIG blob (PROTOCOL.sshsig in OpenSSH).
type sshSignature struct {
	pub       []byte // the public key blob the signature names
	namespace string
	reserved  []byte
	hashAlg   string
	sig       []byte // the ssh signature encoding: string algorithm, string blob
}

// decodeSSHSig decodes the armoured SSHSIG of a gpgsig header. It checks the
// magic and the version, and nothing about the signature.
func decodeSSHSig(armoured string) (*sshSignature, error) {
	var body strings.Builder
	for _, l := range strings.Split(armoured, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "-----") {
			body.WriteString(l)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil {
		return nil, err
	}
	if len(raw) < 10 || string(raw[:6]) != "SSHSIG" {
		return nil, errors.New("no SSHSIG magic")
	}
	if binary.BigEndian.Uint32(raw[6:10]) != 1 {
		return nil, errors.New("SSHSIG version is not 1")
	}
	r := sshReader(raw[10:])
	s := &sshSignature{}
	var ns, alg []byte
	for _, f := range []*[]byte{&s.pub, &ns, &s.reserved, &alg, &s.sig} {
		if *f, err = r.str(); err != nil {
			return nil, err
		}
	}
	if len(r) != 0 {
		return nil, errors.New("trailing bytes after the SSHSIG signature")
	}
	s.namespace, s.hashAlg = string(ns), string(alg)
	return s, nil
}

// verify reports whether s is a signature over message in git's namespace
// that verifies under the public key s itself names. Who that key belongs to
// is the caller's question: Suggest only counts it when its fingerprint is one
// of the human's own keys, and an equal SHA256 of the key blob is the same key.
//
// Abuse: a hostile repository writes any gpgsig header it likes, naming any
// public key, the human's included, because public keys are public. Only the
// holder of the private key can make one that verifies over this commit's
// bytes; anything else is counted as unverified and never selects a key.
func (s *sshSignature) verify(message []byte) bool {
	if s.namespace != sshsigNamespace {
		return false
	}
	var h hash.Hash
	switch s.hashAlg {
	case "sha512":
		h = sha512.New()
	case "sha256":
		h = sha256.New()
	default:
		return false
	}
	h.Write(message)
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, f := range [][]byte{[]byte(s.namespace), s.reserved, []byte(s.hashAlg), h.Sum(nil)} {
		putString(&signed, f)
	}
	return verifySSH(s.pub, s.sig, signed.Bytes())
}

// verifySSH verifies an ssh signature encoding over data under the public key
// blob pub. ssh-ed25519, rsa-sha2-256/512 and ecdsa-sha2-nistp256/384/521 are
// checked; ssh-rsa (SHA-1), security keys (sk-*) and certificates are not, and
// report false.
func verifySSH(pub, sig, data []byte) bool {
	sr := sshReader(sig)
	sigAlg, err := sr.str()
	if err != nil {
		return false
	}
	blob, err := sr.str()
	if err != nil || len(sr) != 0 {
		return false
	}
	pr := sshReader(pub)
	keyAlg, err := pr.str()
	if err != nil {
		return false
	}
	switch string(keyAlg) {
	case "ssh-ed25519":
		k, err := pr.str()
		if err != nil || len(pr) != 0 || len(k) != ed25519.PublicKeySize || string(sigAlg) != "ssh-ed25519" || len(blob) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(k), data, blob)
	case "ssh-rsa":
		e, err1 := pr.mpint()
		n, err2 := pr.mpint()
		if err1 != nil || err2 != nil || len(pr) != 0 || n.BitLen() < minRSABits || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return false
		}
		var hf crypto.Hash
		switch string(sigAlg) {
		case "rsa-sha2-256":
			hf = crypto.SHA256
		case "rsa-sha2-512":
			hf = crypto.SHA512
		default:
			return false
		}
		d := hf.New()
		d.Write(data)
		return rsa.VerifyPKCS1v15(&rsa.PublicKey{N: n, E: int(e.Int64())}, hf, d.Sum(nil), blob) == nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		if string(sigAlg) != string(keyAlg) {
			return false
		}
		curveName, err1 := pr.str()
		q, err2 := pr.str()
		if err1 != nil || err2 != nil || len(pr) != 0 || "ecdsa-sha2-"+string(curveName) != string(keyAlg) {
			return false
		}
		var k *ecdsa.PublicKey
		var d hash.Hash
		var err error
		switch string(curveName) {
		case "nistp256":
			k, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), q)
			d = sha256.New()
		case "nistp384":
			k, err = ecdsa.ParseUncompressedPublicKey(elliptic.P384(), q)
			d = sha512.New384()
		default:
			k, err = ecdsa.ParseUncompressedPublicKey(elliptic.P521(), q)
			d = sha512.New()
		}
		if err != nil {
			return false
		}
		br := sshReader(blob)
		r, err1 := br.mpint()
		s, err2 := br.mpint()
		if err1 != nil || err2 != nil || len(br) != 0 {
			return false
		}
		d.Write(data)
		return ecdsa.Verify(k, d.Sum(nil), r, s)
	}
	return false
}

// sshReader reads the wire encoding of RFC 4251 §5.
type sshReader []byte

func (r *sshReader) str() ([]byte, error) {
	if len(*r) < 4 {
		return nil, errors.New("short ssh string")
	}
	n := binary.BigEndian.Uint32(*r)
	if int64(n) > int64(len(*r)-4) {
		return nil, errors.New("ssh string runs past its buffer")
	}
	s := (*r)[4 : 4+n]
	*r = (*r)[4+n:]
	return s, nil
}

// mpint reads a non-negative mpint; a negative one is refused, since no key or
// signature field snug checks is negative.
func (r *sshReader) mpint() (*big.Int, error) {
	b, err := r.str()
	if err != nil {
		return nil, err
	}
	if len(b) > 0 && b[0]&0x80 != 0 {
		return nil, errors.New("negative mpint")
	}
	return new(big.Int).SetBytes(b), nil
}

func putString(b *bytes.Buffer, s []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	b.Write(n[:])
	b.Write(s)
}

// signedPayload is what git signed: the commit object without its gpgsig
// header and that header's continuation lines, message included. It returns
// nil for a commit with no gpgsig header.
func signedPayload(obj []byte) []byte {
	end := bytes.Index(obj, []byte("\n\n"))
	if end < 0 {
		end = len(obj)
	}
	var out bytes.Buffer
	found, inSig := false, false
	rest := obj
	if end < len(obj) {
		rest = obj[:end+1]
	}
	for len(rest) > 0 {
		i := bytes.IndexByte(rest, '\n')
		line := rest
		if i >= 0 {
			line = rest[:i+1]
		}
		rest = rest[len(line):]
		switch {
		case inSig && len(line) > 0 && line[0] == ' ':
			continue
		case bytes.HasPrefix(line, []byte("gpgsig ")):
			found, inSig = true, true
			continue
		}
		inSig = false
		out.Write(line)
	}
	if !found {
		return nil
	}
	if end < len(obj) {
		out.Write(obj[end+1:])
	}
	return out.Bytes()
}
