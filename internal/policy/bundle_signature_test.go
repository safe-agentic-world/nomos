package policy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBundleWithSignatureVerification(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundleData := []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`)
	if err := os.WriteFile(bundlePath, bundleData, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	digest := sha256.Sum256(bundleData)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigPath := filepath.Join(dir, "bundle.sig")
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub key: %v", err)
	}
	pubPath := filepath.Join(dir, "bundle_pub.pem")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}

	if _, err := LoadBundleWithOptions(bundlePath, LoadOptions{VerifySignature: true, SignaturePath: sigPath, PublicKeyPath: pubPath}); err != nil {
		t.Fatalf("expected signature verification success, got %v", err)
	}

	if err := os.WriteFile(sigPath, []byte("invalid"), 0o600); err != nil {
		t.Fatalf("write invalid sig: %v", err)
	}
	if _, err := LoadBundleWithOptions(bundlePath, LoadOptions{VerifySignature: true, SignaturePath: sigPath, PublicKeyPath: pubPath}); err == nil {
		t.Fatal("expected verification failure")
	}
}
