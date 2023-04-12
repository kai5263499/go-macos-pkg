package macospkg_test

import (
	"crypto/rsa"
	"os"
	"testing"

	macospkg "github.com/korylprince/go-macos-pkg"
	"golang.org/x/crypto/pkcs12"
)

func TestFull(t *testing.T) {
	if os.Getenv("DEVELOPER_IDENTITY") == "" {
		t.Skip("DEVELOPER_IDENTITY not set")
	}

	identity, err := os.ReadFile(os.Getenv("DEVELOPER_IDENTITY"))
	if err != nil {
		t.Fatal("could not read identity: %w", err)
	}
	key, cert, err := pkcs12.Decode(identity, os.Getenv("DEVELOPER_IDENTITY_PASSWORD"))
	if err != nil {
		t.Fatal("could not decode identity: %w", err)
	}

	postinstall := []byte(`#!/bin/bash
echo "Hello, World!"
`)

	pkg, err := macospkg.GeneratePkg("com.github.korylprince.go-macos-pkg.test", "1.0.0", postinstall)
	if err != nil {
		t.Fatalf("generate: want nil err, have: %s", err.Error())
	}

	signedPkg, err := macospkg.SignPkg(pkg, cert, key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("sign: want nil err, have: %s", err.Error())
	}

	if len(signedPkg) < 1 {
		t.Fatalf("infalid signedPkg length: %d", len(signedPkg))
	}

	if err = macospkg.VerifyPkg(signedPkg); err != nil {
		t.Fatalf("verify: want nil err, have: %s", err.Error())
	}
}
