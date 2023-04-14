package macospkg

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	xar "github.com/korylprince/goxar"
)

var ErrNotSigned = errors.New("package not signed")

// SignPkg signs and returns the given pkg with the given certificate and key.
// The certificate should be an "Apple Developer ID Installer" certificate.
// See https://mackyle.github.io/xar/howtosign.html
func SignPkg(pkg []byte, cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	temp, err := os.MkdirTemp("", "macospkg-")
	if err != nil {
		return nil, fmt.Errorf("could not create temporary directory: %w", err)
	}
	defer os.RemoveAll(temp)

	writeFilename := path.Join(temp, "archive.pkg")
	resignedArchiveFilename := path.Join(temp, "signed-archive.xar")

	if err = os.WriteFile(writeFilename, pkg, 0600); err != nil {
		return nil, fmt.Errorf("could not write archive.pkg to %s: %w", temp, err)
	}

	r, err := xar.OpenReader(writeFilename)
	if err != nil {
		return nil, err
	}

	certs := []*x509.Certificate{cert, CertDeveloperIDParsed, CertAppleRootParsed}
	if err = r.Resign(key, certs, resignedArchiveFilename); err != nil {
		return nil, err
	}

	var signedReader *xar.Reader
	signedReader, err = xar.OpenReader(resignedArchiveFilename)
	if err != nil {
		return nil, err
	}
	if err = signedReader.Close(); err != nil {
		return nil, err
	}

	return os.ReadFile(resignedArchiveFilename)
}

type nopReaderAtCloser struct {
	io.ReaderAt
}

func (n nopReaderAtCloser) Close() error {
	return nil
}

// VerifyPkg returns an error if the pkg cannot be verified with a complete chain to Apple's root CA
// If pkg is not signed, ErrNotSigned is returned
func VerifyPkg(pkg []byte) error {
	buf := bytes.NewReader(pkg)
	r, err := xar.NewReader(nopReaderAtCloser{buf}, int64(len(pkg)))
	if err != nil {
		return fmt.Errorf("could not open reader: %w", err)
	}

	if r.SignatureError != nil {
		return fmt.Errorf("invalid signature: %w", r.SignatureError)
	}
	if r.SignatureCreationTime <= 0 {
		return ErrNotSigned
	}

	if len(r.Certificates) < 1 {
		return errors.New("could not find certificates")
	}

	root := r.Certificates[len(r.Certificates)-1]
	if !CertAppleRootParsed.Equal(root) {
		return errors.New("root certificate is not valid Apple root")
	}

	return nil
}
