package x509util

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/pkg/errors"
)

// DefaultIntermediateCertValidity is the default validity of a intermediate certificate in the step PKI.
var DefaultIntermediateCertValidity = time.Hour * 24 * 365 * 10

// Intermediate implements the Profile for a intermediate certificate.
type Intermediate struct {
	base
}

// DefaultDuration returns the default Intermediate Certificate duration.
func (i *Intermediate) DefaultDuration() time.Duration {
	return DefaultIntermediateCertValidity
}

// NewIntermediateProfile returns a new intermediate x509 Certificate profile.
func NewIntermediateProfile(name string, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	sub := defaultIntermediateTemplate(pkix.Name{CommonName: name}, pkix.Name{CommonName: name})
	return newProfile(&Intermediate{}, sub, iss, issPriv, withOps...)
}

// NewIntermediateProfileWithCSR returns a new intermediate x509 Certificate Profile with
// Subject Certificate fields populated directly from the CSR.
// A public/private keypair **WILL NOT** be generated for this profile because
// the public key will be populated from the CSR.
func NewIntermediateProfileWithCSR(csr *x509.CertificateRequest, iss *x509.Certificate, issPriv crypto.PrivateKey, withOps ...WithOption) (Profile, error) {
	if csr.PublicKey == nil {
		return nil, errors.Errorf("CSR must have PublicKey")
	}

	sub := defaultIntermediateTemplate(csr.Subject, iss.Subject)
	sub.ExtraExtensions = csr.Extensions
	sub.DNSNames = csr.DNSNames
	sub.EmailAddresses = csr.EmailAddresses
	sub.IPAddresses = csr.IPAddresses
	sub.URIs = csr.URIs

	withOps = append(withOps, WithPublicKey(csr.PublicKey))
	return newProfile(&Intermediate{}, sub, iss, issPriv, withOps...)
}

func defaultIntermediateTemplate(sub pkix.Name, iss pkix.Name) *x509.Certificate {
	notBefore := time.Now()
	return &x509.Certificate{
		IsCA:                  true,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(DefaultIntermediateCertValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        false,
		Issuer:                iss,
		Subject:               sub,
	}
}
