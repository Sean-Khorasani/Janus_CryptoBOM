package certmanager

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// ML-DSA issuance is pure Go (cloudflare/circl) via hand-marshaled X.509 ASN.1 — Go's
// crypto/x509.CreateCertificate refuses non-RSA/ECDSA/Ed25519 keys, and OpenSSL 3.5+ is not
// assumed present. These certs are for COMMAND signing (WP-029 P3): the signature is produced
// and verified out-of-band (circl on the server, fips204 on the agent), never in a TLS
// handshake — Go's crypto/tls cannot serve ML-DSA, so transport certs stay ECDSA-P384.

// ML-DSA signature/public-key OIDs (NIST CSOR, id-ml-dsa-*).
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

func mldsaOID(scheme string) (asn1.ObjectIdentifier, error) {
	switch scheme {
	case "ML-DSA-44":
		return oidMLDSA44, nil
	case "ML-DSA-65":
		return oidMLDSA65, nil
	case "ML-DSA-87":
		return oidMLDSA87, nil
	default:
		return nil, fmt.Errorf("certmanager: unknown ML-DSA scheme %q", scheme)
	}
}

// Minimal X.509 ASN.1 shapes (RFC 5280) we marshal by hand.
type mldsaValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type mldsaSPKI struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type mldsaTBS struct {
	Version      int `asn1:"explicit,tag:0"`
	SerialNumber *big.Int
	SignatureAlg pkix.AlgorithmIdentifier
	Issuer       asn1.RawValue
	Validity     mldsaValidity
	Subject      asn1.RawValue
	SPKI         mldsaSPKI
	Extensions   []pkix.Extension `asn1:"explicit,tag:3,omitempty"`
}

type mldsaCertificate struct {
	TBSCertificate asn1.RawValue
	SignatureAlg   pkix.AlgorithmIdentifier
	Signature      asn1.BitString
}

type basicConstraints struct {
	IsCA bool `asn1:"optional"`
}

// MLDSACertParams is the input for issuing one ML-DSA certificate. The issuer key signs it;
// for a self-signed CA, issuer == subject and signerPriv is the subject's own key.
type MLDSACertParams struct {
	Scheme      string // "ML-DSA-44|65|87"
	Serial      *big.Int
	Subject     pkix.Name
	Issuer      pkix.Name
	NotBefore   time.Time
	NotAfter    time.Time
	SubjectPub  sign.PublicKey
	IsCA        bool
	DNSNames    []string
	IPAddresses []net.IP

	signScheme sign.Scheme
	signPriv   sign.PrivateKey
}

// IssueMLDSACert hand-marshals and signs a single ML-DSA X.509 certificate. The returned DER
// can be verified by extracting the raw TBSCertificate bytes and checking the issuer's ML-DSA
// signature over them (the agent does this with fips204).
func IssueMLDSACert(p MLDSACertParams) ([]byte, error) {
	oid, err := mldsaOID(p.Scheme)
	if err != nil {
		return nil, err
	}
	algID := pkix.AlgorithmIdentifier{Algorithm: oid} // parameters absent (required for ML-DSA)

	issuerDER, err := asn1.Marshal(p.Issuer.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("certmanager: marshal issuer: %w", err)
	}
	subjectDER, err := asn1.Marshal(p.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("certmanager: marshal subject: %w", err)
	}
	pubRaw, err := p.SubjectPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("certmanager: marshal public key: %w", err)
	}
	exts, err := mldsaExtensions(p)
	if err != nil {
		return nil, err
	}

	tbs := mldsaTBS{
		Version:      2, // v3
		SerialNumber: p.Serial,
		SignatureAlg: algID,
		Issuer:       asn1.RawValue{FullBytes: issuerDER},
		Validity:     mldsaValidity{NotBefore: p.NotBefore.UTC(), NotAfter: p.NotAfter.UTC()},
		Subject:      asn1.RawValue{FullBytes: subjectDER},
		SPKI:         mldsaSPKI{Algorithm: algID, PublicKey: asn1.BitString{Bytes: pubRaw, BitLength: len(pubRaw) * 8}},
		Extensions:   exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("certmanager: marshal TBS: %w", err)
	}

	sig := p.signScheme.Sign(p.signPriv, tbsDER, nil)
	cert := mldsaCertificate{
		TBSCertificate: asn1.RawValue{FullBytes: tbsDER},
		SignatureAlg:   algID,
		Signature:      asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	return asn1.Marshal(cert)
}

func mldsaExtensions(p MLDSACertParams) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	bc, err := asn1.Marshal(basicConstraints{IsCA: p.IsCA})
	if err != nil {
		return nil, err
	}
	exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bc})

	// KeyUsage BIT STRING: bit 0 = digitalSignature, 5 = keyCertSign, 6 = cRLSign.
	var ku asn1.BitString
	if p.IsCA {
		ku = asn1.BitString{Bytes: []byte{0x06}, BitLength: 7} // bits 5,6
	} else {
		ku = asn1.BitString{Bytes: []byte{0x80}, BitLength: 1} // bit 0
	}
	kuDER, err := asn1.Marshal(ku)
	if err != nil {
		return nil, err
	}
	exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: kuDER})

	if len(p.DNSNames) > 0 || len(p.IPAddresses) > 0 {
		var names []asn1.RawValue
		for _, d := range p.DNSNames {
			names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(d)})
		}
		for _, ip := range p.IPAddresses {
			b := ip.To4()
			if b == nil {
				b = ip.To16()
			}
			names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: b})
		}
		sanDER, err := asn1.Marshal(names)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: sanDER})
	}
	return exts, nil
}

// MLDSAChain is a freshly-issued ML-DSA Root CA + leaf, all PEM-encoded, with the raw circl
// keys retained so callers can sign/verify out-of-band.
type MLDSAChain struct {
	Scheme      string
	RootCertPEM []byte
	RootKeyPEM  []byte // raw circl private key bytes (PEM "ML-DSA PRIVATE KEY")
	LeafCertPEM []byte
	LeafKeyPEM  []byte
	RootScheme  sign.Scheme
	RootPub     sign.PublicKey
	RootPriv    sign.PrivateKey
	LeafPriv    sign.PrivateKey
	LeafPub     sign.PublicKey
	RootCertDER []byte
	LeafCertDER []byte
}

// IssueMLDSAChain mints a self-signed ML-DSA Root CA and a leaf certificate signed by it —
// the command-signing trust hierarchy for WP-029 P3.
func IssueMLDSAChain(scheme, rootCN, leafCN string, days int) (*MLDSAChain, error) {
	s := schemes.ByName(scheme)
	if s == nil {
		return nil, fmt.Errorf("certmanager: ML-DSA scheme %q not available in this build", scheme)
	}
	if days <= 0 {
		days = 365
	}
	now := time.Now()

	rootPub, rootPriv, err := s.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("certmanager: generate root key: %w", err)
	}
	rootSerial, err := randSerial()
	if err != nil {
		return nil, err
	}
	rootName := pkix.Name{CommonName: rootCN, Organization: []string{"Janus CryptoBOM"}}
	rootDER, err := IssueMLDSACert(MLDSACertParams{
		Scheme: scheme, Serial: rootSerial, Subject: rootName, Issuer: rootName,
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, days*5),
		SubjectPub: rootPub, IsCA: true, signScheme: s, signPriv: rootPriv,
	})
	if err != nil {
		return nil, err
	}

	leafPub, leafPriv, err := s.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("certmanager: generate leaf key: %w", err)
	}
	leafSerial, err := randSerial()
	if err != nil {
		return nil, err
	}
	leafDER, err := IssueMLDSACert(MLDSACertParams{
		Scheme: scheme, Serial: leafSerial,
		Subject:   pkix.Name{CommonName: leafCN, Organization: []string{"Janus CryptoBOM"}},
		Issuer:    rootName,
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, days),
		SubjectPub: leafPub, IsCA: false, signScheme: s, signPriv: rootPriv,
	})
	if err != nil {
		return nil, err
	}

	rootKeyRaw, err := rootPriv.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("certmanager: marshal root key: %w", err)
	}
	leafKeyRaw, err := leafPriv.(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("certmanager: marshal leaf key: %w", err)
	}

	return &MLDSAChain{
		Scheme:      scheme,
		RootCertPEM: pemBlock("CERTIFICATE", rootDER),
		RootKeyPEM:  pemBlock("ML-DSA PRIVATE KEY", rootKeyRaw),
		LeafCertPEM: pemBlock("CERTIFICATE", leafDER),
		LeafKeyPEM:  pemBlock("ML-DSA PRIVATE KEY", leafKeyRaw),
		RootScheme:  s,
		RootPub:     rootPub,
		RootPriv:    rootPriv,
		LeafPriv:    leafPriv,
		LeafPub:     leafPub,
		RootCertDER: rootDER,
		LeafCertDER: leafDER,
	}, nil
}

// MLDSATBSAndSig extracts the raw TBSCertificate DER and the signature from an ML-DSA cert,
// so a verifier can check issuerPub.Verify(tbs, sig). This is the operation the Rust agent
// mirrors with x509-parser + fips204.
func MLDSATBSAndSig(certDER []byte) (tbs, sig []byte, err error) {
	var c mldsaCertificate
	if _, err = asn1.Unmarshal(certDER, &c); err != nil {
		return nil, nil, fmt.Errorf("certmanager: unmarshal cert: %w", err)
	}
	return c.TBSCertificate.FullBytes, c.Signature.Bytes, nil
}

func schemeNameForOID(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidMLDSA44):
		return "ML-DSA-44"
	case oid.Equal(oidMLDSA65):
		return "ML-DSA-65"
	case oid.Equal(oidMLDSA87):
		return "ML-DSA-87"
	default:
		return ""
	}
}

// MLDSAPublicKeyFromCert extracts the subject's ML-DSA public key and scheme name from a cert
// DER produced by IssueMLDSACert. The Rust agent mirrors this with x509-parser SPKI
// extraction. Returns an error if the SPKI is not an ML-DSA key.
func MLDSAPublicKeyFromCert(certDER []byte) (sign.PublicKey, string, error) {
	var c mldsaCertificate
	if _, err := asn1.Unmarshal(certDER, &c); err != nil {
		return nil, "", fmt.Errorf("certmanager: unmarshal cert: %w", err)
	}
	var tbs mldsaTBS
	if _, err := asn1.Unmarshal(c.TBSCertificate.FullBytes, &tbs); err != nil {
		return nil, "", fmt.Errorf("certmanager: unmarshal tbs: %w", err)
	}
	name := schemeNameForOID(tbs.SPKI.Algorithm.Algorithm)
	if name == "" {
		return nil, "", fmt.Errorf("certmanager: SPKI algorithm is not ML-DSA")
	}
	s := schemes.ByName(name)
	pub, err := s.UnmarshalBinaryPublicKey(tbs.SPKI.PublicKey.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("certmanager: parse ML-DSA public key: %w", err)
	}
	return pub, name, nil
}

// decodePEMCert is a small helper for tests/callers that need the DER back out of a PEM block.
func decodePEMCert(p []byte) ([]byte, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, fmt.Errorf("certmanager: no PEM block")
	}
	return blk.Bytes, nil
}
