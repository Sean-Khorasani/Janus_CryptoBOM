package certmanager

import (
	"encoding/asn1"
	"testing"

	"github.com/cloudflare/circl/sign/schemes"
)

func TestIssueMLDSAChain(t *testing.T) {
	chain, err := IssueMLDSAChain("ML-DSA-65", "Janus Command Root", "janus-command", 30)
	if err != nil {
		t.Fatalf("IssueMLDSAChain: %v", err)
	}

	// The root is self-signed: its own public key verifies its TBS.
	rootTBS, rootSig, err := MLDSATBSAndSig(chain.RootCertDER)
	if err != nil {
		t.Fatalf("root TBS/sig: %v", err)
	}
	if !chain.RootScheme.Verify(chain.RootPub, rootTBS, rootSig, nil) {
		t.Fatal("root self-signature does not verify")
	}

	// The leaf chains to the root: the ROOT's public key verifies the LEAF's TBS.
	leafTBS, leafSig, err := MLDSATBSAndSig(chain.LeafCertDER)
	if err != nil {
		t.Fatalf("leaf TBS/sig: %v", err)
	}
	if !chain.RootScheme.Verify(chain.RootPub, leafTBS, leafSig, nil) {
		t.Fatal("leaf is not validly signed by the root")
	}

	// A tampered TBS must fail (sanity that we verify the real bytes, not a constant).
	bad := append([]byte(nil), leafTBS...)
	bad[len(bad)-1] ^= 0xFF
	if chain.RootScheme.Verify(chain.RootPub, bad, leafSig, nil) {
		t.Fatal("tampered leaf TBS still verified — signature check is not binding")
	}

	// The cert structure is well-formed DER (parses as our Certificate shape).
	var c mldsaCertificate
	if _, err := asn1.Unmarshal(chain.LeafCertDER, &c); err != nil {
		t.Fatalf("leaf cert is not well-formed DER: %v", err)
	}
	if !c.SignatureAlg.Algorithm.Equal(oidMLDSA65) {
		t.Errorf("signatureAlgorithm = %v, want ML-DSA-65 OID", c.SignatureAlg.Algorithm)
	}

	// PEM round-trips.
	if der, err := decodePEMCert(chain.LeafCertPEM); err != nil || len(der) == 0 {
		t.Fatalf("leaf cert PEM does not decode: %v", err)
	}
}

func TestIssueMLDSAChainUnknownScheme(t *testing.T) {
	if _, err := IssueMLDSAChain("ML-DSA-999", "r", "l", 30); err == nil {
		t.Fatal("expected error for unknown scheme")
	}
}

func TestMLDSASchemeAvailable(t *testing.T) {
	// Guards the assumption the rest relies on: circl ships ML-DSA-65 in this build.
	if schemes.ByName("ML-DSA-65") == nil {
		t.Fatal("ML-DSA-65 not available in circl build")
	}
}
