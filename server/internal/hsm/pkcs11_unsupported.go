//go:build !windows

package hsm

import "fmt"

// PKCS11Client is unavailable until a supported non-Windows PKCS#11 provider is
// implemented. Failing closed avoids presenting placeholder HSM operations as
// usable on Linux.
type PKCS11Client struct{}

func LoadPKCS11(modulePath, pin string, slotID uint) (*PKCS11Client, error) {
	return nil, fmt.Errorf("PKCS#11 is not supported on this platform")
}

func (c *PKCS11Client) ListKeys() ([]KeyInfo, error) {
	return nil, fmt.Errorf("PKCS#11 is not supported on this platform")
}

func (c *PKCS11Client) Sign(keyID string, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("PKCS#11 is not supported on this platform")
}

func (c *PKCS11Client) Verify(keyID string, data, signature []byte) (bool, error) {
	return false, fmt.Errorf("PKCS#11 is not supported on this platform")
}

func (c *PKCS11Client) GenerateKeyPair(algorithm string) (string, error) {
	return "", fmt.Errorf("PKCS#11 is not supported on this platform")
}

func (c *PKCS11Client) GetKeyInfo(keyID string) (*KeyInfo, error) {
	return nil, fmt.Errorf("PKCS#11 is not supported on this platform")
}

func (c *PKCS11Client) Close() error {
	return nil
}
