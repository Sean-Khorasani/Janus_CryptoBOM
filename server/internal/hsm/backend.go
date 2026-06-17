package hsm

import "fmt"

// NewBackend builds the HSM backend selected by cfg.Mode. It is the single entry point
// used by the server (HSM-01 + configurable HSM):
//
//   - disabled → (nil, nil): no HSM; callers leave /api/hsm/* returning 501.
//   - software → in-process keystore (real ML-DSA; HMAC for command signing).
//   - pkcs11   → a real PKCS#11 token (SoftHSM2/hardware). Fail-closed: an error here
//     must abort startup rather than silently degrade to software.
//
// newPKCS11 is defined per platform (cgo / stub / windows).
func NewBackend(cfg HSMConfig) (HSM, error) {
	switch cfg.Mode {
	case ModeDisabled:
		return nil, nil
	case ModePKCS11:
		client, err := newPKCS11(cfg)
		if err != nil {
			return nil, fmt.Errorf("pkcs11 backend: %w", err)
		}
		return client, nil
	case ModeSoftware, "":
		return NewSoftHSM2(), nil
	default:
		return nil, fmt.Errorf("unknown JANUS_HSM_MODE %q (use disabled|software|pkcs11)", cfg.Mode)
	}
}
