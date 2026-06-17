//go:build cgo && !windows

package hsm

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
)

// PKCS#11 mechanism/attribute constants newer than miekg/pkcs11's built-ins, taken from
// the PQC-enabled SoftHSMv2 headers (src/lib/pkcs11/pkcs11.h).
const (
	ckmMLDSAKeyPairGen = 0x1C  // CKM_ML_DSA_KEY_PAIR_GEN
	ckmMLDSA           = 0x1D  // CKM_ML_DSA
	ckaParameterSet    = 0x61D // CKA_PARAMETER_SET
	ckpMLDSA44         = 1     // CKP_ML_DSA_44
	ckpMLDSA65         = 2     // CKP_ML_DSA_65
	ckpMLDSA87         = 3     // CKP_ML_DSA_87
)

// PKCS11Client is a real PKCS#11 HSM client (SoftHSM2 or hardware) using a dlopen'd
// module via cgo. Asymmetric signing is PQC-only (ML-DSA / FIPS 204) — RSA/ECDSA are
// refused. It also implements MACSigner (HMAC-SHA256) for HSM-resident command signing.
// PKCS#11 sessions are not safe for concurrent use, so every operation holds the mutex.
type PKCS11Client struct {
	mu      sync.Mutex
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
}

// newPKCS11 opens the module, locates the token (by label, else slot), and logs in.
func newPKCS11(cfg HSMConfig) (HSM, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("JANUS_HSM_MODULE_PATH is required for pkcs11 mode")
	}
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("could not load PKCS#11 module %q", cfg.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("C_Initialize: %w", err)
	}
	slot, err := findSlot(ctx, cfg)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, err
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("OpenSession: %w", err)
	}
	if cfg.Pin != "" {
		if err := ctx.Login(session, pkcs11.CKU_USER, cfg.Pin); err != nil {
			ctx.CloseSession(session)
			ctx.Finalize()
			ctx.Destroy()
			return nil, fmt.Errorf("Login (check JANUS_HSM_PIN): %w", err)
		}
	}
	return &PKCS11Client{ctx: ctx, session: session}, nil
}

// ListSlots enumerates the module's token-present slots without logging in. Used by
// `janus-server hsm info` so the admin can pick a slot INDEX. Standalone (opens and
// finalizes the module itself).
func ListSlots(modulePath string) ([]SlotDetail, error) {
	if modulePath == "" {
		return nil, fmt.Errorf("module path is required")
	}
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("could not load PKCS#11 module %q", modulePath)
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("C_Initialize: %w", err)
	}
	defer func() { _ = ctx.Finalize(); ctx.Destroy() }()
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("GetSlotList: %w", err)
	}
	out := make([]SlotDetail, 0, len(slots))
	for i, s := range slots {
		d := SlotDetail{Index: i, SlotID: s, TokenPresent: true}
		if ti, err := ctx.GetTokenInfo(s); err == nil {
			d.Label = strings.TrimSpace(ti.Label)
			d.Manufacturer = strings.TrimSpace(ti.ManufacturerID)
			d.Model = strings.TrimSpace(ti.Model)
			d.SerialNumber = strings.TrimSpace(ti.SerialNumber)
		}
		out = append(out, d)
	}
	return out, nil
}

// RemoveKey destroys every object (public, private, secret) carrying the label and
// returns how many were removed.
func (c *PKCS11Client) RemoveKey(label string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	handles, err := c.findAll([]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)})
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, h := range handles {
		if err := c.ctx.DestroyObject(c.session, h); err != nil {
			return removed, fmt.Errorf("DestroyObject: %w", err)
		}
		removed++
	}
	return removed, nil
}

// findSlot returns the slot whose token matches cfg.Label, or cfg.SlotID when no label
// is set. Label is preferred because SoftHSM reassigns numeric slot IDs.
func findSlot(ctx *pkcs11.Ctx, cfg HSMConfig) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("GetSlotList: %w", err)
	}
	// Priority: token label (most stable) > slot INDEX (0-based position, practical) >
	// slot id (can be a huge number) > first available.
	if cfg.Label != "" {
		for _, s := range slots {
			if ti, err := ctx.GetTokenInfo(s); err == nil && ti.Label == cfg.Label {
				return s, nil
			}
		}
		return 0, fmt.Errorf("no initialized token with label %q", cfg.Label)
	}
	if cfg.SlotIndex >= 0 {
		if cfg.SlotIndex >= len(slots) {
			return 0, fmt.Errorf("slot index %d out of range: only %d token(s) present", cfg.SlotIndex, len(slots))
		}
		return slots[cfg.SlotIndex], nil
	}
	for _, s := range slots {
		if s == uint(cfg.SlotID) {
			return s, nil
		}
	}
	if len(slots) > 0 {
		return slots[0], nil
	}
	return 0, fmt.Errorf("no initialized PKCS#11 token found")
}

func paramSetFor(algorithm string) (uint, error) {
	switch algorithm {
	case "ML-DSA-44":
		return ckpMLDSA44, nil
	case "ML-DSA-65":
		return ckpMLDSA65, nil
	case "ML-DSA-87":
		return ckpMLDSA87, nil
	default:
		return 0, fmt.Errorf("PKCS#11 backend supports ML-DSA-44/65/87; %q is not available (note: RSA/ECDSA are never used)", algorithm)
	}
}

// GenerateKeyPair creates an ML-DSA key pair on the token. Non-ML-DSA algorithms are
// refused (SLH-DSA needs a different mechanism; RSA/ECDSA are banned).
func (c *PKCS11Client) GenerateKeyPair(algorithm string) (string, error) {
	if !IsAcceptedPQCSignatureAlg(algorithm) {
		return "", fmt.Errorf("pkcs11: refusing non-PQC signing key %q (Janus signs only with ML-DSA/SLH-DSA)", algorithm)
	}
	paramSet, err := paramSetFor(algorithm)
	if err != nil {
		return "", err
	}
	label := fmt.Sprintf("janus-%s-%s", algorithm, uuid.NewString())
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.genMLDSA(label, paramSet); err != nil {
		return "", err
	}
	return label, nil
}

// genMLDSA generates an ML-DSA key pair under the given label. Caller holds the mutex.
func (c *PKCS11Client) genMLDSA(label string, paramSet uint) error {
	id := []byte(label)
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(ckaParameterSet, paramSet),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmMLDSAKeyPairGen, nil)}
	if _, _, err := c.ctx.GenerateKeyPair(c.session, mech, pubTemplate, privTemplate); err != nil {
		return fmt.Errorf("pkcs11: ML-DSA key generation failed (does this token support ML-DSA?): %w", err)
	}
	return nil
}

// EnsureMLDSAKey returns the labelled ML-DSA key, generating one (with that label) if it
// does not yet exist (CommandKeyManager). The key is token-resident, so the public key is
// stable across server restarts — what HSM-resident command signing needs.
func (c *PKCS11Client) EnsureMLDSAKey(label, algorithm string) (string, error) {
	if !IsAcceptedPQCSignatureAlg(algorithm) {
		return "", fmt.Errorf("pkcs11: %q is not a PQC signature algorithm", algorithm)
	}
	paramSet, err := paramSetFor(algorithm)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if h, _ := c.findOne(pkcs11.CKO_PRIVATE_KEY, label); h != 0 {
		return label, nil
	}
	if err := c.genMLDSA(label, paramSet); err != nil {
		return "", err
	}
	return label, nil
}

// PublicKey returns the FIPS 204 encoding of the labelled key's verification key, read
// from the token's public-key object (CommandKeyManager).
func (c *PKCS11Client) PublicKey(keyID string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pub, err := c.findOne(pkcs11.CKO_PUBLIC_KEY, keyID)
	if err != nil {
		return nil, err
	}
	attrs, err := c.ctx.GetAttributeValue(c.session, pub, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil || len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("pkcs11: could not read public key value for %q: %w", keyID, err)
	}
	return attrs[0].Value, nil
}

// Sign produces an ML-DSA signature with the token-resident private key (by label).
func (c *PKCS11Client) Sign(keyID string, data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	priv, err := c.findOne(pkcs11.CKO_PRIVATE_KEY, keyID)
	if err != nil {
		return nil, err
	}
	if err := c.ctx.SignInit(c.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmMLDSA, nil)}, priv); err != nil {
		return nil, fmt.Errorf("pkcs11: SignInit (CKM_ML_DSA): %w", err)
	}
	sig, err := c.ctx.Sign(c.session, data)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: Sign: %w", err)
	}
	return sig, nil
}

// Verify checks an ML-DSA signature with the token-resident public key (by label).
func (c *PKCS11Client) Verify(keyID string, data, signature []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pub, err := c.findOne(pkcs11.CKO_PUBLIC_KEY, keyID)
	if err != nil {
		return false, err
	}
	if err := c.ctx.VerifyInit(c.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmMLDSA, nil)}, pub); err != nil {
		return false, fmt.Errorf("pkcs11: VerifyInit: %w", err)
	}
	if err := c.ctx.Verify(c.session, data, signature); err != nil {
		return false, nil // invalid signature is a clean false, not an error
	}
	return true, nil
}

// EnsureMACKey imports a generic-secret HMAC key under label if absent (MACSigner).
func (c *PKCS11Client) EnsureMACKey(label string, keyMaterial []byte) error {
	if len(keyMaterial) == 0 {
		return fmt.Errorf("pkcs11: MAC key material is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if h, _ := c.findOne(pkcs11.CKO_SECRET_KEY, label); h != 0 {
		return nil // already present
	}
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, keyMaterial),
	}
	if _, err := c.ctx.CreateObject(c.session, tmpl); err != nil {
		return fmt.Errorf("pkcs11: import command MAC key: %w", err)
	}
	return nil
}

// MAC returns HMAC-SHA256 of data under the token-resident generic-secret key (MACSigner).
func (c *PKCS11Client) MAC(label string, data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, err := c.findOne(pkcs11.CKO_SECRET_KEY, label)
	if err != nil {
		return nil, err
	}
	if err := c.ctx.SignInit(c.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_HMAC, nil)}, key); err != nil {
		return nil, fmt.Errorf("pkcs11: SignInit (CKM_SHA256_HMAC): %w", err)
	}
	mac, err := c.ctx.Sign(c.session, data)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: HMAC: %w", err)
	}
	return mac, nil
}

// ListKeys returns metadata for private + secret key objects on the token.
func (c *PKCS11Client) ListKeys() ([]KeyInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []KeyInfo
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_SECRET_KEY} {
		handles, err := c.findAll([]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)})
		if err != nil {
			return nil, err
		}
		for _, h := range handles {
			attrs, err := c.ctx.GetAttributeValue(c.session, h, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			})
			label := ""
			if err == nil && len(attrs) > 0 {
				label = string(attrs[0].Value)
			}
			alg := "ML-DSA"
			if class == pkcs11.CKO_SECRET_KEY {
				alg = "HMAC-SHA256"
			}
			out = append(out, KeyInfo{KeyID: label, Label: label, Algorithm: alg, IsPQC: class == pkcs11.CKO_PRIVATE_KEY})
		}
	}
	return out, nil
}

// GetKeyInfo returns metadata for a key located by label.
func (c *PKCS11Client) GetKeyInfo(keyID string) (*KeyInfo, error) {
	keys, err := c.ListKeys()
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].KeyID == keyID {
			return &keys[i], nil
		}
	}
	return nil, fmt.Errorf("pkcs11: key %q not found", keyID)
}

// Close logs out and releases the module.
func (c *PKCS11Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return nil
	}
	_ = c.ctx.Logout(c.session)
	_ = c.ctx.CloseSession(c.session)
	_ = c.ctx.Finalize()
	c.ctx.Destroy()
	c.ctx = nil
	return nil
}

// findOne returns the first object of the given class with CKA_LABEL == label (0 if none).
// Caller holds the mutex.
func (c *PKCS11Client) findOne(class uint, label string) (pkcs11.ObjectHandle, error) {
	handles, err := c.findAll([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("pkcs11: object %q not found", label)
	}
	return handles[0], nil
}

// findAll runs a FindObjects cycle for the template. Caller holds the mutex.
func (c *PKCS11Client) findAll(template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := c.ctx.FindObjectsInit(c.session, template); err != nil {
		return nil, fmt.Errorf("FindObjectsInit: %w", err)
	}
	handles, _, err := c.ctx.FindObjects(c.session, 256)
	if ferr := c.ctx.FindObjectsFinal(c.session); ferr != nil && err == nil {
		err = ferr
	}
	if err != nil {
		return nil, fmt.Errorf("FindObjects: %w", err)
	}
	return handles, nil
}

// compile-time check: the real client also satisfies MACSigner.
var _ MACSigner = (*PKCS11Client)(nil)
