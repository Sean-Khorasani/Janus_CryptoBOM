//go:build windows

package hsm

// Native, cgo-free PKCS#11 client for Windows. It loads the module DLL with
// golang.org/x/sys/windows and calls the exported C_* functions via syscall, so the
// server builds with the standard MSVC/Go toolchain (CGO_ENABLED=0) — no mingw/gcc.
//
// ABI note (critical): on Windows, C's `unsigned long` (CK_ULONG) is 32-bit even on
// 64-bit Windows (LLP64). All CK_ULONG-typed fields/args here are uint32, and the
// CK_ATTRIBUTE / CK_MECHANISM structs carry explicit padding so their layout matches the
// 64-bit Windows C ABI (4-byte ulong, 8-byte pointer). This differs from the Linux/cgo
// client (LP64, 64-bit ulong) — which is exactly why this is a separate per-platform file.

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

type ckRV = uint32
type ckUlong = uint32

const (
	ckrOK ckRV = 0x00000000

	ckTrue byte = 1

	ckfSerialSession ckUlong = 0x00000004
	ckfRWSession     ckUlong = 0x00000002
	ckuUser          ckUlong = 1

	// Object classes / key types / attributes / mechanisms (PKCS#11 + the PQC SoftHSM).
	ckoPublicKey  ckUlong = 0x00000002
	ckoPrivateKey ckUlong = 0x00000003
	ckoSecretKey  ckUlong = 0x00000004

	ckkGenericSecret ckUlong = 0x00000010

	ckaClass        ckUlong = 0x00000000
	ckaToken        ckUlong = 0x00000001
	ckaPrivate      ckUlong = 0x00000002
	ckaLabel        ckUlong = 0x00000003
	ckaKeyType      ckUlong = 0x00000100
	ckaValue        ckUlong = 0x00000011
	ckaID           ckUlong = 0x00000102
	ckaSign         ckUlong = 0x00000108
	ckaVerify       ckUlong = 0x0000010A
	ckaParameterSet ckUlong = 0x0000061D

	ckmSHA256HMAC      ckUlong = 0x00000251
	ckmMLDSAKeyPairGen ckUlong = 0x0000001C
	ckmMLDSA           ckUlong = 0x0000001D
)

// ckAttribute mirrors CK_ATTRIBUTE on 64-bit Windows: {CK_ULONG type; CK_VOID_PTR pValue;
// CK_ULONG ulValueLen}. With a 4-byte CK_ULONG and 8-byte pointer the compiler inserts
// 4 bytes of padding before pValue and 4 trailing; size = 24.
type ckAttribute struct {
	typ      ckUlong
	_        uint32
	pValue   uintptr
	valueLen ckUlong
	_        uint32
}

// ckMechanism mirrors CK_MECHANISM on 64-bit Windows. Same alignment story as above.
type ckMechanism struct {
	mechanism ckUlong
	_         uint32
	pParam    uintptr
	paramLen  ckUlong
	_         uint32
}

// PKCS11Client is a Windows-native PKCS#11 HSM client. Sessions are not concurrency-safe,
// so every operation holds the mutex.
type PKCS11Client struct {
	mu      sync.Mutex
	module  windows.Handle
	procs   map[string]uintptr
	session ckUlong
}

// loadModule loads the PKCS#11 DLL with LOAD_WITH_ALTERED_SEARCH_PATH so Windows resolves
// the module's dependency DLLs (e.g. SoftHSM's OpenSSL libcrypto-3) from the module's own
// directory — a plain LoadLibrary(absolute path) does NOT, which yields the misleading
// "specified module could not be found" when a sibling dependency is present but unsearched.
func loadModule(modulePath string) (windows.Handle, error) {
	if modulePath == "" {
		return 0, fmt.Errorf("JANUS_HSM_MODULE_PATH is required for pkcs11 mode")
	}
	h, err := windows.LoadLibraryEx(modulePath, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
	if err != nil {
		return 0, fmt.Errorf("load PKCS#11 module %q (a dependency DLL, e.g. OpenSSL libcrypto-3, may be missing from the module's own folder): %w", modulePath, err)
	}
	return h, nil
}

// proc resolves and caches a PKCS#11 function address by name. Caller holds the mutex
// (or is in single-threaded setup).
func (c *PKCS11Client) proc(name string) (uintptr, error) {
	if a, ok := c.procs[name]; ok {
		return a, nil
	}
	a, err := windows.GetProcAddress(c.module, name)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: %s not exported by module: %w", name, err)
	}
	c.procs[name] = a
	return a, nil
}

// call invokes a PKCS#11 function and maps a non-OK CK_RV to an error.
func (c *PKCS11Client) call(name string, args ...uintptr) error {
	a, err := c.proc(name)
	if err != nil {
		return err
	}
	r1, _, _ := syscall.SyscallN(a, args...)
	if rv := ckRV(uint32(r1)); rv != ckrOK {
		return fmt.Errorf("pkcs11: %s -> CK_RV=0x%08X", name, uint32(rv))
	}
	return nil
}

// newPKCS11 loads the module, finds the slot (label > index > id), opens a session and logs in.
func newPKCS11(cfg HSMConfig) (HSM, error) {
	h, err := loadModule(cfg.ModulePath)
	if err != nil {
		return nil, err
	}
	c := &PKCS11Client{module: h, procs: make(map[string]uintptr)}
	if err := c.call("C_Initialize", 0); err != nil {
		return nil, err
	}
	slot, err := c.findSlot(cfg)
	if err != nil {
		_ = c.call("C_Finalize", 0)
		return nil, err
	}
	var session ckUlong
	if err := c.call("C_OpenSession", uintptr(slot),
		uintptr(ckfSerialSession|ckfRWSession), 0, 0, uintptr(unsafe.Pointer(&session))); err != nil {
		_ = c.call("C_Finalize", 0)
		return nil, err
	}
	c.session = session
	if cfg.Pin != "" {
		pin := []byte(cfg.Pin)
		if err := c.call("C_Login", uintptr(session), uintptr(ckuUser),
			uintptr(unsafe.Pointer(&pin[0])), uintptr(ckUlong(len(pin)))); err != nil {
			_ = c.call("C_CloseSession", uintptr(session))
			_ = c.call("C_Finalize", 0)
			return nil, fmt.Errorf("login (check JANUS_HSM_PIN): %w", err)
		}
	}
	return c, nil
}

// slotList returns the token-present slot ids.
func (c *PKCS11Client) slotList() ([]ckUlong, error) {
	var count ckUlong
	if err := c.call("C_GetSlotList", uintptr(ckTrue), 0, uintptr(unsafe.Pointer(&count))); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	slots := make([]ckUlong, count)
	if err := c.call("C_GetSlotList", uintptr(ckTrue),
		uintptr(unsafe.Pointer(&slots[0])), uintptr(unsafe.Pointer(&count))); err != nil {
		return nil, err
	}
	return slots[:count], nil
}

func (c *PKCS11Client) findSlot(cfg HSMConfig) (ckUlong, error) {
	slots, err := c.slotList()
	if err != nil {
		return 0, err
	}
	if len(slots) == 0 {
		return 0, fmt.Errorf("no initialized PKCS#11 token found")
	}
	if cfg.Label != "" {
		for _, s := range slots {
			if d, err := c.tokenInfo(s); err == nil && d.Label == cfg.Label {
				return s, nil
			}
		}
		return 0, fmt.Errorf("no initialized token with label %q", cfg.Label)
	}
	if cfg.SlotIndex >= 0 {
		if cfg.SlotIndex >= len(slots) {
			return 0, fmt.Errorf("slot index %d out of range: %d token(s) present", cfg.SlotIndex, len(slots))
		}
		return slots[cfg.SlotIndex], nil
	}
	for _, s := range slots {
		if s == ckUlong(cfg.SlotID) {
			return s, nil
		}
	}
	return slots[0], nil
}

// tokenInfo reads the leading fixed-width string fields of CK_TOKEN_INFO. We over-allocate
// the buffer (CK_TOKEN_INFO is larger) and parse only label/manufacturer/model/serial,
// which occupy the first 96 bytes in a fixed layout independent of CK_ULONG width.
func (c *PKCS11Client) tokenInfo(slot ckUlong) (SlotDetail, error) {
	var buf [512]byte
	if err := c.call("C_GetTokenInfo", uintptr(slot), uintptr(unsafe.Pointer(&buf[0]))); err != nil {
		return SlotDetail{}, err
	}
	trim := func(b []byte) string { return strings.TrimSpace(string(b)) }
	return SlotDetail{
		SlotID:       uint(slot),
		TokenPresent: true,
		Label:        trim(buf[0:32]),
		Manufacturer: trim(buf[32:64]),
		Model:        trim(buf[64:80]),
		SerialNumber: trim(buf[80:96]),
	}, nil
}

// findObjects runs a FindObjects cycle for the template. Caller holds the mutex.
func (c *PKCS11Client) findObjects(template []ckAttribute) ([]ckUlong, error) {
	var tmplPtr uintptr
	if len(template) > 0 {
		tmplPtr = uintptr(unsafe.Pointer(&template[0]))
	}
	if err := c.call("C_FindObjectsInit", uintptr(c.session), tmplPtr, uintptr(ckUlong(len(template)))); err != nil {
		return nil, err
	}
	handles := make([]ckUlong, 256)
	var found ckUlong
	err := c.call("C_FindObjects", uintptr(c.session),
		uintptr(unsafe.Pointer(&handles[0])), uintptr(ckUlong(len(handles))), uintptr(unsafe.Pointer(&found)))
	_ = c.call("C_FindObjectsFinal", uintptr(c.session))
	if err != nil {
		return nil, err
	}
	return handles[:found], nil
}

func labelAttr(label string) ckAttribute {
	b := []byte(label)
	return ckAttribute{typ: ckaLabel, pValue: uintptr(unsafe.Pointer(&b[0])), valueLen: ckUlong(len(b))}
}
func classAttr(class ckUlong) ckAttribute {
	v := class
	return ckAttribute{typ: ckaClass, pValue: uintptr(unsafe.Pointer(&v)), valueLen: ckUlong(unsafe.Sizeof(v))}
}

func (c *PKCS11Client) findOne(class ckUlong, label string) (ckUlong, error) {
	la := labelAttr(label)
	ca := classAttr(class)
	hs, err := c.findObjects([]ckAttribute{ca, la})
	if err != nil {
		return 0, err
	}
	if len(hs) == 0 {
		return 0, fmt.Errorf("pkcs11: object %q not found", label)
	}
	return hs[0], nil
}

func paramSetForWin(algorithm string) (ckUlong, error) {
	switch algorithm {
	case "ML-DSA-44":
		return 1, nil
	case "ML-DSA-65":
		return 2, nil
	case "ML-DSA-87":
		return 3, nil
	default:
		return 0, fmt.Errorf("pkcs11: ML-DSA-44/65/87 supported; %q is not (RSA/ECDSA are never used)", algorithm)
	}
}

func (c *PKCS11Client) genMLDSA(label string, paramSet ckUlong) error {
	id := []byte(label)
	lbl := []byte(label)
	tru := ckTrue
	ps := paramSet
	pub := []ckAttribute{
		{typ: ckaToken, pValue: uintptr(unsafe.Pointer(&tru)), valueLen: 1},
		{typ: ckaVerify, pValue: uintptr(unsafe.Pointer(&tru)), valueLen: 1},
		{typ: ckaLabel, pValue: uintptr(unsafe.Pointer(&lbl[0])), valueLen: ckUlong(len(lbl))},
		{typ: ckaID, pValue: uintptr(unsafe.Pointer(&id[0])), valueLen: ckUlong(len(id))},
		{typ: ckaParameterSet, pValue: uintptr(unsafe.Pointer(&ps)), valueLen: ckUlong(unsafe.Sizeof(ps))},
	}
	priv := []ckAttribute{
		{typ: ckaToken, pValue: uintptr(unsafe.Pointer(&tru)), valueLen: 1},
		{typ: ckaPrivate, pValue: uintptr(unsafe.Pointer(&tru)), valueLen: 1},
		{typ: ckaSign, pValue: uintptr(unsafe.Pointer(&tru)), valueLen: 1},
		{typ: ckaLabel, pValue: uintptr(unsafe.Pointer(&lbl[0])), valueLen: ckUlong(len(lbl))},
		{typ: ckaID, pValue: uintptr(unsafe.Pointer(&id[0])), valueLen: ckUlong(len(id))},
	}
	mech := ckMechanism{mechanism: ckmMLDSAKeyPairGen}
	var hPub, hPriv ckUlong
	return c.call("C_GenerateKeyPair", uintptr(c.session), uintptr(unsafe.Pointer(&mech)),
		uintptr(unsafe.Pointer(&pub[0])), uintptr(ckUlong(len(pub))),
		uintptr(unsafe.Pointer(&priv[0])), uintptr(ckUlong(len(priv))),
		uintptr(unsafe.Pointer(&hPub)), uintptr(unsafe.Pointer(&hPriv)))
}

// --- HSM interface ---------------------------------------------------------------------

func (c *PKCS11Client) GenerateKeyPair(algorithm string) (string, error) {
	if !IsAcceptedPQCSignatureAlg(algorithm) {
		return "", fmt.Errorf("pkcs11: refusing non-PQC signing key %q", algorithm)
	}
	ps, err := paramSetForWin(algorithm)
	if err != nil {
		return "", err
	}
	label := fmt.Sprintf("janus-%s-%s", algorithm, uuid.NewString())
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.genMLDSA(label, ps); err != nil {
		return "", fmt.Errorf("pkcs11: ML-DSA keygen failed (token ML-DSA support?): %w", err)
	}
	return label, nil
}

func (c *PKCS11Client) signWith(class ckUlong, mech ckUlong, label string, data []byte) ([]byte, error) {
	key, err := c.findOne(class, label)
	if err != nil {
		return nil, err
	}
	m := ckMechanism{mechanism: mech}
	if err := c.call("C_SignInit", uintptr(c.session), uintptr(unsafe.Pointer(&m)), uintptr(key)); err != nil {
		return nil, err
	}
	var dataPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}
	var sigLen ckUlong
	if err := c.call("C_Sign", uintptr(c.session), dataPtr, uintptr(ckUlong(len(data))),
		0, uintptr(unsafe.Pointer(&sigLen))); err != nil {
		return nil, err
	}
	sig := make([]byte, sigLen)
	if err := c.call("C_Sign", uintptr(c.session), dataPtr, uintptr(ckUlong(len(data))),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(unsafe.Pointer(&sigLen))); err != nil {
		return nil, err
	}
	return sig[:sigLen], nil
}

func (c *PKCS11Client) Sign(keyID string, data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signWith(ckoPrivateKey, ckmMLDSA, keyID, data)
}

func (c *PKCS11Client) Verify(keyID string, data, signature []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pub, err := c.findOne(ckoPublicKey, keyID)
	if err != nil {
		return false, err
	}
	m := ckMechanism{mechanism: ckmMLDSA}
	if err := c.call("C_VerifyInit", uintptr(c.session), uintptr(unsafe.Pointer(&m)), uintptr(pub)); err != nil {
		return false, err
	}
	var dataPtr, sigPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}
	if len(signature) > 0 {
		sigPtr = uintptr(unsafe.Pointer(&signature[0]))
	}
	if err := c.call("C_Verify", uintptr(c.session), dataPtr, uintptr(ckUlong(len(data))),
		sigPtr, uintptr(ckUlong(len(signature)))); err != nil {
		return false, nil // invalid signature is a clean false
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
	if h, _ := c.findOne(ckoSecretKey, label); h != 0 {
		return nil
	}
	cls, kt := ckoSecretKey, ckkGenericSecret
	tru := ckTrue
	lbl := []byte(label)
	tmpl := []ckAttribute{
		{typ: ckaClass, pValue: uintptr(unsafe.Pointer(&cls)), valueLen: ckUlong(unsafe.Sizeof(cls))},
		{typ: ckaKeyType, pValue: uintptr(unsafe.Pointer(&kt)), valueLen: ckUlong(unsafe.Sizeof(kt))},
		{typ: ckaToken, pValue: uintptr(unsafe.Pointer(&tru)), valueLen: 1},
		{typ: ckaPrivate, pValue: uintptr(unsafe.Pointer(&tru)), valueLen: 1},
		{typ: ckaSign, pValue: uintptr(unsafe.Pointer(&tru)), valueLen: 1},
		{typ: ckaLabel, pValue: uintptr(unsafe.Pointer(&lbl[0])), valueLen: ckUlong(len(lbl))},
		{typ: ckaValue, pValue: uintptr(unsafe.Pointer(&keyMaterial[0])), valueLen: ckUlong(len(keyMaterial))},
	}
	var h ckUlong
	return c.call("C_CreateObject", uintptr(c.session),
		uintptr(unsafe.Pointer(&tmpl[0])), uintptr(ckUlong(len(tmpl))), uintptr(unsafe.Pointer(&h)))
}

// MAC returns HMAC-SHA256 over data using the token-resident generic-secret key (MACSigner).
func (c *PKCS11Client) MAC(label string, data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signWith(ckoSecretKey, ckmSHA256HMAC, label, data)
}

// EnsureMLDSAKey finds or generates the labelled ML-DSA key (CommandKeyManager).
func (c *PKCS11Client) EnsureMLDSAKey(label, algorithm string) (string, error) {
	ps, err := paramSetForWin(algorithm)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if h, _ := c.findOne(ckoPrivateKey, label); h != 0 {
		return label, nil
	}
	if err := c.genMLDSA(label, ps); err != nil {
		return "", err
	}
	return label, nil
}

// PublicKey reads the FIPS 204 public key value from the labelled public-key object.
func (c *PKCS11Client) PublicKey(keyID string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pub, err := c.findOne(ckoPublicKey, keyID)
	if err != nil {
		return nil, err
	}
	// Two-pass C_GetAttributeValue for CKA_VALUE.
	attr := []ckAttribute{{typ: ckaValue}}
	if err := c.call("C_GetAttributeValue", uintptr(c.session), uintptr(pub),
		uintptr(unsafe.Pointer(&attr[0])), 1); err != nil {
		return nil, err
	}
	if attr[0].valueLen == 0 {
		return nil, fmt.Errorf("pkcs11: public key %q has no CKA_VALUE", keyID)
	}
	buf := make([]byte, attr[0].valueLen)
	attr[0].pValue = uintptr(unsafe.Pointer(&buf[0]))
	if err := c.call("C_GetAttributeValue", uintptr(c.session), uintptr(pub),
		uintptr(unsafe.Pointer(&attr[0])), 1); err != nil {
		return nil, err
	}
	return buf[:attr[0].valueLen], nil
}

func (c *PKCS11Client) ListKeys() ([]KeyInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []KeyInfo
	for _, class := range []ckUlong{ckoPrivateKey, ckoSecretKey} {
		ca := classAttr(class)
		handles, err := c.findObjects([]ckAttribute{ca})
		if err != nil {
			return nil, err
		}
		alg := "ML-DSA"
		if class == ckoSecretKey {
			alg = "HMAC-SHA256"
		}
		for _, h := range handles {
			out = append(out, KeyInfo{KeyID: c.readLabel(h), Label: c.readLabel(h), Algorithm: alg, IsPQC: class == ckoPrivateKey})
		}
	}
	return out, nil
}

func (c *PKCS11Client) readLabel(h ckUlong) string {
	attr := []ckAttribute{{typ: ckaLabel}}
	if err := c.call("C_GetAttributeValue", uintptr(c.session), uintptr(h), uintptr(unsafe.Pointer(&attr[0])), 1); err != nil || attr[0].valueLen == 0 {
		return ""
	}
	buf := make([]byte, attr[0].valueLen)
	attr[0].pValue = uintptr(unsafe.Pointer(&buf[0]))
	if err := c.call("C_GetAttributeValue", uintptr(c.session), uintptr(h), uintptr(unsafe.Pointer(&attr[0])), 1); err != nil {
		return ""
	}
	return string(buf[:attr[0].valueLen])
}

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

// RemoveKey destroys every object carrying the label.
func (c *PKCS11Client) RemoveKey(label string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	handles, err := c.findObjects([]ckAttribute{labelAttr(label)})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, h := range handles {
		if err := c.call("C_DestroyObject", uintptr(c.session), uintptr(h)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (c *PKCS11Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.module == 0 {
		return nil
	}
	_ = c.call("C_Logout", uintptr(c.session))
	_ = c.call("C_CloseSession", uintptr(c.session))
	_ = c.call("C_Finalize", 0)
	_ = windows.FreeLibrary(c.module)
	c.module = 0
	return nil
}

// ListSlots enumerates token-present slots without logging in (for `hsm info`).
func ListSlots(modulePath string) ([]SlotDetail, error) {
	h, err := loadModule(modulePath)
	if err != nil {
		return nil, err
	}
	c := &PKCS11Client{module: h, procs: make(map[string]uintptr)}
	if err := c.call("C_Initialize", 0); err != nil {
		return nil, err
	}
	defer func() { _ = c.call("C_Finalize", 0); _ = windows.FreeLibrary(c.module) }()
	slots, err := c.slotList()
	if err != nil {
		return nil, err
	}
	out := make([]SlotDetail, 0, len(slots))
	for i, s := range slots {
		d, err := c.tokenInfo(s)
		if err != nil {
			d = SlotDetail{SlotID: uint(s), TokenPresent: true}
		}
		d.Index = i
		out = append(out, d)
	}
	return out, nil
}

// Compile-time checks that the Windows client satisfies the optional capabilities.
var (
	_ MACSigner         = (*PKCS11Client)(nil)
	_ CommandKeyManager = (*PKCS11Client)(nil)
)
