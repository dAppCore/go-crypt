// SPDX-Licence-Identifier: EUPL-1.2

// Tests for the two construction seams the sealed-key service exposes
// so it never reaches for an application global: the directory
// resolver and the audit recorder. AX-7 triplet per public symbol
// named Test<File>_<Symbol>_<Variant>.

package keys_test

import (
	"sync"

	"dappco.re/go/crypt/keys"

	core "dappco.re/go"
)

// countingResolver records how many times the Service asked for its
// directory — the instrument behind the late-binding assertions.
type countingResolver struct {
	mu    sync.Mutex
	calls int
	dir   string
}

func (c *countingResolver) resolve() core.Result {
	c.mu.Lock()
	c.calls++
	dir := c.dir
	c.mu.Unlock()
	if r := core.MkdirAll(dir, 0o700); !r.OK {
		return r
	}
	return core.Ok(dir)
}

func (c *countingResolver) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// --- WithDir ---

func TestOptions_WithDir_Good(t *core.T) {
	t.Setenv("HOME", t.TempDir())
	custom := core.PathJoin(t.TempDir(), "elsewhere", "keys")

	svc := tier1Fixture(t, keys.WithDir(custom))
	core.AssertTrue(t, svc.PutTier1("openai-default", []byte("sk-injected-dir")).OK)

	// The blob must land under the injected directory, not under the
	// default $HOME/Lethean tree — that is the whole point of the seam.
	blob := core.PathJoin(custom, "openai-default.t1.aead")
	core.AssertTrue(t, core.Stat(blob).OK,
		"tier-1 ciphertext must be written under the injected directory")

	statR := core.Stat(custom)
	core.AssertTrue(t, statR.OK)
	info := statR.Value.(core.FsFileInfo)
	core.AssertEqual(t, "700", core.Sprintf("%o", info.Mode().Perm()),
		"an injected directory is still created owner-only")
}

func TestOptions_WithDir_Bad(t *core.T) {
	t.Setenv("HOME", t.TempDir())
	r := keys.New(keys.WithDir(""))
	core.AssertFalse(t, r.OK, "an empty injected directory must Fail construction")
}

func TestOptions_WithDir_Ugly(t *core.T) {
	t.Setenv("HOME", t.TempDir())
	blocker := core.PathJoin(t.TempDir(), "regular-file")
	core.AssertTrue(t, core.WriteFile(blocker, []byte("x"), 0o644).OK)

	// A directory whose parent is a regular file cannot be created.
	r := keys.New(keys.WithDir(core.PathJoin(blocker, "keys")))
	core.AssertFalse(t, r.OK, "an uncreatable injected directory must Fail construction")

	// Re-constructing over an existing injected directory is fine.
	custom := core.PathJoin(t.TempDir(), "twice")
	core.AssertTrue(t, keys.New(keys.WithDir(custom)).OK)
	core.AssertTrue(t, keys.New(keys.WithDir(custom)).OK)
}

// --- WithDirResolver ---

func TestOptions_WithDirResolver_Good(t *core.T) {
	t.Setenv("HOME", t.TempDir())
	res := &countingResolver{dir: core.PathJoin(t.TempDir(), "resolved")}

	svc := tier1Fixture(t, keys.WithDirResolver(res.resolve))
	atConstruction := res.count()
	core.AssertTrue(t, atConstruction > 0, "construction must ask the resolver once")

	core.AssertTrue(t, svc.PutTier1("openai-default", []byte("sk-late-bound")).OK)
	core.AssertTrue(t, svc.ListTier1().OK)

	// Late binding is the reason this is a resolver and not a string:
	// the Service asks again at every disk touch rather than caching a
	// path that may since have moved.
	core.AssertTrue(t, res.count() > atConstruction,
		"the resolver must be consulted again on subsequent operations, not cached")
}

func TestOptions_WithDirResolver_Bad(t *core.T) {
	t.Setenv("HOME", t.TempDir())
	r := keys.New(keys.WithDirResolver(func() core.Result {
		return core.Fail(core.NewError("host: data root unavailable"))
	}))
	core.AssertFalse(t, r.OK, "a failing resolver must Fail construction")
}

func TestOptions_WithDirResolver_Ugly(t *core.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// A nil resolver is ignored rather than installed, so the Service
	// falls back to the package default instead of panicking on first
	// use — a host passing a zero value gets working software.
	r := keys.New(keys.WithDirResolver(nil), nil)
	core.AssertTrue(t, r.OK)
	core.AssertTrue(t, core.Stat(core.PathJoin(home, "Lethean", "data", "keys")).OK,
		"a nil resolver must fall back to the default $HOME/Lethean/data/keys")
}

// --- WithAuditRecorder ---

func TestOptions_WithAuditRecorder_Good(t *core.T) {
	svc, rec := auditedTier1Fixture(t)
	core.AssertTrue(t, svc.PutTier1("openai-default", []byte("sk-audited")).OK)

	stored := findKeysEvent(rec.snapshot(), keys.AuditEventTier1Stored)
	core.AssertTrue(t, stored != nil, "the injected recorder must receive the row")
	core.AssertEqual(t, keys.AuditScopeKeys, stored.Scope)
	core.AssertEqual(t, keys.AuditOutcomeOK, stored.Outcome)
}

func TestOptions_WithAuditRecorder_Bad(t *core.T) {
	// No recorder injected: the rows drop, but a credential path must
	// never be blocked by the absence of an audit sink.
	svc := tier1Fixture(t, keys.WithAuditRecorder(nil))
	core.AssertNotPanics(t, func() {
		core.AssertTrue(t, svc.PutTier1("openai-default", []byte("sk-unaudited")).OK)
		core.AssertTrue(t, svc.DeleteTier1("openai-default").OK)
	})
}

func TestOptions_WithAuditRecorder_Ugly(t *core.T) {
	// Two Services, two recorders — the seam is per-Service, so one
	// host's trail can never appear in another's.
	svcA, recA := auditedTier1Fixture(t)
	svcB, recB := auditedTier1Fixture(t)

	core.AssertTrue(t, svcA.PutTier1("only-a", []byte("sk-a")).OK)

	core.AssertTrue(t, findKeysEvent(recA.snapshot(), keys.AuditEventTier1Stored) != nil)
	core.AssertEqual(t, 0, len(recB.snapshot()),
		"a second Service's recorder must not see the first Service's rows")
	_ = svcB
}

// TestOptions_WithAuditRecorder_ErrorPath asserts the failure branch
// still records: a rejected ref emits Outcome=error carrying the code
// the injected recorder derived, not a silent drop.
func TestOptions_WithAuditRecorder_ErrorPath(t *core.T) {
	svc, rec := auditedTier1Fixture(t)

	r := svc.DeleteTier1("")
	core.AssertFalse(t, r.OK, "an empty ref must be rejected")

	deleted := findKeysEvent(rec.snapshot(), keys.AuditEventTier1Deleted)
	core.AssertTrue(t, deleted != nil, "a rejected delete must still emit a row")
	core.AssertEqual(t, keys.AuditOutcomeError, deleted.Outcome)
	core.AssertTrue(t, deleted.Meta["error_code"] != nil && deleted.Meta["error_code"] != "",
		"the failure row must carry the error code the recorder derived")
}

// --- Registrar ---

func TestOptions_Registrar_Good(t *core.T) {
	t.Setenv("HOME", t.TempDir())
	custom := core.PathJoin(t.TempDir(), "registered")
	rec := &keysRecordingRecorder{}

	c := core.New(core.WithName("keys", keys.Registrar(
		keys.WithDir(custom),
		keys.WithAuditRecorder(rec),
	)))
	got := c.Service("keys")
	core.AssertTrue(t, got.OK, "keys service discoverable after WithName")
	core.AssertTrue(t, core.Stat(custom).OK,
		"Registrar must carry the injected directory through to construction")
}

func TestOptions_Registrar_Bad(t *core.T) {
	t.Setenv("HOME", t.TempDir())
	c := core.New()
	core.AssertFalse(t, keys.Registrar(keys.WithDir(""))(c).OK,
		"Registrar must propagate a construction failure")
}

func TestOptions_Registrar_Ugly(t *core.T) {
	t.Setenv("HOME", t.TempDir())
	c := core.New()
	reg := keys.Registrar()
	core.AssertTrue(t, reg(c).OK)
	core.AssertNotPanics(t, func() { _ = reg(c) })
}
