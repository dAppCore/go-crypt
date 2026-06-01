// SPDX-License-Identifier: EUPL-1.2
package trust

import (
	"testing"
	"time"

	core "dappco.re/go"
	"dappco.re/go/crypt/auth"
)

// registeredUserID extracts the KeyID (the login user_id) from an
// auth.register action result.
func registeredUserID(t testing.TB, r core.Result) string {
	t.Helper()
	user, ok := r.Value.(*auth.User)
	mustTrue(t, ok, "register result should carry *auth.User")
	return user.KeyID
}

// sessionToken extracts the session token from an auth.login result.
func sessionToken(t testing.TB, r core.Result) string {
	t.Helper()
	session, ok := r.Value.(*auth.Session)
	mustTrue(t, ok, "login result should carry *auth.Session")
	return session.Token
}

// newTestService builds a fully-wired crypt Service on a fresh Core with
// default in-memory config and runs ServiceStartup so every auth.* /
// trust.* / crypt.* action handler is registered. Returns the live Core
// for Action(...).Run dispatch.
//
//	c, svc := newTestService(t)
//	r := c.Action("crypt.hash.sha256").Run(core.Background(), core.NewOptions(...))
func newTestService(t testing.TB) (*core.Core, *Service) {
	t.Helper()
	// Sandbox auth artefacts under a per-test temp dir so user registration
	// does not collide with the real package directory or sibling tests.
	c := core.New(core.WithName("crypt", NewService(CryptConfig{
		Auth: AuthOptions{MediumRoot: t.TempDir()},
	})))
	svc, ok := core.ServiceFor[*Service](c, "crypt")
	mustTrue(t, ok, "crypt service should register")
	mustNotNil(t, svc, "service handle should be non-nil")
	r := c.ServiceStartup(core.Background(), nil)
	mustTrue(t, r.OK, "service startup should succeed")
	return c, svc
}

// TestServiceBehaviour_NewService_Good wires the default config and
// asserts every embedded handle is live.
func TestServiceBehaviour_NewService_Good(t *core.T) {
	_, svc := newTestService(t)
	wantNotNil(t, svc.Authenticator, "authenticator")
	wantNotNil(t, svc.SessionStore, "session store")
	wantNotNil(t, svc.Registry, "registry")
	wantNotNil(t, svc.Policy, "policy")
	wantNotNil(t, svc.Queue, "queue")
	wantNotNil(t, svc.Audit, "audit")
}

// TestServiceBehaviour_NewService_Bad wires a non-empty MediumRoot so
// the sandboxed-medium branch executes (local media construction does
// not error), and a non-zero ChallengeTTL/SessionTTL so the TTL option
// branches are exercised. The resulting service is fully live.
func TestServiceBehaviour_NewService_Bad(t *core.T) {
	c := core.New()
	factory := NewService(CryptConfig{Auth: AuthOptions{
		MediumRoot:   t.TempDir(),
		ChallengeTTL: 5 * time.Minute,
		SessionTTL:   24 * time.Hour,
	}})
	r := factory(c)
	mustTrue(t, r.OK, "sandboxed medium + TTL overrides should construct a live service")
	svc, ok := r.Value.(*Service)
	mustTrue(t, ok, "value should be *Service")
	wantNotNil(t, svc.Authenticator, "authenticator wired over sandboxed medium")
}

// TestServiceBehaviour_NewService_Ugly opens a SQLite session store at a
// path that cannot be created, surfacing the open error.
func TestServiceBehaviour_NewService_Ugly(t *core.T) {
	c := core.New()
	factory := NewService(CryptConfig{Auth: AuthOptions{SessionDBPath: "/this/path/cannot/exist/sessions.db"}})
	r := factory(c)
	wantFalse(t, r.OK, "opening a sqlite store at an uncreatable path should fail")
}

// TestServiceBehaviour_Register_Good wires the imperative Register
// helper and asserts a live service result.
func TestServiceBehaviour_Register_Good(t *core.T) {
	c := core.New()
	r := Register(c)
	mustTrue(t, r.OK, "Register should succeed with defaults")
	svc, ok := r.Value.(*Service)
	mustTrue(t, ok, "Register value should be *Service")
	wantNotNil(t, svc.Registry, "registry should be wired by Register")
}

// TestServiceBehaviour_OnStartup_Idempotent confirms repeated startup is
// a no-op (core.Once) and that a nil service is safe.
func TestServiceBehaviour_OnStartup_Idempotent(t *core.T) {
	c, svc := newTestService(t)
	r := svc.OnStartup(core.Background())
	wantTrue(t, r.OK, "second OnStartup should be a safe no-op")
	wantTrue(t, c.Action("auth.register").Exists(), "auth.register stays registered")

	var nilSvc *Service
	rNil := nilSvc.OnStartup(core.Background())
	wantTrue(t, rNil.OK, "nil service OnStartup is safe")
}

// TestServiceBehaviour_OnShutdown_Memory closes a memory-backed service
// cleanly; the in-memory store has nothing to release.
func TestServiceBehaviour_OnShutdown_Memory(t *core.T) {
	_, svc := newTestService(t)
	r := svc.OnShutdown(core.Background())
	wantTrue(t, r.OK, "shutdown of a memory-store service should succeed")

	var nilSvc *Service
	rNil := nilSvc.OnShutdown(core.Background())
	wantTrue(t, rNil.OK, "nil service OnShutdown is safe")
}

// TestServiceBehaviour_OnShutdown_SQLite closes a SQLite-backed session
// store via the Close path.
func TestServiceBehaviour_OnShutdown_SQLite(t *core.T) {
	dbPath := t.TempDir() + "/sessions.db"
	c := core.New(core.WithName("crypt", NewService(CryptConfig{Auth: AuthOptions{SessionDBPath: dbPath}})))
	svc, ok := core.ServiceFor[*Service](c, "crypt")
	mustTrue(t, ok, "service should register with sqlite store")
	r := svc.OnShutdown(core.Background())
	wantTrue(t, r.OK, "shutdown should close the sqlite store cleanly")
}

// --- auth.* action handlers ---------------------------------------------

// TestServiceBehaviour_AuthRegisterLogin_Good drives the full register →
// login → validate → refresh → revoke session lifecycle through actions.
func TestServiceBehaviour_AuthRegisterLogin_Good(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()

	reg := c.Action("auth.register").Run(ctx, core.NewOptions(
		core.Option{Key: "username", Value: "alice"},
		core.Option{Key: "password", Value: "hunter2"},
	))
	mustTrue(t, reg.OK, "register should succeed")
	uid := registeredUserID(t, reg)

	login := c.Action("auth.login").Run(ctx, core.NewOptions(
		core.Option{Key: "user_id", Value: uid},
		core.Option{Key: "password", Value: "hunter2"},
	))
	mustTrue(t, login.OK, "login should succeed")
	token := sessionToken(t, login)
	wantNotEmpty(t, token, "session token")

	val := c.Action("auth.session.validate").Run(ctx, core.NewOptions(
		core.Option{Key: "token", Value: token},
	))
	wantTrue(t, val.OK, "session validate should succeed")

	ref := c.Action("auth.session.refresh").Run(ctx, core.NewOptions(
		core.Option{Key: "token", Value: token},
	))
	wantTrue(t, ref.OK, "session refresh should succeed")

	isRev := c.Action("auth.user.is_revoked").Run(ctx, core.NewOptions(
		core.Option{Key: "user_id", Value: uid},
	))
	mustTrue(t, isRev.OK, "is_revoked query should succeed")
	wantFalse(t, isRev.Value.(bool), "fresh user should not be revoked")

	rev := c.Action("auth.session.revoke").Run(ctx, core.NewOptions(
		core.Option{Key: "token", Value: token},
	))
	wantTrue(t, rev.OK, "session revoke should succeed")
}

// TestServiceBehaviour_AuthChallenge_Good issues a challenge for a
// registered user.
func TestServiceBehaviour_AuthChallenge_Good(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()
	reg := c.Action("auth.register").Run(ctx, core.NewOptions(
		core.Option{Key: "username", Value: "charlie"},
		core.Option{Key: "password", Value: "pass"},
	))
	mustTrue(t, reg.OK, "register should succeed")
	uid := registeredUserID(t, reg)

	ch := c.Action("auth.challenge.create").Run(ctx, core.NewOptions(
		core.Option{Key: "user_id", Value: uid},
	))
	wantTrue(t, ch.OK, "challenge create should succeed")
}

// TestServiceBehaviour_AuthUserDelete_Good removes a registered user.
func TestServiceBehaviour_AuthUserDelete_Good(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()
	reg := c.Action("auth.register").Run(ctx, core.NewOptions(
		core.Option{Key: "username", Value: "dave"},
		core.Option{Key: "password", Value: "pass"},
	))
	mustTrue(t, reg.OK, "register should succeed")
	uid := registeredUserID(t, reg)

	del := c.Action("auth.user.delete").Run(ctx, core.NewOptions(
		core.Option{Key: "user_id", Value: uid},
	))
	wantTrue(t, del.OK, "user delete should succeed")
}

// TestServiceBehaviour_AuthLogin_Bad rejects login for an unknown user.
func TestServiceBehaviour_AuthLogin_Bad(t *core.T) {
	c, _ := newTestService(t)
	r := c.Action("auth.login").Run(core.Background(), core.NewOptions(
		core.Option{Key: "user_id", Value: "no-such-user"},
		core.Option{Key: "password", Value: "x"},
	))
	wantFalse(t, r.OK, "login for an unknown user should fail")
}

// TestServiceBehaviour_AuthSessionValidate_Bad rejects a bogus token.
func TestServiceBehaviour_AuthSessionValidate_Bad(t *core.T) {
	c, _ := newTestService(t)
	r := c.Action("auth.session.validate").Run(core.Background(), core.NewOptions(
		core.Option{Key: "token", Value: "not-a-real-token"},
	))
	wantFalse(t, r.OK, "validating a bogus token should fail")
}

// TestServiceBehaviour_AuthHandlers_NilService_Ugly proves every auth
// handler fails closed when invoked on a nil service.
func TestServiceBehaviour_AuthHandlers_NilService_Ugly(t *core.T) {
	var s *Service
	opts := core.NewOptions()
	cases := []func(core.Context, core.Options) core.Result{
		s.handleAuthRegister, s.handleAuthLogin, s.handleAuthChallengeCreate,
		s.handleAuthSessionValidate, s.handleAuthSessionRefresh, s.handleAuthSessionRevoke,
		s.handleAuthUserDelete, s.handleAuthUserIsRevoked,
	}
	for i, fn := range cases {
		r := fn(core.Background(), opts)
		wantFalse(t, r.OK, testMessagef("nil-service auth handler %d should fail closed", i))
	}
}

// --- trust.* action handlers --------------------------------------------

// TestServiceBehaviour_TrustRegisterRemove_Good registers an agent then
// removes it.
func TestServiceBehaviour_TrustRegisterRemove_Good(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()
	reg := c.Action("trust.register").Run(ctx, core.NewOptions(
		core.Option{Key: "name", Value: "athena"},
		core.Option{Key: "tier", Value: int(TierFull)},
	))
	wantTrue(t, reg.OK, "trust register should succeed")

	rem := c.Action("trust.remove").Run(ctx, core.NewOptions(
		core.Option{Key: "name", Value: "athena"},
	))
	mustTrue(t, rem.OK, "trust remove should succeed")
	wantTrue(t, rem.Value.(bool), "removing a registered agent returns true")

	remAgain := c.Action("trust.remove").Run(ctx, core.NewOptions(
		core.Option{Key: "name", Value: "athena"},
	))
	wantFalse(t, remAgain.Value.(bool), "removing an absent agent returns false")
}

// TestServiceBehaviour_TrustRegister_Bad rejects an invalid tier.
func TestServiceBehaviour_TrustRegister_Bad(t *core.T) {
	c, _ := newTestService(t)
	r := c.Action("trust.register").Run(core.Background(), core.NewOptions(
		core.Option{Key: "name", Value: "rogue"},
		core.Option{Key: "tier", Value: 99},
	))
	wantFalse(t, r.OK, "registering an agent with an invalid tier should fail")
}

// TestServiceBehaviour_TrustEvaluate_Good evaluates a capability for a
// registered full-tier agent and records to audit.
func TestServiceBehaviour_TrustEvaluate_Good(t *core.T) {
	c, svc := newTestService(t)
	ctx := core.Background()
	wantTrue(t, c.Action("trust.register").Run(ctx, core.NewOptions(
		core.Option{Key: "name", Value: "athena"},
		core.Option{Key: "tier", Value: int(TierFull)},
	)).OK, "register")

	r := c.Action("trust.evaluate").Run(ctx, core.NewOptions(
		core.Option{Key: "agent", Value: "athena"},
		core.Option{Key: "capability", Value: string(CapPushRepo)},
		core.Option{Key: "repo", Value: "owner/repo"},
	))
	mustTrue(t, r.OK, "evaluate should succeed")
	res, ok := r.Value.(EvalResult)
	mustTrue(t, ok, "evaluate value should be EvalResult")
	_ = res
	// Audit log is nil-writer by default but Record is still invoked.
	wantNotNil(t, svc.Audit, "audit handle live")
}

// TestServiceBehaviour_TrustApprovalFlow_Good submits a request then
// approves it, and a second submission then denies it.
func TestServiceBehaviour_TrustApprovalFlow_Good(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()

	sub := c.Action("trust.approval.submit").Run(ctx, core.NewOptions(
		core.Option{Key: "agent", Value: "alice"},
		core.Option{Key: "capability", Value: string(CapMergePR)},
		core.Option{Key: "repo", Value: "owner/repo"},
	))
	mustTrue(t, sub.OK, "approval submit should succeed")
	id, ok := sub.Value.(string)
	mustTrue(t, ok, "submit value should be a request id")
	wantNotEmpty(t, id, "request id")

	pend := c.Action("trust.approval.pending").Run(ctx, core.NewOptions())
	mustTrue(t, pend.OK, "pending listing should succeed")
	wantLen(t, pend.Value.([]ApprovalRequest), 1, "one pending request")

	app := c.Action("trust.approval.approve").Run(ctx, core.NewOptions(
		core.Option{Key: "id", Value: id},
		core.Option{Key: "reviewed_by", Value: "snider"},
		core.Option{Key: "reason", Value: "vetted"},
	))
	wantTrue(t, app.OK, "approve should succeed")

	// Approving again should fail — no longer pending.
	appAgain := c.Action("trust.approval.approve").Run(ctx, core.NewOptions(
		core.Option{Key: "id", Value: id},
		core.Option{Key: "reviewed_by", Value: "snider"},
		core.Option{Key: "reason", Value: "again"},
	))
	wantFalse(t, appAgain.OK, "re-approving a resolved request should fail")

	// Submit a second and deny it.
	sub2 := c.Action("trust.approval.submit").Run(ctx, core.NewOptions(
		core.Option{Key: "agent", Value: "bob"},
		core.Option{Key: "capability", Value: string(CapMergePR)},
		core.Option{Key: "repo", Value: "owner/repo"},
	))
	mustTrue(t, sub2.OK, "second submit should succeed")
	id2 := sub2.Value.(string)
	den := c.Action("trust.approval.deny").Run(ctx, core.NewOptions(
		core.Option{Key: "id", Value: id2},
		core.Option{Key: "reviewed_by", Value: "snider"},
		core.Option{Key: "reason", Value: "policy"},
	))
	wantTrue(t, den.OK, "deny should succeed")
}

// TestServiceBehaviour_TrustApproval_Bad approves/denies an unknown id.
func TestServiceBehaviour_TrustApproval_Bad(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()
	app := c.Action("trust.approval.approve").Run(ctx, core.NewOptions(
		core.Option{Key: "id", Value: "no-such-id"},
		core.Option{Key: "reviewed_by", Value: "x"},
		core.Option{Key: "reason", Value: "y"},
	))
	wantFalse(t, app.OK, "approving an unknown request should fail")

	den := c.Action("trust.approval.deny").Run(ctx, core.NewOptions(
		core.Option{Key: "id", Value: "no-such-id"},
		core.Option{Key: "reviewed_by", Value: "x"},
		core.Option{Key: "reason", Value: "y"},
	))
	wantFalse(t, den.OK, "denying an unknown request should fail")
}

// TestServiceBehaviour_TrustHandlers_NilService_Ugly proves every trust
// handler fails closed on a nil service.
func TestServiceBehaviour_TrustHandlers_NilService_Ugly(t *core.T) {
	var s *Service
	opts := core.NewOptions()
	cases := []func(core.Context, core.Options) core.Result{
		s.handleTrustRegister, s.handleTrustRemove, s.handleTrustEvaluate,
		s.handleTrustApprovalSubmit, s.handleTrustApprovalApprove,
		s.handleTrustApprovalDeny, s.handleTrustApprovalPending,
	}
	for i, fn := range cases {
		r := fn(core.Background(), opts)
		wantFalse(t, r.OK, testMessagef("nil-service trust handler %d should fail closed", i))
	}
}

// --- crypt.* action handlers --------------------------------------------

// TestServiceBehaviour_CryptEncryptDecrypt_Good round-trips ciphertext
// through the encrypt/decrypt actions.
func TestServiceBehaviour_CryptEncryptDecrypt_Good(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()
	plaintext := []byte("top secret payload")
	passphrase := []byte("correct horse battery staple")

	enc := c.Action("crypt.encrypt").Run(ctx, core.NewOptions(
		core.Option{Key: "plaintext", Value: plaintext},
		core.Option{Key: "passphrase", Value: passphrase},
	))
	mustTrue(t, enc.OK, "encrypt should succeed")
	ciphertext, ok := enc.Value.([]byte)
	mustTrue(t, ok, "ciphertext should be []byte")
	wantNotEmpty(t, ciphertext, "ciphertext")
	wantNotEqual(t, plaintext, ciphertext, "ciphertext differs from plaintext")

	dec := c.Action("crypt.decrypt").Run(ctx, core.NewOptions(
		core.Option{Key: "ciphertext", Value: ciphertext},
		core.Option{Key: "passphrase", Value: passphrase},
	))
	mustTrue(t, dec.OK, "decrypt should succeed")
	wantEqual(t, plaintext, dec.Value.([]byte), "round-trip restores plaintext")
}

// TestServiceBehaviour_CryptDecrypt_Bad rejects a wrong passphrase and
// tampered ciphertext.
func TestServiceBehaviour_CryptDecrypt_Bad(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()
	enc := c.Action("crypt.encrypt").Run(ctx, core.NewOptions(
		core.Option{Key: "plaintext", Value: []byte("data")},
		core.Option{Key: "passphrase", Value: []byte("right")},
	))
	mustTrue(t, enc.OK, "encrypt should succeed")
	ciphertext := enc.Value.([]byte)

	wrong := c.Action("crypt.decrypt").Run(ctx, core.NewOptions(
		core.Option{Key: "ciphertext", Value: ciphertext},
		core.Option{Key: "passphrase", Value: []byte("wrong")},
	))
	wantFalse(t, wrong.OK, "decrypt with the wrong passphrase should fail")

	// Tamper with the final byte (AEAD tag) and decrypt with the right key.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF
	tamper := c.Action("crypt.decrypt").Run(ctx, core.NewOptions(
		core.Option{Key: "ciphertext", Value: tampered},
		core.Option{Key: "passphrase", Value: []byte("right")},
	))
	wantFalse(t, tamper.OK, "decrypt of tampered ciphertext should fail")
}

// TestServiceBehaviour_CryptHash_Good computes SHA-256 and SHA-512 hex
// digests over a known payload.
func TestServiceBehaviour_CryptHash_Good(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()
	data := []byte("payload")

	s256 := c.Action("crypt.hash.sha256").Run(ctx, core.NewOptions(
		core.Option{Key: "data", Value: data},
	))
	mustTrue(t, s256.OK, "sha256 should succeed")
	wantLen(t, s256.Value.(string), 64, "sha256 hex length")

	s512 := c.Action("crypt.hash.sha512").Run(ctx, core.NewOptions(
		core.Option{Key: "data", Value: data},
	))
	mustTrue(t, s512.OK, "sha512 should succeed")
	wantLen(t, s512.Value.(string), 128, "sha512 hex length")
}

// TestServiceBehaviour_CryptPassword_Good hashes then verifies a
// password, and rejects a wrong one.
func TestServiceBehaviour_CryptPassword_Good(t *core.T) {
	c, _ := newTestService(t)
	ctx := core.Background()

	hash := c.Action("crypt.password.hash").Run(ctx, core.NewOptions(
		core.Option{Key: "password", Value: "s3cret"},
	))
	mustTrue(t, hash.OK, "password hash should succeed")
	hashed := hash.Value.(string)
	wantNotEmpty(t, hashed, "hashed password")

	ok := c.Action("crypt.password.verify").Run(ctx, core.NewOptions(
		core.Option{Key: "password", Value: "s3cret"},
		core.Option{Key: "hash", Value: hashed},
	))
	mustTrue(t, ok.OK, "verify should succeed")
	wantTrue(t, ok.Value.(bool), "correct password verifies true")

	bad := c.Action("crypt.password.verify").Run(ctx, core.NewOptions(
		core.Option{Key: "password", Value: "wrong"},
		core.Option{Key: "hash", Value: hashed},
	))
	mustTrue(t, bad.OK, "verify of a wrong password returns a result, not an error")
	wantFalse(t, bad.Value.(bool), "wrong password verifies false")
}

// TestServiceBehaviour_CryptPasswordVerify_Bad surfaces an error for a
// malformed hash.
func TestServiceBehaviour_CryptPasswordVerify_Bad(t *core.T) {
	c, _ := newTestService(t)
	r := c.Action("crypt.password.verify").Run(core.Background(), core.NewOptions(
		core.Option{Key: "password", Value: "x"},
		core.Option{Key: "hash", Value: "not-a-valid-hash"},
	))
	wantFalse(t, r.OK, "verifying against a malformed hash should fail")
}

// TestServiceBehaviour_GetBytes covers the getBytes helper: present []byte,
// absent key, and wrong-typed value all behave as documented.
func TestServiceBehaviour_GetBytes(t *core.T) {
	opts := core.NewOptions(
		core.Option{Key: "good", Value: []byte("abc")},
		core.Option{Key: "wrong", Value: 42},
	)
	wantEqual(t, []byte("abc"), getBytes(opts, "good"), "present []byte returned verbatim")
	wantNil(t, getBytes(opts, "absent"), "absent key yields nil")
	wantNil(t, getBytes(opts, "wrong"), "wrong-typed value yields nil")
}
