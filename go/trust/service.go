// SPDX-License-Identifier: EUPL-1.2

// Service registration for the go-crypt repo. Single repo-level
// service that wraps the auth Authenticator + trust Registry/Policy/
// Approval/Audit handles + the stateless crypt encryption primitives
// behind one Core subsystem so the whole crypt surface can be
// supervised by go-process (in-binary or out-of-process).
//
// Action namespaces preserve the per-domain shape: auth.* for
// Authenticator operations, trust.* for tier/policy/approval
// operations, crypt.* for stateless encryption helpers. Direct method
// use stays available on svc.Authenticator / svc.Registry / etc. for
// callers that need richer signatures (RotateKeyPair, RevokeKey,
// WriteChallengeFile, etc.) which are not IPC-serialisable.
//
//	c, _ := core.New(
//	    core.WithName("crypt", crypt.NewService(crypt.CryptConfig{
//	        Auth: crypt.AuthOptions{
//	            MediumRoot:    "/var/lib/core/auth",
//	            SessionDBPath: "/var/lib/core/auth/sessions.db",
//	        },
//	    })),
//	)
//	r := c.Action("auth.register").Run(ctx, core.NewOptions(
//	    core.Option{Key: "username", Value: "alice"},
//	    core.Option{Key: "password", Value: "•••"},
//	))

package trust

import (
	"context"
	"time"

	core "dappco.re/go"
	"dappco.re/go/crypt/auth"
	"dappco.re/go/crypt/crypt"
	coreio "dappco.re/go/io"
)

// CryptConfig is the unified config for the crypt repo's service.
// AuthOptions configures the Authenticator + SessionStore; TrustOptions
// configures the trust Registry/Policy/Approval/Audit handles. All
// fields are IPC-serialisable so the service can be supervised
// out-of-process by go-process.
//
// Usage example: `cfg := crypt.CryptConfig{Auth: crypt.AuthOptions{MediumRoot: "/var/lib/core/auth"}}`
type CryptConfig struct {
	// Auth configures the auth subsystem (Authenticator + SessionStore).
	// Usage example: `cfg := crypt.CryptConfig{Auth: crypt.AuthOptions{SessionDBPath: "/var/lib/core/auth/sessions.db"}}`
	Auth AuthOptions
	// Trust configures the trust subsystem (Registry/Policy/Approval/
	// Audit). Currently empty — defaults are used.
	// Usage example: `cfg := crypt.CryptConfig{Trust: crypt.TrustOptions{}}`
	Trust TrustOptions
}

// AuthOptions wires the auth subsystem at construction time. Empty
// AuthOptions gives the unsandboxed package medium + an in-memory
// session store (sessions die with the process — fine for tests, not
// for production).
//
// Usage example: `opts := crypt.AuthOptions{MediumRoot: "/var/lib/core/auth", SessionDBPath: "/var/lib/core/auth/sessions.db"}`
type AuthOptions struct {
	// MediumRoot is the sandbox root for user artefacts. Empty = use
	// the unsandboxed package Local medium.
	// Usage example: `opts := crypt.AuthOptions{MediumRoot: "/var/lib/core/auth"}`
	MediumRoot string
	// SessionDBPath is the SQLite path for persistent sessions. Empty
	// = use an in-memory session store.
	// Usage example: `opts := crypt.AuthOptions{SessionDBPath: "/var/lib/core/auth/sessions.db"}`
	SessionDBPath string
	// ChallengeTTL overrides the auth package's DefaultChallengeTTL
	// when non-zero.
	// Usage example: `opts := crypt.AuthOptions{ChallengeTTL: 5 * time.Minute}`
	ChallengeTTL time.Duration
	// SessionTTL overrides the auth package's DefaultSessionTTL when
	// non-zero.
	// Usage example: `opts := crypt.AuthOptions{SessionTTL: 24 * time.Hour}`
	SessionTTL time.Duration
}

// TrustOptions wires the trust subsystem at construction time. Empty
// TrustOptions gives an empty Registry, defaulted PolicyEngine, empty
// ApprovalQueue, and an AuditLog with a nil-writer (entries discarded).
//
// Usage example: `opts := crypt.TrustOptions{}`
type TrustOptions struct{}

// Service is the registerable handle for the go-crypt repo — embeds
// *core.ServiceRuntime[CryptConfig] for typed options access and
// holds the live auth + trust handles for direct method use (stream-
// returning ops + interface-typed inputs / multi-return signatures
// stay direct since they don't cross IPC).
//
// Usage example: `svc := core.MustServiceFor[*crypt.Service](c, "crypt"); svc.Authenticator.RotateKeyPair(...)`
type Service struct {
	*core.ServiceRuntime[CryptConfig]
	// Authenticator is the live auth Authenticator the service wraps.
	// Usage example: `svc.Authenticator.Register("alice", "•••")`
	Authenticator *auth.Authenticator
	// SessionStore is the underlying auth session-store implementation
	// (memory or SQLite, per CryptConfig.Auth.SessionDBPath).
	// Usage example: `_ = svc.SessionStore.Cleanup()`
	SessionStore auth.SessionStore
	// Registry holds the trust agent → tier mapping.
	// Usage example: `_ = svc.Registry.Register(Agent{Name: "alice"})`
	Registry *Registry
	// Policy is the live trust PolicyEngine evaluating capability
	// requests against the Registry.
	// Usage example: `r := svc.Policy.Evaluate("alice", CapRead, "owner/repo")`
	Policy *PolicyEngine
	// Queue holds pending trust approval requests for capabilities the
	// PolicyEngine could not decide automatically.
	// Usage example: `id, _ := svc.Queue.Submit("alice", CapWrite, "owner/repo")`
	Queue *ApprovalQueue
	// Audit captures trust evaluation results for review and replay.
	// Usage example: `entries := svc.Audit.Entries()`
	Audit         *AuditLog
	registrations core.Once
}

// NewService returns a factory that resolves the medium + session
// store from config and produces a *Service ready for c.Service()
// registration.
//
// Usage example: `c, _ := core.New(core.WithName("crypt", crypt.NewService(crypt.CryptConfig{})))`
func NewService(config CryptConfig) func(*core.Core) core.Result {
	return func(c *core.Core) core.Result {
		medium := coreio.Local
		if config.Auth.MediumRoot != "" {
			sandboxed, err := coreio.NewSandboxed(config.Auth.MediumRoot)
			if err != nil {
				return core.Fail(core.E("crypt.NewService", "create sandboxed medium", err))
			}
			medium = sandboxed
		}

		var sessionStore auth.SessionStore
		if config.Auth.SessionDBPath != "" {
			sqlStore, err := auth.NewSQLiteSessionStore(config.Auth.SessionDBPath)
			if err != nil {
				return core.Fail(core.E("crypt.NewService", "open sqlite session store", err))
			}
			sessionStore = sqlStore
		} else {
			sessionStore = auth.NewMemorySessionStore()
		}

		opts := []auth.Option{auth.WithSessionStore(sessionStore)}
		if config.Auth.ChallengeTTL > 0 {
			opts = append(opts, auth.WithChallengeTTL(config.Auth.ChallengeTTL))
		}
		if config.Auth.SessionTTL > 0 {
			opts = append(opts, auth.WithSessionTTL(config.Auth.SessionTTL))
		}

		registry := NewRegistry()

		return core.Ok(&Service{
			ServiceRuntime: core.NewServiceRuntime(c, config),
			Authenticator:  auth.New(medium, opts...),
			SessionStore:   sessionStore,
			Registry:       registry,
			Policy:         NewPolicyEngine(registry),
			Queue:          NewApprovalQueue(),
			Audit:          NewAuditLog(nil),
		})
	}
}

// Register builds the crypt service with default CryptConfig (Local
// medium + in-memory sessions + empty trust registry + nil-writer
// audit) and returns the service Result directly — the imperative-
// style alternative to NewService for consumers wiring services
// without WithName options.
//
// Usage example: `r := crypt.Register(c); svc := r.Value.(*crypt.Service)`
func Register(c *core.Core) core.Result {
	return NewService(CryptConfig{})(c)
}

// OnStartup registers the auth + trust + crypt action handlers on the
// attached Core. Implements core.Startable. Idempotent via core.Once.
//
// Usage example: `r := svc.OnStartup(ctx)`
func (s *Service) OnStartup(context.Context) core.Result {
	if s == nil {
		return core.Ok(nil)
	}
	s.registrations.Do(func() {
		c := s.Core()
		if c == nil {
			return
		}
		c.Action("auth.register", s.handleAuthRegister)
		c.Action("auth.login", s.handleAuthLogin)
		c.Action("auth.challenge.create", s.handleAuthChallengeCreate)
		c.Action("auth.session.validate", s.handleAuthSessionValidate)
		c.Action("auth.session.refresh", s.handleAuthSessionRefresh)
		c.Action("auth.session.revoke", s.handleAuthSessionRevoke)
		c.Action("auth.user.delete", s.handleAuthUserDelete)
		c.Action("auth.user.is_revoked", s.handleAuthUserIsRevoked)
		c.Action("trust.register", s.handleTrustRegister)
		c.Action("trust.remove", s.handleTrustRemove)
		c.Action("trust.evaluate", s.handleTrustEvaluate)
		c.Action("trust.approval.submit", s.handleTrustApprovalSubmit)
		c.Action("trust.approval.approve", s.handleTrustApprovalApprove)
		c.Action("trust.approval.deny", s.handleTrustApprovalDeny)
		c.Action("trust.approval.pending", s.handleTrustApprovalPending)
		c.Action("crypt.encrypt", s.handleCryptEncrypt)
		c.Action("crypt.decrypt", s.handleCryptDecrypt)
		c.Action("crypt.hash.sha256", s.handleCryptSha256)
		c.Action("crypt.hash.sha512", s.handleCryptSha512)
		c.Action("crypt.password.hash", s.handleCryptPasswordHash)
		c.Action("crypt.password.verify", s.handleCryptPasswordVerify)
	})
	return core.Ok(nil)
}

// OnShutdown closes the SQLite session store when one was opened by
// NewService; in-memory stores have nothing to release. The trust
// registry / policy / queue / audit hold no closable resources.
// Implements core.Stoppable.
//
// Usage example: `r := svc.OnShutdown(ctx)`
func (s *Service) OnShutdown(context.Context) core.Result {
	if s == nil || s.SessionStore == nil {
		return core.Ok(nil)
	}
	if closer, ok := s.SessionStore.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			return core.Fail(core.E("crypt.OnShutdown", "close session store", err))
		}
	}
	return core.Ok(nil)
}

// handleAuthRegister — `auth.register` action handler. Reads
// opts.username + opts.password, returns the new *User in r.Value.
//
// Usage example: `r := c.Action("auth.register").Run(ctx, core.NewOptions(core.Option{Key: "username", Value: "alice"}, core.Option{Key: "password", Value: "•••"}))`
func (s *Service) handleAuthRegister(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.register", "service not initialised", nil))
	}
	user, err := s.Authenticator.Register(opts.String("username"), opts.String("password"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(user)
}

// handleAuthLogin — `auth.login` action handler. Reads opts.user_id +
// opts.password, returns the *Session in r.Value.
//
// Usage example: `r := c.Action("auth.login").Run(ctx, core.NewOptions(core.Option{Key: "user_id", Value: id}, core.Option{Key: "password", Value: "•••"}))`
func (s *Service) handleAuthLogin(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.login", "service not initialised", nil))
	}
	session, err := s.Authenticator.Login(opts.String("user_id"), opts.String("password"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(session)
}

// handleAuthChallengeCreate — `auth.challenge.create` action handler.
// Reads opts.user_id, returns the issued *Challenge in r.Value.
//
// Usage example: `r := c.Action("auth.challenge.create").Run(ctx, core.NewOptions(core.Option{Key: "user_id", Value: id}))`
func (s *Service) handleAuthChallengeCreate(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.challenge.create", "service not initialised", nil))
	}
	challenge, err := s.Authenticator.CreateChallenge(opts.String("user_id"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(challenge)
}

// handleAuthSessionValidate — `auth.session.validate` action handler.
// Reads opts.token, returns the resolved *Session in r.Value.
//
// Usage example: `r := c.Action("auth.session.validate").Run(ctx, core.NewOptions(core.Option{Key: "token", Value: tok}))`
func (s *Service) handleAuthSessionValidate(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.session.validate", "service not initialised", nil))
	}
	session, err := s.Authenticator.ValidateSession(opts.String("token"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(session)
}

// handleAuthSessionRefresh — `auth.session.refresh` action handler.
// Reads opts.token, returns the refreshed *Session in r.Value.
//
// Usage example: `r := c.Action("auth.session.refresh").Run(ctx, core.NewOptions(core.Option{Key: "token", Value: tok}))`
func (s *Service) handleAuthSessionRefresh(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.session.refresh", "service not initialised", nil))
	}
	session, err := s.Authenticator.RefreshSession(opts.String("token"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(session)
}

// handleAuthSessionRevoke — `auth.session.revoke` action handler.
// Reads opts.token, removes the session.
//
// Usage example: `r := c.Action("auth.session.revoke").Run(ctx, core.NewOptions(core.Option{Key: "token", Value: tok}))`
func (s *Service) handleAuthSessionRevoke(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.session.revoke", "service not initialised", nil))
	}
	if err := s.Authenticator.RevokeSession(opts.String("token")); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleAuthUserDelete — `auth.user.delete` action handler. Reads
// opts.user_id, removes the user account artefacts.
//
// Usage example: `r := c.Action("auth.user.delete").Run(ctx, core.NewOptions(core.Option{Key: "user_id", Value: id}))`
func (s *Service) handleAuthUserDelete(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.user.delete", "service not initialised", nil))
	}
	if err := s.Authenticator.DeleteUser(opts.String("user_id")); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleAuthUserIsRevoked — `auth.user.is_revoked` action handler.
// Reads opts.user_id, returns bool in r.Value.
//
// Usage example: `r := c.Action("auth.user.is_revoked").Run(ctx, core.NewOptions(core.Option{Key: "user_id", Value: id}))`
func (s *Service) handleAuthUserIsRevoked(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.user.is_revoked", "service not initialised", nil))
	}
	return core.Ok(s.Authenticator.IsRevoked(opts.String("user_id")))
}

// handleTrustRegister — `trust.register` action handler. Reads
// opts.name + opts.tier (int Tier) and adds the agent.
//
// Usage example: `r := c.Action("trust.register").Run(ctx, core.NewOptions(core.Option{Key: "name", Value: "alice"}, core.Option{Key: "tier", Value: int(TierTrusted)}))`
func (s *Service) handleTrustRegister(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Registry == nil {
		return core.Fail(core.E("trust.register", "service not initialised", nil))
	}
	agent := Agent{Name: opts.String("name"), Tier: Tier(opts.Int("tier"))}
	if err := s.Registry.Register(agent); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleTrustRemove — `trust.remove` action handler. Reads opts.name,
// returns bool in r.Value (true if the agent existed and was removed).
//
// Usage example: `r := c.Action("trust.remove").Run(ctx, core.NewOptions(core.Option{Key: "name", Value: "alice"}))`
func (s *Service) handleTrustRemove(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Registry == nil {
		return core.Fail(core.E("trust.remove", "service not initialised", nil))
	}
	return core.Ok(s.Registry.Remove(opts.String("name")))
}

// handleTrustEvaluate — `trust.evaluate` action handler. Reads
// opts.agent + opts.capability + opts.repo and returns the EvalResult
// in r.Value. Audits the result if the AuditLog writer is non-nil.
//
// Usage example: `r := c.Action("trust.evaluate").Run(ctx, core.NewOptions(core.Option{Key: "agent", Value: "alice"}, core.Option{Key: "capability", Value: "read"}, core.Option{Key: "repo", Value: "owner/repo"}))`
func (s *Service) handleTrustEvaluate(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Policy == nil {
		return core.Fail(core.E("trust.evaluate", "service not initialised", nil))
	}
	result := s.Policy.Evaluate(opts.String("agent"), Capability(opts.String("capability")), opts.String("repo"))
	if s.Audit != nil {
		_ = s.Audit.Record(result, opts.String("repo"))
	}
	return core.Ok(result)
}

// handleTrustApprovalSubmit — `trust.approval.submit` action handler.
// Reads opts.agent + opts.capability + opts.repo and returns the
// generated approval-request ID in r.Value.
//
// Usage example: `r := c.Action("trust.approval.submit").Run(ctx, core.NewOptions(core.Option{Key: "agent", Value: "alice"}, core.Option{Key: "capability", Value: "write"}, core.Option{Key: "repo", Value: "owner/repo"}))`
func (s *Service) handleTrustApprovalSubmit(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Queue == nil {
		return core.Fail(core.E("trust.approval.submit", "service not initialised", nil))
	}
	id, err := s.Queue.Submit(opts.String("agent"), Capability(opts.String("capability")), opts.String("repo"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(id)
}

// handleTrustApprovalApprove — `trust.approval.approve` action
// handler. Reads opts.id + opts.reviewed_by + opts.reason.
//
// Usage example: `r := c.Action("trust.approval.approve").Run(ctx, core.NewOptions(core.Option{Key: "id", Value: rid}, core.Option{Key: "reviewed_by", Value: "snider"}, core.Option{Key: "reason", Value: "vetted"}))`
func (s *Service) handleTrustApprovalApprove(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Queue == nil {
		return core.Fail(core.E("trust.approval.approve", "service not initialised", nil))
	}
	if err := s.Queue.Approve(opts.String("id"), opts.String("reviewed_by"), opts.String("reason")); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleTrustApprovalDeny — `trust.approval.deny` action handler.
// Reads opts.id + opts.reviewed_by + opts.reason.
//
// Usage example: `r := c.Action("trust.approval.deny").Run(ctx, core.NewOptions(core.Option{Key: "id", Value: rid}, core.Option{Key: "reviewed_by", Value: "snider"}, core.Option{Key: "reason", Value: "policy"}))`
func (s *Service) handleTrustApprovalDeny(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Queue == nil {
		return core.Fail(core.E("trust.approval.deny", "service not initialised", nil))
	}
	if err := s.Queue.Deny(opts.String("id"), opts.String("reviewed_by"), opts.String("reason")); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleTrustApprovalPending — `trust.approval.pending` action
// handler. Returns []ApprovalRequest in r.Value.
//
// Usage example: `r := c.Action("trust.approval.pending").Run(ctx, core.Options{})`
func (s *Service) handleTrustApprovalPending(_ core.Context, _ core.Options) core.Result {
	if s == nil || s.Queue == nil {
		return core.Fail(core.E("trust.approval.pending", "service not initialised", nil))
	}
	return core.Ok(s.Queue.Pending())
}

// handleCryptEncrypt — `crypt.encrypt` action handler. Reads
// opts.plaintext + opts.passphrase ([]byte each) and returns the
// ciphertext []byte in r.Value via the package Encrypt primitive
// (ChaCha20-Poly1305 + scrypt KDF).
//
// Usage example: `r := c.Action("crypt.encrypt").Run(ctx, core.NewOptions(core.Option{Key: "plaintext", Value: []byte("hi")}, core.Option{Key: "passphrase", Value: []byte("•••")}))`
func (s *Service) handleCryptEncrypt(_ core.Context, opts core.Options) core.Result {
	plaintext := getBytes(opts, "plaintext")
	passphrase := getBytes(opts, "passphrase")
	ciphertext, err := crypt.Encrypt(plaintext, passphrase)
	if err != nil {
		return core.Fail(core.E("crypt.encrypt", "encrypt", err))
	}
	return core.Ok(ciphertext)
}

// handleCryptDecrypt — `crypt.decrypt` action handler. Reads
// opts.ciphertext + opts.passphrase ([]byte each) and returns the
// plaintext []byte in r.Value via the package Decrypt primitive.
//
// Usage example: `r := c.Action("crypt.decrypt").Run(ctx, core.NewOptions(core.Option{Key: "ciphertext", Value: ct}, core.Option{Key: "passphrase", Value: []byte("•••")}))`
func (s *Service) handleCryptDecrypt(_ core.Context, opts core.Options) core.Result {
	ciphertext := getBytes(opts, "ciphertext")
	passphrase := getBytes(opts, "passphrase")
	plaintext, err := crypt.Decrypt(ciphertext, passphrase)
	if err != nil {
		return core.Fail(core.E("crypt.decrypt", "decrypt", err))
	}
	return core.Ok(plaintext)
}

// handleCryptSha256 — `crypt.hash.sha256` action handler. Reads
// opts.data ([]byte) and returns the hex-encoded SHA-256 sum in
// r.Value.
//
// Usage example: `r := c.Action("crypt.hash.sha256").Run(ctx, core.NewOptions(core.Option{Key: "data", Value: []byte("payload")}))`
func (s *Service) handleCryptSha256(_ core.Context, opts core.Options) core.Result {
	data := getBytes(opts, "data")
	return core.Ok(crypt.SHA256Sum(data))
}

// handleCryptSha512 — `crypt.hash.sha512` action handler. Reads
// opts.data ([]byte) and returns the hex-encoded SHA-512 sum in
// r.Value.
//
// Usage example: `r := c.Action("crypt.hash.sha512").Run(ctx, core.NewOptions(core.Option{Key: "data", Value: []byte("payload")}))`
func (s *Service) handleCryptSha512(_ core.Context, opts core.Options) core.Result {
	data := getBytes(opts, "data")
	return core.Ok(crypt.SHA512Sum(data))
}

// handleCryptPasswordHash — `crypt.password.hash` action handler.
// Reads opts.password and returns the bcrypt-hashed string in r.Value.
//
// Usage example: `r := c.Action("crypt.password.hash").Run(ctx, core.NewOptions(core.Option{Key: "password", Value: "•••"}))`
func (s *Service) handleCryptPasswordHash(_ core.Context, opts core.Options) core.Result {
	hashed, err := crypt.HashPassword(opts.String("password"))
	if err != nil {
		return core.Fail(core.E("crypt.password.hash", "hash password", err))
	}
	return core.Ok(hashed)
}

// handleCryptPasswordVerify — `crypt.password.verify` action handler.
// Reads opts.password + opts.hash and returns bool in r.Value.
//
// Usage example: `r := c.Action("crypt.password.verify").Run(ctx, core.NewOptions(core.Option{Key: "password", Value: "•••"}, core.Option{Key: "hash", Value: h}))`
func (s *Service) handleCryptPasswordVerify(_ core.Context, opts core.Options) core.Result {
	ok, err := crypt.VerifyPassword(opts.String("password"), opts.String("hash"))
	if err != nil {
		return core.Fail(core.E("crypt.password.verify", "verify password", err))
	}
	return core.Ok(ok)
}

// getBytes extracts a []byte value from opts, returning nil if absent
// or the wrong type.
func getBytes(opts core.Options, key string) []byte {
	r := opts.Get(key)
	if !r.OK {
		return nil
	}
	b, _ := r.Value.([]byte)
	return b
}
