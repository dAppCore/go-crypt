// SPDX-License-Identifier: EUPL-1.2

// Service registration for the auth package. Wraps the package
// Authenticator + SessionStore as a self-contained Core subsystem so
// it can be supervised by go-process (in-binary or out-of-process).
//
//	c, _ := core.New(
//	    core.WithName("auth", auth.NewService(auth.AuthConfig{
//	        MediumRoot:     "/var/lib/core/auth",
//	        SessionDBPath:  "/var/lib/core/auth/sessions.db",
//	        ChallengeTTL:   5 * time.Minute,
//	        SessionTTL:     24 * time.Hour,
//	    })),
//	)
//	r := c.Action("auth.register").Run(ctx, core.NewOptions(
//	    core.Option{Key: "username", Value: "alice"},
//	    core.Option{Key: "password", Value: "•••"},
//	))

package auth

import (
	"context"
	"time"

	core "dappco.re/go"
	coreio "dappco.re/go/io"
)

// AuthConfig configures the auth service. All fields are
// IPC-serialisable strings/durations so the service can be supervised
// out-of-process via go-process.
//
// Usage example: `cfg := auth.AuthConfig{MediumRoot: "/var/lib/core/auth", SessionDBPath: "/var/lib/core/auth/sessions.db"}`
type AuthConfig struct {
	// MediumRoot is the sandbox root for user artefacts. Empty = use
	// the unsandboxed package Local medium.
	// Usage example: `cfg := auth.AuthConfig{MediumRoot: "/var/lib/core/auth"}`
	MediumRoot string
	// SessionDBPath is the SQLite path for persistent sessions. Empty
	// = use an in-memory session store (sessions die with the
	// process — fine for tests, not for production).
	// Usage example: `cfg := auth.AuthConfig{SessionDBPath: "/var/lib/core/auth/sessions.db"}`
	SessionDBPath string
	// ChallengeTTL overrides DefaultChallengeTTL when non-zero.
	// Usage example: `cfg := auth.AuthConfig{ChallengeTTL: 5 * time.Minute}`
	ChallengeTTL time.Duration
	// SessionTTL overrides DefaultSessionTTL when non-zero.
	// Usage example: `cfg := auth.AuthConfig{SessionTTL: 24 * time.Hour}`
	SessionTTL time.Duration
}

// Service is the registerable handle for the auth package — embeds
// *core.ServiceRuntime[AuthConfig] for typed options access and holds
// the live *Authenticator + SessionStore (so direct method use stays
// cheap) alongside the action-handler veneer.
//
// Usage example: `svc := core.MustServiceFor[*auth.Service](c, "auth"); svc.Authenticator.Login("user", "pw")`
type Service struct {
	*core.ServiceRuntime[AuthConfig]
	// Authenticator is the live *Authenticator the service wraps.
	// Usage example: `svc.Authenticator.Register("alice", "•••")`
	Authenticator *Authenticator
	// SessionStore is the underlying session-store implementation
	// (memory or SQLite, per AuthConfig.SessionDBPath).
	// Usage example: `_ = svc.SessionStore.Cleanup()`
	SessionStore SessionStore
	registrations core.Once
}

// NewService returns a factory that resolves the medium + session
// store from config and produces a *Service ready for c.Service()
// registration.
//
// Usage example: `c, _ := core.New(core.WithName("auth", auth.NewService(auth.AuthConfig{SessionDBPath: "/var/lib/core/auth/sessions.db"})))`
func NewService(config AuthConfig) func(*core.Core) core.Result {
	return func(c *core.Core) core.Result {
		medium := coreio.Local
		if config.MediumRoot != "" {
			sandboxed, err := coreio.NewSandboxed(config.MediumRoot)
			if err != nil {
				return core.Fail(core.E("auth.NewService", "create sandboxed medium", err))
			}
			medium = sandboxed
		}

		var sessionStore SessionStore
		if config.SessionDBPath != "" {
			sqlStore, err := NewSQLiteSessionStore(config.SessionDBPath)
			if err != nil {
				return core.Fail(core.E("auth.NewService", "open sqlite session store", err))
			}
			sessionStore = sqlStore
		} else {
			sessionStore = NewMemorySessionStore()
		}

		opts := []Option{WithSessionStore(sessionStore)}
		if config.ChallengeTTL > 0 {
			opts = append(opts, WithChallengeTTL(config.ChallengeTTL))
		}
		if config.SessionTTL > 0 {
			opts = append(opts, WithSessionTTL(config.SessionTTL))
		}

		return core.Ok(&Service{
			ServiceRuntime: core.NewServiceRuntime(c, config),
			Authenticator:  New(medium, opts...),
			SessionStore:   sessionStore,
		})
	}
}

// Register builds the auth service with default AuthConfig (Local
// medium + in-memory sessions) and returns the service Result
// directly — the imperative-style alternative to NewService for
// consumers wiring services without WithName options.
//
// Usage example: `r := auth.Register(c); svc := r.Value.(*auth.Service)`
func Register(c *core.Core) core.Result {
	return NewService(AuthConfig{})(c)
}

// OnStartup registers the auth action handlers on the attached Core.
// Implements core.Startable. Idempotent via core.Once.
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
		c.Action("auth.register", s.handleRegister)
		c.Action("auth.login", s.handleLogin)
		c.Action("auth.challenge.create", s.handleChallengeCreate)
		c.Action("auth.session.validate", s.handleSessionValidate)
		c.Action("auth.session.refresh", s.handleSessionRefresh)
		c.Action("auth.session.revoke", s.handleSessionRevoke)
		c.Action("auth.user.delete", s.handleUserDelete)
		c.Action("auth.user.is_revoked", s.handleUserIsRevoked)
	})
	return core.Ok(nil)
}

// OnShutdown closes the SQLite session store when one was opened by
// NewService; in-memory stores have nothing to release. Implements
// core.Stoppable.
//
// Usage example: `r := svc.OnShutdown(ctx)`
func (s *Service) OnShutdown(context.Context) core.Result {
	if s == nil || s.SessionStore == nil {
		return core.Ok(nil)
	}
	if closer, ok := s.SessionStore.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			return core.Fail(core.E("auth.OnShutdown", "close session store", err))
		}
	}
	return core.Ok(nil)
}

// handleRegister — `auth.register` action handler. Reads opts.username
// + opts.password, returns the new *User in r.Value.
//
// Usage example: `r := c.Action("auth.register").Run(ctx, core.NewOptions(core.Option{Key: "username", Value: "alice"}, core.Option{Key: "password", Value: "•••"}))`
func (s *Service) handleRegister(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.register", "service not initialised", nil))
	}
	user, err := s.Authenticator.Register(opts.String("username"), opts.String("password"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(user)
}

// handleLogin — `auth.login` action handler. Reads opts.user_id +
// opts.password, returns the *Session in r.Value.
//
// Usage example: `r := c.Action("auth.login").Run(ctx, core.NewOptions(core.Option{Key: "user_id", Value: id}, core.Option{Key: "password", Value: "•••"}))`
func (s *Service) handleLogin(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.login", "service not initialised", nil))
	}
	session, err := s.Authenticator.Login(opts.String("user_id"), opts.String("password"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(session)
}

// handleChallengeCreate — `auth.challenge.create` action handler.
// Reads opts.user_id, returns the issued *Challenge in r.Value.
//
// Usage example: `r := c.Action("auth.challenge.create").Run(ctx, core.NewOptions(core.Option{Key: "user_id", Value: id}))`
func (s *Service) handleChallengeCreate(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.challenge.create", "service not initialised", nil))
	}
	challenge, err := s.Authenticator.CreateChallenge(opts.String("user_id"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(challenge)
}

// handleSessionValidate — `auth.session.validate` action handler.
// Reads opts.token, returns the resolved *Session in r.Value.
//
// Usage example: `r := c.Action("auth.session.validate").Run(ctx, core.NewOptions(core.Option{Key: "token", Value: tok}))`
func (s *Service) handleSessionValidate(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.session.validate", "service not initialised", nil))
	}
	session, err := s.Authenticator.ValidateSession(opts.String("token"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(session)
}

// handleSessionRefresh — `auth.session.refresh` action handler.
// Reads opts.token, returns the refreshed *Session in r.Value.
//
// Usage example: `r := c.Action("auth.session.refresh").Run(ctx, core.NewOptions(core.Option{Key: "token", Value: tok}))`
func (s *Service) handleSessionRefresh(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.session.refresh", "service not initialised", nil))
	}
	session, err := s.Authenticator.RefreshSession(opts.String("token"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(session)
}

// handleSessionRevoke — `auth.session.revoke` action handler. Reads
// opts.token, removes the session.
//
// Usage example: `r := c.Action("auth.session.revoke").Run(ctx, core.NewOptions(core.Option{Key: "token", Value: tok}))`
func (s *Service) handleSessionRevoke(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.session.revoke", "service not initialised", nil))
	}
	if err := s.Authenticator.RevokeSession(opts.String("token")); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleUserDelete — `auth.user.delete` action handler. Reads
// opts.user_id, removes the user account artefacts.
//
// Usage example: `r := c.Action("auth.user.delete").Run(ctx, core.NewOptions(core.Option{Key: "user_id", Value: id}))`
func (s *Service) handleUserDelete(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.user.delete", "service not initialised", nil))
	}
	if err := s.Authenticator.DeleteUser(opts.String("user_id")); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleUserIsRevoked — `auth.user.is_revoked` action handler. Reads
// opts.user_id, returns bool in r.Value.
//
// Usage example: `r := c.Action("auth.user.is_revoked").Run(ctx, core.NewOptions(core.Option{Key: "user_id", Value: id}))`
func (s *Service) handleUserIsRevoked(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Authenticator == nil {
		return core.Fail(core.E("auth.user.is_revoked", "service not initialised", nil))
	}
	return core.Ok(s.Authenticator.IsRevoked(opts.String("user_id")))
}
