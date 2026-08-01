// SPDX-Licence-Identifier: EUPL-1.2

package keys

import core "dappco.re/go"

// Option configures a Service at construction. The zero-option Service
// is usable — it resolves its directory under $HOME/Lethean/data/keys
// and drops audit rows — so a host adopts only the seams it needs.
type Option func(*Service)

// WithDirResolver injects the function the Service calls whenever it
// needs its keys directory. The resolver returns the absolute path in
// Result.Value (string) and is expected to create the directory if
// missing.
//
// WHY a resolver rather than a string: the Service calls this at every
// point it touches the directory, exactly where it used to reach for a
// global. A host whose path depends on process state (an unlocked
// profile, a relocated data root, a test rerouting $HOME per case) gets
// the same late binding it had before, and the Service never caches a
// path that has since moved.
//
// Usage example — a host handing over its own path policy:
//
//	svc := keys.New(keys.WithDirResolver(paths.KeysDir))
func WithDirResolver(resolve func() core.Result) Option {
	return func(s *Service) {
		if resolve != nil {
			s.dirResolver = resolve
		}
	}
}

// WithDir pins the Service to one absolute directory, creating it at
// 0700 if missing. The convenience form of WithDirResolver for a host
// that already knows the path.
//
// Usage example:
//
//	svc := keys.New(keys.WithDir("/var/lib/myapp/keys"))
func WithDir(dir string) Option {
	return WithDirResolver(func() core.Result {
		if dir == "" {
			return core.Fail(core.NewError("keys.WithDir: directory must not be empty"))
		}
		if r := core.MkdirAll(dir, dirMode); !r.OK {
			return r
		}
		return core.Ok(dir)
	})
}

// WithAuditRecorder injects the audit substrate that receives this
// package's credential-mutation rows. Without it the rows drop — the
// Service still works, but the credential trail is not written, which
// for a store of bearer credentials is a deliberate decision a host
// should have to make rather than inherit.
//
// Usage example — a host adapting its own audit package:
//
//	svc := keys.New(keys.WithAuditRecorder(myAuditAdapter{}))
func WithAuditRecorder(rec AuditRecorder) Option {
	return func(s *Service) {
		if rec != nil {
			s.audit = rec
		}
	}
}

// keysDir resolves the directory this Service owns, creating it if
// missing. Falls back to defaultKeysDir when no resolver was injected.
func (s *Service) keysDir() core.Result {
	if s != nil && s.dirResolver != nil {
		return s.dirResolver()
	}
	return defaultKeysDir()
}

// auditRecorder returns the injected recorder, or the drop-everything
// noop. Never nil so an emit-site need not nil-check.
func (s *Service) auditRecorder() AuditRecorder {
	if s != nil && s.audit != nil {
		return s.audit
	}
	return noopAuditRecorder{}
}
