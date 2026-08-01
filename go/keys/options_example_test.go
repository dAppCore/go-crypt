// SPDX-Licence-Identifier: EUPL-1.2

// Example*** functions for the construction seams. These compile and
// render via `go doc`.

package keys_test

import (
	"dappco.re/go/crypt/keys"

	core "dappco.re/go"
)

// exampleRecorder is the shape a host writes to adapt its own audit
// package onto keys.AuditRecorder — a translation, nothing more.
type exampleRecorder struct{}

func (exampleRecorder) Record(_ keys.AuditEvent) core.Result { return core.Ok(nil) }

func (exampleRecorder) ErrorCode(r core.Result) string {
	if r.OK {
		return ""
	}
	return r.Code()
}

func ExampleWithDir() {
	r := keys.New(keys.WithDir("/var/lib/myapp/keys"))
	if r.OK {
		svc := r.Value.(*keys.Service)
		_ = svc
	}
}

func ExampleWithDirResolver() {
	// The resolver is called at every disk touch, so a host whose data
	// root moves at runtime stays consistent without the Service
	// caching a stale path.
	r := keys.New(keys.WithDirResolver(func() core.Result {
		dir := core.PathJoin(core.UserHomeDir().Value.(string), "myapp", "keys")
		if mk := core.MkdirAll(dir, 0o700); !mk.OK {
			return mk
		}
		return core.Ok(dir)
	}))
	if r.OK {
		svc := r.Value.(*keys.Service)
		_ = svc
	}
}

func ExampleWithAuditRecorder() {
	r := keys.New(keys.WithAuditRecorder(exampleRecorder{}))
	if r.OK {
		svc := r.Value.(*keys.Service)
		_ = svc
	}
}

func ExampleRegistrar() {
	c := core.New(core.WithName("keys", keys.Registrar(
		keys.WithDir("/var/lib/myapp/keys"),
		keys.WithAuditRecorder(exampleRecorder{}),
	)))
	_ = c
}

func ExampleAuditEvent() {
	ev := keys.AuditEvent{
		Event:   keys.AuditEventTier1Stored,
		TS:      core.Now().Unix(),
		Scope:   keys.AuditScopeKeys,
		Outcome: keys.AuditOutcomeOK,
		Meta:    map[string]any{"ref": "openai-default", "tier": "tier1"},
	}
	_ = ev
}

func ExampleAuditRecorder() {
	var rec keys.AuditRecorder = exampleRecorder{}
	_ = rec.Record(keys.AuditEvent{Event: keys.AuditEventTier1Deleted})
}
