// SPDX-Licence-Identifier: EUPL-1.2

package keys

import core "dappco.re/go"

// AuditEvent is the credential-mutation row this package hands to the
// host application's audit substrate. It is deliberately a subset of a
// full audit row: the keys service only ever emits the five fields it
// can honestly populate, so declaring the wider shape here would invite
// a consumer to believe keys fills fields it never touches.
//
// Meta hygiene is load-bearing — the key bytes / passphrase content
// MUST NEVER appear in Meta. Only the opaque ref handle, the
// categorical tier/source discriminators, and the substrate error code
// on failure. This package never hands plaintext to the recorder.
type AuditEvent struct {
	// Event is the dotted event name — one of the AuditEventTier*
	// constants below. Reserved schema: a downstream log-tailer joins
	// on these literals, so renaming one is a wire-contract change.
	Event string `json:"event"`
	// TS is the unix-seconds timestamp at emit time.
	TS int64 `json:"ts"`
	// Scope is the categorical event-family label — always "keys" for
	// rows emitted by this package.
	Scope string `json:"scope,omitempty"`
	// Outcome is AuditOutcomeOK or AuditOutcomeError.
	Outcome string `json:"outcome,omitempty"`
	// Meta carries the per-event fields (ref / kind / tier / source,
	// plus error_code on failure).
	Meta map[string]any `json:"meta,omitempty"`
}

// AuditRecorder is the seam through which a host application receives
// this package's credential-mutation rows. Two methods because the keys
// service needs exactly two things from an audit substrate:
//
//   - Record persists the row. Its core.Result is deliberately ignored
//     at every emit-site — an audit sink failure MUST NEVER block a
//     credential path.
//   - ErrorCode maps a failed core.Result onto the host's bounded error
//     codespace. Keys owns WHICH Meta key that lands under; the host
//     owns WHAT the codespace is, because the host's forensic tooling
//     and any frontend decoder are the things that must stay in
//     lockstep with it. Duplicating that resolution here would fork the
//     codespace the moment the host extended it.
//
// A host satisfies this with a thin adapter over its own audit package;
// nothing about the interface requires the host's event type to change.
type AuditRecorder interface {
	// Record persists one credential-mutation row.
	Record(ev AuditEvent) core.Result
	// ErrorCode maps a failed core.Result onto a bounded error code,
	// returning "" for an OK Result.
	ErrorCode(r core.Result) string
}

// AuditOutcome* are the outcome literals this package emits. A closed
// set so a host's outcome facet stays stable — keys only ever reports
// success or substrate error, never "denied" (it has no policy layer)
// and never "failed" (a rejected ref is an error, not a decision).
const (
	AuditOutcomeOK    = "ok"
	AuditOutcomeError = "error"
)

// AuditScopeKeys is the Scope literal on every row this package emits.
const AuditScopeKeys = "keys"

// AuditEventTier* are the dotted event names for the six
// credential-mutation emit-sites. Reserved schema — these literals are
// the wire contract with the host's audit substrate and with any
// frontend that decodes the resulting rows, so a host mirroring them
// should pin the equality in a test rather than trust prose.
const (
	// AuditEventTier0Stored fires when PutTier0 attempts an at-rest
	// write of a tier-0 (pre-unlock) credential.
	AuditEventTier0Stored = "keys.tier0.stored"
	// AuditEventTier0Deleted fires when DeleteTier0 attempts removal
	// of a tier-0 ciphertext.
	AuditEventTier0Deleted = "keys.tier0.deleted"
	// AuditEventTier1Stored fires when PutTier1 writes a ref that had
	// no prior ciphertext.
	AuditEventTier1Stored = "keys.tier1.stored"
	// AuditEventTier1Replaced fires when PutTier1 writes over an
	// existing ref — distinct from Stored so a forensic walker can
	// tell a first provisioning from a rotation.
	AuditEventTier1Replaced = "keys.tier1.replaced"
	// AuditEventTier1Deleted fires when DeleteTier1 attempts removal
	// of a tier-1 ciphertext.
	AuditEventTier1Deleted = "keys.tier1.deleted"
)

// noopAuditRecorder is the recorder a Service falls back to when a host
// has not injected one. Record drops the row; ErrorCode returns ""
// because with no sink the code is never observed, so deriving one
// would be work in service of nothing. A host that wants the trail
// injects a real recorder via WithAuditRecorder.
type noopAuditRecorder struct{}

// Record drops the row. Returns Ok so the caller's ignored-Result
// contract holds uniformly across recorders.
func (noopAuditRecorder) Record(_ AuditEvent) core.Result { return core.Ok(nil) }

// ErrorCode returns "" — see the type comment for why.
func (noopAuditRecorder) ErrorCode(_ core.Result) string { return "" }
