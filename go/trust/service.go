// SPDX-License-Identifier: EUPL-1.2

// Service registration for the trust package. Wraps the Registry +
// PolicyEngine + ApprovalQueue + AuditLog as a self-contained Core
// subsystem so it can be supervised by go-process (in-binary or
// out-of-process).
//
//	c, _ := core.New(
//	    core.WithName("trust", trust.NewService(trust.TrustConfig{})),
//	)
//	r := c.Action("trust.register").Run(ctx, core.NewOptions(
//	    core.Option{Key: "name", Value: "alice"},
//	    core.Option{Key: "tier", Value: int(trust.TierTrusted)},
//	))

package trust

import (
	"context"

	core "dappco.re/go"
)

// TrustConfig configures the trust service. Empty config gives an
// empty Registry, defaulted PolicyEngine, empty ApprovalQueue, and an
// AuditLog that discards entries (the writer is nil-safe).
//
// Usage example: `cfg := trust.TrustConfig{}`
type TrustConfig struct{}

// Service is the registerable handle for the trust package — embeds
// *core.ServiceRuntime[TrustConfig] for typed options access and
// holds live Registry/PolicyEngine/ApprovalQueue/AuditLog handles for
// direct method use.
//
// Usage example: `svc := core.MustServiceFor[*trust.Service](c, "trust"); svc.Registry.List()`
type Service struct {
	*core.ServiceRuntime[TrustConfig]
	// Registry holds the agent → tier mapping.
	// Usage example: `_ = svc.Registry.Register(trust.Agent{Name: "alice"})`
	Registry *Registry
	// Policy is the live PolicyEngine evaluating capability requests
	// against the Registry.
	// Usage example: `r := svc.Policy.Evaluate("alice", trust.CapRead, "owner/repo")`
	Policy *PolicyEngine
	// Queue holds pending approval requests for capabilities the
	// PolicyEngine could not decide automatically.
	// Usage example: `id, _ := svc.Queue.Submit("alice", trust.CapWrite, "owner/repo")`
	Queue *ApprovalQueue
	// Audit captures evaluation results for review and replay.
	// Usage example: `entries := svc.Audit.Entries()`
	Audit *AuditLog
	registrations core.Once
}

// NewService returns a factory that constructs the trust subsystem
// (empty Registry, defaulted PolicyEngine, empty ApprovalQueue, nil-
// writer AuditLog) and produces a *Service ready for c.Service()
// registration.
//
// Usage example: `c, _ := core.New(core.WithName("trust", trust.NewService(trust.TrustConfig{})))`
func NewService(config TrustConfig) func(*core.Core) core.Result {
	return func(c *core.Core) core.Result {
		registry := NewRegistry()
		return core.Ok(&Service{
			ServiceRuntime: core.NewServiceRuntime(c, config),
			Registry:       registry,
			Policy:         NewPolicyEngine(registry),
			Queue:          NewApprovalQueue(),
			Audit:          NewAuditLog(nil),
		})
	}
}

// Register builds the trust service with default TrustConfig and
// returns the service Result directly — the imperative-style
// alternative to NewService for consumers wiring services without
// WithName options.
//
// Usage example: `r := trust.Register(c); svc := r.Value.(*trust.Service)`
func Register(c *core.Core) core.Result {
	return NewService(TrustConfig{})(c)
}

// OnStartup registers the trust action handlers on the attached
// Core. Implements core.Startable. Idempotent via core.Once.
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
		c.Action("trust.register", s.handleRegister)
		c.Action("trust.remove", s.handleRemove)
		c.Action("trust.evaluate", s.handleEvaluate)
		c.Action("trust.approval.submit", s.handleApprovalSubmit)
		c.Action("trust.approval.approve", s.handleApprovalApprove)
		c.Action("trust.approval.deny", s.handleApprovalDeny)
		c.Action("trust.approval.pending", s.handleApprovalPending)
	})
	return core.Ok(nil)
}

// OnShutdown is a no-op — Registry/PolicyEngine/ApprovalQueue hold
// no closable resources, and the AuditLog writer (if any) is owned
// by the constructor caller. Implements core.Stoppable.
//
// Usage example: `r := svc.OnShutdown(ctx)`
func (s *Service) OnShutdown(context.Context) core.Result {
	return core.Ok(nil)
}

// handleRegister — `trust.register` action handler. Reads opts.name
// + opts.tier (int Tier) and adds the agent.
//
// Usage example: `r := c.Action("trust.register").Run(ctx, core.NewOptions(core.Option{Key: "name", Value: "alice"}, core.Option{Key: "tier", Value: int(trust.TierTrusted)}))`
func (s *Service) handleRegister(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Registry == nil {
		return core.Fail(core.E("trust.register", "service not initialised", nil))
	}
	agent := Agent{Name: opts.String("name"), Tier: Tier(opts.Int("tier"))}
	if err := s.Registry.Register(agent); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleRemove — `trust.remove` action handler. Reads opts.name,
// returns bool in r.Value (true if the agent existed and was removed).
//
// Usage example: `r := c.Action("trust.remove").Run(ctx, core.NewOptions(core.Option{Key: "name", Value: "alice"}))`
func (s *Service) handleRemove(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Registry == nil {
		return core.Fail(core.E("trust.remove", "service not initialised", nil))
	}
	return core.Ok(s.Registry.Remove(opts.String("name")))
}

// handleEvaluate — `trust.evaluate` action handler. Reads opts.agent
// + opts.capability + opts.repo and returns the EvalResult in
// r.Value. Audits the result if the AuditLog writer is non-nil.
//
// Usage example: `r := c.Action("trust.evaluate").Run(ctx, core.NewOptions(core.Option{Key: "agent", Value: "alice"}, core.Option{Key: "capability", Value: int(trust.CapRead)}, core.Option{Key: "repo", Value: "owner/repo"}))`
func (s *Service) handleEvaluate(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Policy == nil {
		return core.Fail(core.E("trust.evaluate", "service not initialised", nil))
	}
	result := s.Policy.Evaluate(opts.String("agent"), Capability(opts.String("capability")), opts.String("repo"))
	if s.Audit != nil {
		_ = s.Audit.Record(result, opts.String("repo"))
	}
	return core.Ok(result)
}

// handleApprovalSubmit — `trust.approval.submit` action handler.
// Reads opts.agent + opts.capability + opts.repo and returns the
// generated approval-request ID in r.Value.
//
// Usage example: `r := c.Action("trust.approval.submit").Run(ctx, core.NewOptions(core.Option{Key: "agent", Value: "alice"}, core.Option{Key: "capability", Value: int(trust.CapWrite)}, core.Option{Key: "repo", Value: "owner/repo"}))`
func (s *Service) handleApprovalSubmit(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Queue == nil {
		return core.Fail(core.E("trust.approval.submit", "service not initialised", nil))
	}
	id, err := s.Queue.Submit(opts.String("agent"), Capability(opts.String("capability")), opts.String("repo"))
	if err != nil {
		return core.Fail(err)
	}
	return core.Ok(id)
}

// handleApprovalApprove — `trust.approval.approve` action handler.
// Reads opts.id + opts.reviewed_by + opts.reason.
//
// Usage example: `r := c.Action("trust.approval.approve").Run(ctx, core.NewOptions(core.Option{Key: "id", Value: rid}, core.Option{Key: "reviewed_by", Value: "snider"}, core.Option{Key: "reason", Value: "vetted"}))`
func (s *Service) handleApprovalApprove(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Queue == nil {
		return core.Fail(core.E("trust.approval.approve", "service not initialised", nil))
	}
	if err := s.Queue.Approve(opts.String("id"), opts.String("reviewed_by"), opts.String("reason")); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleApprovalDeny — `trust.approval.deny` action handler. Reads
// opts.id + opts.reviewed_by + opts.reason.
//
// Usage example: `r := c.Action("trust.approval.deny").Run(ctx, core.NewOptions(core.Option{Key: "id", Value: rid}, core.Option{Key: "reviewed_by", Value: "snider"}, core.Option{Key: "reason", Value: "policy"}))`
func (s *Service) handleApprovalDeny(_ core.Context, opts core.Options) core.Result {
	if s == nil || s.Queue == nil {
		return core.Fail(core.E("trust.approval.deny", "service not initialised", nil))
	}
	if err := s.Queue.Deny(opts.String("id"), opts.String("reviewed_by"), opts.String("reason")); err != nil {
		return core.Fail(err)
	}
	return core.Ok(nil)
}

// handleApprovalPending — `trust.approval.pending` action handler.
// Returns []ApprovalRequest in r.Value.
//
// Usage example: `r := c.Action("trust.approval.pending").Run(ctx, core.Options{})`
func (s *Service) handleApprovalPending(_ core.Context, _ core.Options) core.Result {
	if s == nil || s.Queue == nil {
		return core.Fail(core.E("trust.approval.pending", "service not initialised", nil))
	}
	return core.Ok(s.Queue.Pending())
}
