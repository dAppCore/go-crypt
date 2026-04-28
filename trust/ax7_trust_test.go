package trust

import core "dappco.re/go"

const ax7PolicyJSON = `{"policies":[{"tier":3,"allowed":["repo.push","pr.merge"]},{"tier":2,"allowed":["pr.create"],"requires_approval":["pr.merge"],"denied":["cmd.privileged"]}]}`

func ax7Registry(t *core.T) *Registry {
	t.Helper()
	r := NewRegistry()
	core.RequireNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	core.RequireNoError(t, r.Register(Agent{Name: "Clotho", Tier: TierVerified, ScopedRepos: []string{"host-uk/core"}}))
	return r
}

func ax7Engine(t *core.T) *PolicyEngine {
	t.Helper()
	return NewPolicyEngine(ax7Registry(t))
}

func ax7Eval(agent string, decision Decision) EvalResult {
	return EvalResult{Agent: agent, Cap: CapPushRepo, Decision: decision, Reason: decision.String()}
}

func TestAX7Trust_Tier_String_Good(t *core.T) {
	core.AssertEqual(t, "untrusted", TierUntrusted.String())
	core.AssertEqual(t, "verified", TierVerified.String())
	core.AssertEqual(t, "full", TierFull.String())
}

func TestAX7Trust_Tier_String_Bad(t *core.T) {
	got := Tier(99).String()
	core.AssertContains(t, got, "unknown")
	core.AssertContains(t, got, "99")
}

func TestAX7Trust_Tier_String_Ugly(t *core.T) {
	got := Tier(-1).String()
	core.AssertContains(t, got, "unknown")
	core.AssertContains(t, got, "-1")
}

func TestAX7Trust_Tier_Valid_Good(t *core.T) {
	core.AssertTrue(t, TierUntrusted.Valid())
	core.AssertTrue(t, TierVerified.Valid())
	core.AssertTrue(t, TierFull.Valid())
}

func TestAX7Trust_Tier_Valid_Bad(t *core.T) {
	core.AssertFalse(t, Tier(0).Valid())
	core.AssertFalse(t, Tier(4).Valid())
	core.AssertFalse(t, Tier(-1).Valid())
}

func TestAX7Trust_Tier_Valid_Ugly(t *core.T) {
	var zero Tier
	core.AssertFalse(t, zero.Valid())
	core.AssertTrue(t, TierFull.Valid())
}

func TestAX7Trust_NewRegistry_Good(t *core.T) {
	r := NewRegistry()
	core.AssertNotNil(t, r)
	core.AssertEqual(t, 0, r.Len())
}

func TestAX7Trust_NewRegistry_Bad(t *core.T) {
	r := NewRegistry()
	agent := r.Get("missing")
	core.AssertNil(t, agent)
	core.AssertEqual(t, 0, r.Len())
}

func TestAX7Trust_NewRegistry_Ugly(t *core.T) {
	first := NewRegistry()
	second := NewRegistry()
	core.AssertNotNil(t, first.agents)
	core.AssertTrue(t, first != second)
}

func TestAX7Trust_Registry_Register_Good(t *core.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Athena", Tier: TierFull})
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, r.Len())
}

func TestAX7Trust_Registry_Register_Bad(t *core.T) {
	r := NewRegistry()
	err := r.Register(Agent{Tier: TierFull})
	core.AssertError(t, err)
	core.AssertEqual(t, 0, r.Len())
}

func TestAX7Trust_Registry_Register_Ugly(t *core.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Bad", Tier: Tier(99)})
	core.AssertError(t, err)
	core.AssertNil(t, r.Get("Bad"))
}

func TestAX7Trust_Registry_Get_Good(t *core.T) {
	r := NewRegistry()
	core.RequireNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	agent := r.Get("Athena")
	core.AssertNotNil(t, agent)
	core.AssertEqual(t, TierFull, agent.Tier)
}

func TestAX7Trust_Registry_Get_Bad(t *core.T) {
	r := NewRegistry()
	agent := r.Get("missing")
	core.AssertNil(t, agent)
	core.AssertEqual(t, 0, r.Len())
}

func TestAX7Trust_Registry_Get_Ugly(t *core.T) {
	r := NewRegistry()
	core.RequireNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	agent := r.Get("")
	core.AssertNil(t, agent)
	core.AssertEqual(t, 1, r.Len())
}

func TestAX7Trust_Registry_Remove_Good(t *core.T) {
	r := NewRegistry()
	core.RequireNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	removed := r.Remove("Athena")
	core.AssertTrue(t, removed)
	core.AssertEqual(t, 0, r.Len())
}

func TestAX7Trust_Registry_Remove_Bad(t *core.T) {
	r := NewRegistry()
	removed := r.Remove("missing")
	core.AssertFalse(t, removed)
	core.AssertEqual(t, 0, r.Len())
}

func TestAX7Trust_Registry_Remove_Ugly(t *core.T) {
	r := NewRegistry()
	core.RequireNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	removed := r.Remove("")
	core.AssertFalse(t, removed)
	core.AssertEqual(t, 1, r.Len())
}

func TestAX7Trust_Registry_List_Good(t *core.T) {
	r := ax7Registry(t)
	agents := r.List()
	core.AssertEqual(t, 2, len(agents))
	core.AssertEqual(t, 2, r.Len())
}

func TestAX7Trust_Registry_List_Bad(t *core.T) {
	r := NewRegistry()
	agents := r.List()
	core.AssertEqual(t, 0, len(agents))
	core.AssertEqual(t, 0, r.Len())
}

func TestAX7Trust_Registry_List_Ugly(t *core.T) {
	r := NewRegistry()
	core.RequireNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	agents := r.List()
	agents[0].Tier = TierUntrusted
	core.AssertEqual(t, TierFull, r.Get("Athena").Tier)
}

func TestAX7Trust_Registry_ListSeq_Good(t *core.T) {
	r := ax7Registry(t)
	count := 0
	for range r.ListSeq() {
		count++
	}
	core.AssertEqual(t, 2, count)
}

func TestAX7Trust_Registry_ListSeq_Bad(t *core.T) {
	r := NewRegistry()
	count := 0
	for range r.ListSeq() {
		count++
	}
	core.AssertEqual(t, 0, count)
}

func TestAX7Trust_Registry_ListSeq_Ugly(t *core.T) {
	r := ax7Registry(t)
	count := 0
	for range r.ListSeq() {
		count++
		break
	}
	core.AssertEqual(t, 1, count)
}

func TestAX7Trust_Registry_Len_Good(t *core.T) {
	r := ax7Registry(t)
	core.AssertEqual(t, 2, r.Len())
	core.AssertNotNil(t, r.Get("Athena"))
}

func TestAX7Trust_Registry_Len_Bad(t *core.T) {
	r := NewRegistry()
	core.AssertEqual(t, 0, r.Len())
	core.AssertNil(t, r.Get("missing"))
}

func TestAX7Trust_Registry_Len_Ugly(t *core.T) {
	r := NewRegistry()
	core.RequireNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	core.AssertTrue(t, r.Remove("Athena"))
	core.AssertEqual(t, 0, r.Len())
}

func TestAX7Trust_ApprovalStatus_String_Good(t *core.T) {
	core.AssertEqual(t, "pending", ApprovalPending.String())
	core.AssertEqual(t, "approved", ApprovalApproved.String())
	core.AssertEqual(t, "denied", ApprovalDenied.String())
}

func TestAX7Trust_ApprovalStatus_String_Bad(t *core.T) {
	got := ApprovalStatus(99).String()
	core.AssertContains(t, got, "unknown")
	core.AssertContains(t, got, "99")
}

func TestAX7Trust_ApprovalStatus_String_Ugly(t *core.T) {
	got := ApprovalStatus(-1).String()
	core.AssertContains(t, got, "unknown")
	core.AssertContains(t, got, "-1")
}

func TestAX7Trust_NewApprovalQueue_Good(t *core.T) {
	q := NewApprovalQueue()
	core.AssertNotNil(t, q)
	core.AssertEqual(t, 0, q.Len())
}

func TestAX7Trust_NewApprovalQueue_Bad(t *core.T) {
	q := NewApprovalQueue()
	req := q.Get("missing")
	core.AssertNil(t, req)
	core.AssertEqual(t, 0, q.Len())
}

func TestAX7Trust_NewApprovalQueue_Ugly(t *core.T) {
	first := NewApprovalQueue()
	second := NewApprovalQueue()
	core.AssertNotNil(t, first.requests)
	core.AssertTrue(t, first != second)
}

func TestAX7Trust_ApprovalQueue_Submit_Good(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.AssertNoError(t, err)
	core.AssertNotEmpty(t, id)
	core.AssertEqual(t, 1, q.Len())
}

func TestAX7Trust_ApprovalQueue_Submit_Bad(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("", CapMergePR, "host-uk/core")
	core.AssertError(t, err)
	core.AssertEqual(t, "", id)
}

func TestAX7Trust_ApprovalQueue_Submit_Ugly(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", "", "host-uk/core")
	core.AssertError(t, err)
	core.AssertEqual(t, "", id)
}

func TestAX7Trust_ApprovalQueue_Approve_Good(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	err = q.Approve(id, "admin", "ok")
	core.AssertNoError(t, err)
	core.AssertEqual(t, ApprovalApproved, q.Get(id).Status)
}

func TestAX7Trust_ApprovalQueue_Approve_Bad(t *core.T) {
	q := NewApprovalQueue()
	err := q.Approve("missing", "admin", "ok")
	core.AssertError(t, err)
	core.AssertEqual(t, 0, q.Len())
}

func TestAX7Trust_ApprovalQueue_Approve_Ugly(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	core.RequireNoError(t, q.Deny(id, "admin", "no"))
	err = q.Approve(id, "admin", "ok")
	core.AssertError(t, err)
}

func TestAX7Trust_ApprovalQueue_Deny_Good(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	err = q.Deny(id, "admin", "no")
	core.AssertNoError(t, err)
	core.AssertEqual(t, ApprovalDenied, q.Get(id).Status)
}

func TestAX7Trust_ApprovalQueue_Deny_Bad(t *core.T) {
	q := NewApprovalQueue()
	err := q.Deny("missing", "admin", "no")
	core.AssertError(t, err)
	core.AssertEqual(t, 0, q.Len())
}

func TestAX7Trust_ApprovalQueue_Deny_Ugly(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	core.RequireNoError(t, q.Approve(id, "admin", "ok"))
	err = q.Deny(id, "admin", "no")
	core.AssertError(t, err)
}

func TestAX7Trust_ApprovalQueue_Get_Good(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	req := q.Get(id)
	core.AssertNotNil(t, req)
	core.AssertEqual(t, "Clotho", req.Agent)
}

func TestAX7Trust_ApprovalQueue_Get_Bad(t *core.T) {
	q := NewApprovalQueue()
	req := q.Get("missing")
	core.AssertNil(t, req)
	core.AssertEqual(t, 0, q.Len())
}

func TestAX7Trust_ApprovalQueue_Get_Ugly(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	req := q.Get(id)
	req.Agent = "changed"
	core.AssertEqual(t, "Clotho", q.Get(id).Agent)
}

func TestAX7Trust_ApprovalQueue_Pending_Good(t *core.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	pending := q.Pending()
	core.AssertEqual(t, 1, len(pending))
}

func TestAX7Trust_ApprovalQueue_Pending_Bad(t *core.T) {
	q := NewApprovalQueue()
	pending := q.Pending()
	core.AssertEqual(t, 0, len(pending))
	core.AssertEqual(t, 0, q.Len())
}

func TestAX7Trust_ApprovalQueue_Pending_Ugly(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	core.RequireNoError(t, q.Approve(id, "admin", "ok"))
	pending := q.Pending()
	core.AssertEqual(t, 0, len(pending))
}

func TestAX7Trust_ApprovalQueue_PendingSeq_Good(t *core.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	count := 0
	for range q.PendingSeq() {
		count++
	}
	core.AssertEqual(t, 1, count)
}

func TestAX7Trust_ApprovalQueue_PendingSeq_Bad(t *core.T) {
	q := NewApprovalQueue()
	count := 0
	for range q.PendingSeq() {
		count++
	}
	core.AssertEqual(t, 0, count)
}

func TestAX7Trust_ApprovalQueue_PendingSeq_Ugly(t *core.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	count := 0
	for range q.PendingSeq() {
		count++
		break
	}
	core.AssertEqual(t, 1, count)
}

func TestAX7Trust_ApprovalQueue_Len_Good(t *core.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	core.AssertEqual(t, 1, q.Len())
}

func TestAX7Trust_ApprovalQueue_Len_Bad(t *core.T) {
	q := NewApprovalQueue()
	core.AssertEqual(t, 0, q.Len())
	core.AssertNil(t, q.Get("missing"))
}

func TestAX7Trust_ApprovalQueue_Len_Ugly(t *core.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	core.RequireNoError(t, err)
	core.RequireNoError(t, q.Approve(id, "admin", "ok"))
	core.AssertEqual(t, 1, q.Len())
}

func TestAX7Trust_Decision_String_Good(t *core.T) {
	core.AssertEqual(t, "deny", Deny.String())
	core.AssertEqual(t, "allow", Allow.String())
	core.AssertEqual(t, "needs_approval", NeedsApproval.String())
}

func TestAX7Trust_Decision_String_Bad(t *core.T) {
	got := Decision(99).String()
	core.AssertContains(t, got, "unknown")
	core.AssertContains(t, got, "99")
}

func TestAX7Trust_Decision_String_Ugly(t *core.T) {
	got := Decision(-1).String()
	core.AssertContains(t, got, "unknown")
	core.AssertContains(t, got, "-1")
}

func TestAX7Trust_Decision_MarshalJSON_Good(t *core.T) {
	data, err := Allow.MarshalJSON()
	core.AssertNoError(t, err)
	core.AssertEqual(t, `"allow"`, string(data))
}

func TestAX7Trust_Decision_MarshalJSON_Bad(t *core.T) {
	data, err := Decision(99).MarshalJSON()
	core.AssertNoError(t, err)
	core.AssertContains(t, string(data), "unknown")
}

func TestAX7Trust_Decision_MarshalJSON_Ugly(t *core.T) {
	data, err := Decision(-1).MarshalJSON()
	core.AssertNoError(t, err)
	core.AssertContains(t, string(data), "-1")
}

func TestAX7Trust_Decision_UnmarshalJSON_Good(t *core.T) {
	var d Decision
	err := d.UnmarshalJSON([]byte(`"needs_approval"`))
	core.AssertNoError(t, err)
	core.AssertEqual(t, NeedsApproval, d)
}

func TestAX7Trust_Decision_UnmarshalJSON_Bad(t *core.T) {
	var d Decision
	err := d.UnmarshalJSON([]byte(`"bogus"`))
	core.AssertError(t, err)
	core.AssertEqual(t, Deny, d)
}

func TestAX7Trust_Decision_UnmarshalJSON_Ugly(t *core.T) {
	var d Decision
	err := d.UnmarshalJSON([]byte(`42`))
	core.AssertError(t, err)
	core.AssertEqual(t, Deny, d)
}

func TestAX7Trust_NewAuditLog_Good(t *core.T) {
	log := NewAuditLog(nil)
	core.AssertNotNil(t, log)
	core.AssertEqual(t, 0, log.Len())
}

func TestAX7Trust_NewAuditLog_Bad(t *core.T) {
	log := NewAuditLog(&failWriter{})
	err := log.Record(ax7Eval("Athena", Allow), "")
	core.AssertError(t, err)
	core.AssertEqual(t, 1, log.Len())
}

func TestAX7Trust_NewAuditLog_Ugly(t *core.T) {
	buf := core.NewBuilder()
	log := NewAuditLog(buf)
	core.AssertNotNil(t, log)
	core.AssertEqual(t, "", buf.String())
}

func TestAX7Trust_AuditLog_Record_Good(t *core.T) {
	log := NewAuditLog(nil)
	err := log.Record(ax7Eval("Athena", Allow), "host-uk/core")
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, log.Len())
}

func TestAX7Trust_AuditLog_Record_Bad(t *core.T) {
	log := NewAuditLog(&failWriter{})
	err := log.Record(ax7Eval("Athena", Allow), "host-uk/core")
	core.AssertError(t, err)
	core.AssertEqual(t, 1, log.Len())
}

func TestAX7Trust_AuditLog_Record_Ugly(t *core.T) {
	log := NewAuditLog(nil)
	err := log.Record(EvalResult{}, "")
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, len(log.Entries()))
}

func TestAX7Trust_AuditLog_Entries_Good(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	entries := log.Entries()
	core.AssertEqual(t, 1, len(entries))
	core.AssertEqual(t, "Athena", entries[0].Agent)
}

func TestAX7Trust_AuditLog_Entries_Bad(t *core.T) {
	log := NewAuditLog(nil)
	entries := log.Entries()
	core.AssertEqual(t, 0, len(entries))
	core.AssertEqual(t, 0, log.Len())
}

func TestAX7Trust_AuditLog_Entries_Ugly(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	entries := log.Entries()
	entries[0].Agent = "changed"
	core.AssertEqual(t, "Athena", log.Entries()[0].Agent)
}

func TestAX7Trust_AuditLog_EntriesSeq_Good(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	count := 0
	for range log.EntriesSeq() {
		count++
	}
	core.AssertEqual(t, 1, count)
}

func TestAX7Trust_AuditLog_EntriesSeq_Bad(t *core.T) {
	log := NewAuditLog(nil)
	count := 0
	for range log.EntriesSeq() {
		count++
	}
	core.AssertEqual(t, 0, count)
}

func TestAX7Trust_AuditLog_EntriesSeq_Ugly(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	count := 0
	for range log.EntriesSeq() {
		count++
		break
	}
	core.AssertEqual(t, 1, count)
}

func TestAX7Trust_AuditLog_Len_Good(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	core.AssertEqual(t, 1, log.Len())
}

func TestAX7Trust_AuditLog_Len_Bad(t *core.T) {
	log := NewAuditLog(nil)
	core.AssertEqual(t, 0, log.Len())
	core.AssertEqual(t, 0, len(log.Entries()))
}

func TestAX7Trust_AuditLog_Len_Ugly(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("", Deny), ""))
	core.AssertEqual(t, 1, log.Len())
}

func TestAX7Trust_AuditLog_EntriesFor_Good(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	core.RequireNoError(t, log.Record(ax7Eval("Clotho", Deny), ""))
	entries := log.EntriesFor("Athena")
	core.AssertEqual(t, 1, len(entries))
	core.AssertEqual(t, "Athena", entries[0].Agent)
}

func TestAX7Trust_AuditLog_EntriesFor_Bad(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	entries := log.EntriesFor("missing")
	core.AssertEqual(t, 0, len(entries))
}

func TestAX7Trust_AuditLog_EntriesFor_Ugly(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("", Deny), ""))
	entries := log.EntriesFor("")
	core.AssertEqual(t, 1, len(entries))
}

func TestAX7Trust_AuditLog_EntriesForSeq_Good(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	count := 0
	for range log.EntriesForSeq("Athena") {
		count++
	}
	core.AssertEqual(t, 1, count)
}

func TestAX7Trust_AuditLog_EntriesForSeq_Bad(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	count := 0
	for range log.EntriesForSeq("missing") {
		count++
	}
	core.AssertEqual(t, 0, count)
}

func TestAX7Trust_AuditLog_EntriesForSeq_Ugly(t *core.T) {
	log := NewAuditLog(nil)
	core.RequireNoError(t, log.Record(ax7Eval("Athena", Allow), ""))
	count := 0
	for range log.EntriesForSeq("Athena") {
		count++
		break
	}
	core.AssertEqual(t, 1, count)
}

func TestAX7Trust_NewPolicyEngine_Good(t *core.T) {
	pe := NewPolicyEngine(ax7Registry(t))
	core.AssertNotNil(t, pe)
	core.AssertNotNil(t, pe.GetPolicy(TierFull))
}

func TestAX7Trust_NewPolicyEngine_Bad(t *core.T) {
	pe := NewPolicyEngine(nil)
	core.AssertNotNil(t, pe)
	core.AssertNil(t, pe.registry)
}

func TestAX7Trust_NewPolicyEngine_Ugly(t *core.T) {
	pe := NewPolicyEngine(NewRegistry())
	result := pe.Evaluate("missing", CapPushRepo, "")
	core.AssertEqual(t, Deny, result.Decision)
}

func TestAX7Trust_PolicyEngine_Evaluate_Good(t *core.T) {
	pe := ax7Engine(t)
	result := pe.Evaluate("Athena", CapPushRepo, "host-uk/core")
	core.AssertEqual(t, Allow, result.Decision)
	core.AssertEqual(t, "Athena", result.Agent)
}

func TestAX7Trust_PolicyEngine_Evaluate_Bad(t *core.T) {
	pe := ax7Engine(t)
	result := pe.Evaluate("missing", CapPushRepo, "host-uk/core")
	core.AssertEqual(t, Deny, result.Decision)
	core.AssertContains(t, result.Reason, "not registered")
}

func TestAX7Trust_PolicyEngine_Evaluate_Ugly(t *core.T) {
	r := NewRegistry()
	r.agents["Odd"] = &Agent{Name: "Odd", Tier: Tier(99)}
	pe := NewPolicyEngine(r)
	result := pe.Evaluate("Odd", CapPushRepo, "")
	core.AssertEqual(t, Deny, result.Decision)
	core.AssertContains(t, result.Reason, "no policy")
}

func TestAX7Trust_PolicyEngine_SetPolicy_Good(t *core.T) {
	pe := ax7Engine(t)
	err := pe.SetPolicy(Policy{Tier: TierVerified, Allowed: []Capability{CapMergePR}})
	core.AssertNoError(t, err)
	core.AssertEqual(t, 1, len(pe.GetPolicy(TierVerified).Allowed))
}

func TestAX7Trust_PolicyEngine_SetPolicy_Bad(t *core.T) {
	pe := ax7Engine(t)
	err := pe.SetPolicy(Policy{Tier: Tier(99)})
	core.AssertError(t, err)
	core.AssertNotNil(t, pe.GetPolicy(TierFull))
}

func TestAX7Trust_PolicyEngine_SetPolicy_Ugly(t *core.T) {
	pe := ax7Engine(t)
	err := pe.SetPolicy(Policy{Tier: TierVerified})
	core.AssertNoError(t, err)
	core.AssertEqual(t, 0, len(pe.GetPolicy(TierVerified).Allowed))
}

func TestAX7Trust_PolicyEngine_GetPolicy_Good(t *core.T) {
	pe := ax7Engine(t)
	policy := pe.GetPolicy(TierFull)
	core.AssertNotNil(t, policy)
	core.AssertEqual(t, TierFull, policy.Tier)
}

func TestAX7Trust_PolicyEngine_GetPolicy_Bad(t *core.T) {
	pe := ax7Engine(t)
	policy := pe.GetPolicy(Tier(99))
	core.AssertNil(t, policy)
	core.AssertNotNil(t, pe.GetPolicy(TierFull))
}

func TestAX7Trust_PolicyEngine_GetPolicy_Ugly(t *core.T) {
	pe := ax7Engine(t)
	delete(pe.policies, TierFull)
	policy := pe.GetPolicy(TierFull)
	core.AssertNil(t, policy)
}

func TestAX7Trust_LoadPolicies_Good(t *core.T) {
	policies, err := LoadPolicies(core.NewReader(ax7PolicyJSON))
	core.AssertNoError(t, err)
	core.AssertEqual(t, 2, len(policies))
}

func TestAX7Trust_LoadPolicies_Bad(t *core.T) {
	policies, err := LoadPolicies(core.NewReader(`{invalid`))
	core.AssertError(t, err)
	core.AssertNil(t, policies)
}

func TestAX7Trust_LoadPolicies_Ugly(t *core.T) {
	policies, err := LoadPolicies(core.NewReader(`{"policies":[{"tier":99,"allowed":[]}]}`))
	core.AssertError(t, err)
	core.AssertNil(t, policies)
}

func TestAX7Trust_LoadPoliciesFromFile_Good(t *core.T) {
	path := core.Path(t.TempDir(), "policies.json")
	writeResult := (&core.Fs{}).New("/").WriteMode(path, ax7PolicyJSON, 0o644)
	core.RequireTrue(t, writeResult.OK)
	policies, err := LoadPoliciesFromFile(path)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 2, len(policies))
}

func TestAX7Trust_LoadPoliciesFromFile_Bad(t *core.T) {
	policies, err := LoadPoliciesFromFile(core.Path(t.TempDir(), "missing.json"))
	core.AssertError(t, err)
	core.AssertNil(t, policies)
}

func TestAX7Trust_LoadPoliciesFromFile_Ugly(t *core.T) {
	path := core.Path(t.TempDir(), "policies.json")
	writeResult := (&core.Fs{}).New("/").WriteMode(path, `{invalid`, 0o644)
	core.RequireTrue(t, writeResult.OK)
	policies, err := LoadPoliciesFromFile(path)
	core.AssertError(t, err)
	core.AssertNil(t, policies)
}

func TestAX7Trust_PolicyEngine_ApplyPolicies_Good(t *core.T) {
	pe := ax7Engine(t)
	err := pe.ApplyPolicies(core.NewReader(ax7PolicyJSON))
	core.AssertNoError(t, err)
	core.AssertEqual(t, 2, len(pe.GetPolicy(TierFull).Allowed))
}

func TestAX7Trust_PolicyEngine_ApplyPolicies_Bad(t *core.T) {
	pe := ax7Engine(t)
	err := pe.ApplyPolicies(core.NewReader(`{invalid`))
	core.AssertError(t, err)
	core.AssertNotNil(t, pe.GetPolicy(TierFull))
}

func TestAX7Trust_PolicyEngine_ApplyPolicies_Ugly(t *core.T) {
	pe := ax7Engine(t)
	err := pe.ApplyPolicies(core.NewReader(`{"policies":[]}`))
	core.AssertNoError(t, err)
	core.AssertNotNil(t, pe.GetPolicy(TierFull))
}

func TestAX7Trust_PolicyEngine_ApplyPoliciesFromFile_Good(t *core.T) {
	path := core.Path(t.TempDir(), "policies.json")
	writeResult := (&core.Fs{}).New("/").WriteMode(path, ax7PolicyJSON, 0o644)
	core.RequireTrue(t, writeResult.OK)
	pe := ax7Engine(t)
	err := pe.ApplyPoliciesFromFile(path)
	core.AssertNoError(t, err)
	core.AssertEqual(t, 2, len(pe.GetPolicy(TierFull).Allowed))
}

func TestAX7Trust_PolicyEngine_ApplyPoliciesFromFile_Bad(t *core.T) {
	pe := ax7Engine(t)
	err := pe.ApplyPoliciesFromFile(core.Path(t.TempDir(), "missing.json"))
	core.AssertError(t, err)
	core.AssertNotNil(t, pe.GetPolicy(TierFull))
}

func TestAX7Trust_PolicyEngine_ApplyPoliciesFromFile_Ugly(t *core.T) {
	path := core.Path(t.TempDir(), "policies.json")
	writeResult := (&core.Fs{}).New("/").WriteMode(path, `{invalid`, 0o644)
	core.RequireTrue(t, writeResult.OK)
	pe := ax7Engine(t)
	err := pe.ApplyPoliciesFromFile(path)
	core.AssertError(t, err)
}

func TestAX7Trust_PolicyEngine_ExportPolicies_Good(t *core.T) {
	pe := ax7Engine(t)
	buf := core.NewBuilder()
	err := pe.ExportPolicies(buf)
	core.AssertNoError(t, err)
	core.AssertContains(t, buf.String(), "policies")
}

func TestAX7Trust_PolicyEngine_ExportPolicies_Bad(t *core.T) {
	pe := ax7Engine(t)
	err := pe.ExportPolicies(&failWriter{})
	core.AssertError(t, err)
	core.AssertNotNil(t, pe.GetPolicy(TierFull))
}

func TestAX7Trust_PolicyEngine_ExportPolicies_Ugly(t *core.T) {
	pe := ax7Engine(t)
	pe.policies = map[Tier]*Policy{}
	buf := core.NewBuilder()
	err := pe.ExportPolicies(buf)
	core.AssertNoError(t, err)
	core.AssertContains(t, buf.String(), "policies")
}
