package trust

func ExampleDecision_MarshalJSON() {
	_ = (*Decision).MarshalJSON
}

func ExampleDecision_UnmarshalJSON() {
	_ = (*Decision).UnmarshalJSON
}

func ExampleNewAuditLog() {
	_ = NewAuditLog
}

func ExampleAuditLog_Record() {
	_ = (*AuditLog).Record
}

func ExampleAuditLog_Entries() {
	_ = (*AuditLog).Entries
}

func ExampleAuditLog_EntriesSeq() {
	_ = (*AuditLog).EntriesSeq
}

func ExampleAuditLog_Len() {
	_ = (*AuditLog).Len
}

func ExampleAuditLog_EntriesFor() {
	_ = (*AuditLog).EntriesFor
}

func ExampleAuditLog_EntriesForSeq() {
	_ = (*AuditLog).EntriesForSeq
}
