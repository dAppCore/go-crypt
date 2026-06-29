package trust

func ExampleApprovalStatus_String() {
	_ = (*ApprovalStatus).String
}

func ExampleNewApprovalQueue() {
	_ = NewApprovalQueue
}

func ExampleApprovalQueue_Submit() {
	_ = (*ApprovalQueue).Submit
}

func ExampleApprovalQueue_Approve() {
	_ = (*ApprovalQueue).Approve
}

func ExampleApprovalQueue_Deny() {
	_ = (*ApprovalQueue).Deny
}

func ExampleApprovalQueue_Get() {
	_ = (*ApprovalQueue).Get
}

func ExampleApprovalQueue_Pending() {
	_ = (*ApprovalQueue).Pending
}

func ExampleApprovalQueue_PendingSeq() {
	_ = (*ApprovalQueue).PendingSeq
}

func ExampleApprovalQueue_Len() {
	_ = (*ApprovalQueue).Len
}
