package trust

func ExampleDecision_String() {
	_ = (*Decision).String
}

func ExampleNewPolicyEngine() {
	_ = NewPolicyEngine
}

func ExamplePolicyEngine_Evaluate() {
	_ = (*PolicyEngine).Evaluate
}

func ExamplePolicyEngine_SetPolicy() {
	_ = (*PolicyEngine).SetPolicy
}

func ExamplePolicyEngine_GetPolicy() {
	_ = (*PolicyEngine).GetPolicy
}
