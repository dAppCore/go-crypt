package trust

func ExampleLoadPoliciesFromFile() {
	_ = LoadPoliciesFromFile
}

func ExampleLoadPolicies() {
	_ = LoadPolicies
}

func ExamplePolicyEngine_ApplyPolicies() {
	_ = (*PolicyEngine).ApplyPolicies
}

func ExamplePolicyEngine_ApplyPoliciesFromFile() {
	_ = (*PolicyEngine).ApplyPoliciesFromFile
}

func ExamplePolicyEngine_ExportPolicies() {
	_ = (*PolicyEngine).ExportPolicies
}
