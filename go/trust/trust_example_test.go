package trust

func ExampleTier_String() {
	_ = (*Tier).String
}

func ExampleTier_Valid() {
	_ = (*Tier).Valid
}

func ExampleNewRegistry() {
	_ = NewRegistry
}

func ExampleRegistry_Register() {
	_ = (*Registry).Register
}

func ExampleRegistry_Get() {
	_ = (*Registry).Get
}

func ExampleRegistry_Remove() {
	_ = (*Registry).Remove
}

func ExampleRegistry_List() {
	_ = (*Registry).List
}

func ExampleRegistry_ListSeq() {
	_ = (*Registry).ListSeq
}

func ExampleRegistry_Len() {
	_ = (*Registry).Len
}
