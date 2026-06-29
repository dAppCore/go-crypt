package auth

func ExampleNewMemorySessionStore() {
	_ = NewMemorySessionStore
}

func ExampleMemorySessionStore_Get() {
	_ = (*MemorySessionStore).Get
}

func ExampleMemorySessionStore_Set() {
	_ = (*MemorySessionStore).Set
}

func ExampleMemorySessionStore_Delete() {
	_ = (*MemorySessionStore).Delete
}

func ExampleMemorySessionStore_DeleteByUser() {
	_ = (*MemorySessionStore).DeleteByUser
}

func ExampleMemorySessionStore_Cleanup() {
	_ = (*MemorySessionStore).Cleanup
}
