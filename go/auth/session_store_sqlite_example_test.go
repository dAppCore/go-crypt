package auth

func ExampleNewSQLiteSessionStore() {
	_ = NewSQLiteSessionStore
}

func ExampleSQLiteSessionStore_Get() {
	_ = (*SQLiteSessionStore).Get
}

func ExampleSQLiteSessionStore_Set() {
	_ = (*SQLiteSessionStore).Set
}

func ExampleSQLiteSessionStore_Delete() {
	_ = (*SQLiteSessionStore).Delete
}

func ExampleSQLiteSessionStore_DeleteByUser() {
	_ = (*SQLiteSessionStore).DeleteByUser
}

func ExampleSQLiteSessionStore_Cleanup() {
	_ = (*SQLiteSessionStore).Cleanup
}

func ExampleSQLiteSessionStore_Close() {
	_ = (*SQLiteSessionStore).Close
}
