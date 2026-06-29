package auth

import (
	core "dappco.re/go"
)

func TestSessionStoreSqlite_NewSQLiteSessionStore_Good(t *core.T) {
	subject := NewSQLiteSessionStore
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_NewSQLiteSessionStore_Bad(t *core.T) {
	subject := NewSQLiteSessionStore
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_NewSQLiteSessionStore_Ugly(t *core.T) {
	subject := NewSQLiteSessionStore
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Get_Good(t *core.T) {
	subject := (*SQLiteSessionStore).Get
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Get_Bad(t *core.T) {
	subject := (*SQLiteSessionStore).Get
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Get_Ugly(t *core.T) {
	subject := (*SQLiteSessionStore).Get
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Set_Good(t *core.T) {
	subject := (*SQLiteSessionStore).Set
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Set_Bad(t *core.T) {
	subject := (*SQLiteSessionStore).Set
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Set_Ugly(t *core.T) {
	subject := (*SQLiteSessionStore).Set
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Delete_Good(t *core.T) {
	subject := (*SQLiteSessionStore).Delete
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Delete_Bad(t *core.T) {
	subject := (*SQLiteSessionStore).Delete
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Delete_Ugly(t *core.T) {
	subject := (*SQLiteSessionStore).Delete
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_DeleteByUser_Good(t *core.T) {
	subject := (*SQLiteSessionStore).DeleteByUser
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_DeleteByUser_Bad(t *core.T) {
	subject := (*SQLiteSessionStore).DeleteByUser
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_DeleteByUser_Ugly(t *core.T) {
	subject := (*SQLiteSessionStore).DeleteByUser
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Cleanup_Good(t *core.T) {
	subject := (*SQLiteSessionStore).Cleanup
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Cleanup_Bad(t *core.T) {
	subject := (*SQLiteSessionStore).Cleanup
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Cleanup_Ugly(t *core.T) {
	subject := (*SQLiteSessionStore).Cleanup
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Close_Good(t *core.T) {
	subject := (*SQLiteSessionStore).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Close_Bad(t *core.T) {
	subject := (*SQLiteSessionStore).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestSessionStoreSqlite_SQLiteSessionStore_Close_Ugly(t *core.T) {
	subject := (*SQLiteSessionStore).Close
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
