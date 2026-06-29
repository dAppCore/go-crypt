package auth

func ExampleWithChallengeTTL() {
	_ = WithChallengeTTL
}

func ExampleWithSessionTTL() {
	_ = WithSessionTTL
}

func ExampleWithSessionStore() {
	_ = WithSessionStore
}

func ExampleNew() {
	_ = New
}

func ExampleAuthenticator_Register() {
	_ = (*Authenticator).Register
}

func ExampleAuthenticator_CreateChallenge() {
	_ = (*Authenticator).CreateChallenge
}

func ExampleAuthenticator_ValidateResponse() {
	_ = (*Authenticator).ValidateResponse
}

func ExampleAuthenticator_ValidateSession() {
	_ = (*Authenticator).ValidateSession
}

func ExampleAuthenticator_RefreshSession() {
	_ = (*Authenticator).RefreshSession
}

func ExampleAuthenticator_RevokeSession() {
	_ = (*Authenticator).RevokeSession
}

func ExampleAuthenticator_DeleteUser() {
	_ = (*Authenticator).DeleteUser
}

func ExampleAuthenticator_Login() {
	_ = (*Authenticator).Login
}

func ExampleAuthenticator_RotateKeyPair() {
	_ = (*Authenticator).RotateKeyPair
}

func ExampleAuthenticator_RevokeKey() {
	_ = (*Authenticator).RevokeKey
}

func ExampleAuthenticator_IsRevoked() {
	_ = (*Authenticator).IsRevoked
}

func ExampleAuthenticator_WriteChallengeFile() {
	_ = (*Authenticator).WriteChallengeFile
}

func ExampleAuthenticator_ReadResponseFile() {
	_ = (*Authenticator).ReadResponseFile
}

func ExampleAuthenticator_StartCleanup() {
	_ = (*Authenticator).StartCleanup
}
