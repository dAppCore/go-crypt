package openpgp

func ExampleNew() {
	_ = New
}

func ExampleService_CreateKeyPair() {
	_ = (*Service).CreateKeyPair
}

func ExampleService_EncryptPGP() {
	_ = (*Service).EncryptPGP
}

func ExampleService_DecryptPGP() {
	_ = (*Service).DecryptPGP
}

func ExampleService_HandleIPCEvents() {
	_ = (*Service).HandleIPCEvents
}
