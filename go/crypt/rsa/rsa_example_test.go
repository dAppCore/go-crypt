package rsa

func ExampleNewService() {
	_ = NewService
}

func ExampleService_GenerateKeyPair() {
	_ = (*Service).GenerateKeyPair
}

func ExampleService_Encrypt() {
	_ = (*Service).Encrypt
}

func ExampleService_Decrypt() {
	_ = (*Service).Decrypt
}
