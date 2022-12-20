package pot_test

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"testing"

	pot "POT"
	"POT/ciphering"
)

func TestPre(t *testing.T) {
	a, publicKeyA, err := pot.RandomG1Point(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	b, err := pot.RandomFieldElement(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 10000)
	if _, err = mrand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	// step 1: encrypt
	cipherBuf := bytes.NewBuffer(nil)
	A, err := pot.Encrypt(publicKeyA, ciphering.NewEncryptClosure(bytes.NewReader(plaintext), cipherBuf))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := cipherBuf.Bytes()

	// step 2: generate re-key
	rkAB := pot.GenerateReKey(a, b)

	// step 3: re-encrypt
	APrime := pot.ReEncrypt(A, rkAB)

	// step 4: decrypt by receiver
	receiverDeBuf := bytes.NewBuffer(nil)
	err = pot.DecryptByReceiver(APrime, b, ciphering.NewDecryptClosure(bytes.NewReader(ciphertext), receiverDeBuf))
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(plaintext, receiverDeBuf.Bytes()) {
		t.Errorf("decrypt by receiver error")
	}

	// step 5: decrypt by owner
	ownerDeBuf := bytes.NewBuffer(nil)
	err = pot.DecryptByOwner(A, a, ciphering.NewDecryptClosure(bytes.NewReader(ciphertext), ownerDeBuf))
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(plaintext, ownerDeBuf.Bytes()) {
		t.Errorf("decrypt by owner error")
	}
}
