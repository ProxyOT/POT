package pot_test

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	pot "POT"
	"POT/ciphering"

	"github.com/ethereum/go-ethereum/crypto/bls12381"
)

func TestProxyOT(t *testing.T) {
	const (
		messageSize  = 1_000_000
		messageCount = 10
		choice       = 3
	)

	// create G1 engine
	g1 := bls12381.NewG1()

	// alice setup
	skA, pkA, err := pot.RandomG1Point(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msgList := make([][]byte, messageCount)
	for i := range msgList {
		msgList[i] = make([]byte, messageSize)
		if _, err := rand.Read(msgList[i]); err != nil {
			t.Fatal(err)
		}
	}

	// bob setup
	skB, pkB, err := pot.RandomG1Point(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// alice encrypt & upload messages to proxy
	encMsgList := make([][]byte, messageCount)
	As := make([]*bls12381.PointG1, messageCount)
	for i := range msgList {
		cipherBuf := bytes.NewBuffer(make([]byte, 0, messageSize))
		A, err := pot.Encrypt(pkA, ciphering.NewEncryptClosure(bytes.NewReader(msgList[i]), cipherBuf))
		if err != nil {
			t.Fatal(err)
		}
		As[i] = A
		encMsgList[i] = cipherBuf.Bytes()
	}

	// bob send choice
	Y, L, err := pot.SealChoice(big.NewInt(int64(choice)), pkA, pkB)
	if err != nil {
		t.Fatal(err)
	}

	// alice generate re-key
	kps, LPrime, err := pot.CalculateKeyPoints(Y, L, pkA, messageCount)
	if err != nil {
		t.Fatal(err)
	}
	bobEphemeralKeys := make([]*big.Int, messageCount)
	for i := range kps {
		bobEphemeralKeys[i] = pot.DeriveFieldElementFromBytes(pot.G1PointToBytes(g1, kps[i]))
	}
	reKeys := make([]*bls12381.PointG2, messageCount)
	for i := range reKeys {
		reKeys[i] = pot.GenerateReKey(skA, bobEphemeralKeys[i])
	}

	// proxy re-encrypt
	APrimes := make([]*bls12381.E, messageCount)
	for i := range reKeys {
		APrimes[i] = pot.ReEncrypt(As[i], reKeys[i])
	}

	// bob decrypt
	APrime := APrimes[choice-1]
	kp := pot.RevealKeyPoint(LPrime, skB)
	bobEphemeralKey := pot.DeriveFieldElementFromBytes(pot.G1PointToBytes(g1, kp))
	decBuf := bytes.NewBuffer(make([]byte, 0, messageSize))
	err = pot.DecryptByReceiver(APrime, bobEphemeralKey, ciphering.NewDecryptClosure(bytes.NewReader(encMsgList[choice-1]), decBuf))
	if err != nil {
		t.Fatal(err)
	}
	decMsg := decBuf.Bytes()

	// compare
	if !bytes.Equal(msgList[choice-1], decMsg) {
		t.Fatal("decrypted message is not equal to original message")
	}
}
