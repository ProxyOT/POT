package pot_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	pot "POT"

	"github.com/ethereum/go-ethereum/crypto/bls12381"
)

func TestOT(t *testing.T) {
	var count int64 = 50
	var betaI int64 = 23
	var beta = big.NewInt(betaI)

	_, pkA, err := pot.RandomG1Point(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	skB, pkB, err := pot.RandomG1Point(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	Y, L, err := pot.SealChoice(beta, pkA, pkB)
	if err != nil {
		t.Fatal(err)
	}

	kps, LPrime, err := pot.CalculateKeyPoints(Y, L, pkA, count)
	if err != nil {
		t.Fatal(err)
	}

	g1 := bls12381.NewG1()

	kpA := kps[betaI-1]
	kpB := pot.RevealKeyPoint(LPrime, skB)
	if pot.G1PointToString(g1, kpA) != pot.G1PointToString(g1, kpB) {
		t.Errorf("Key Point not equal:\nAlice: %s\nBob: %s", pot.G1PointToString(g1, kpA), pot.G1PointToString(g1, kpB))
	}
}
