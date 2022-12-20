package pot

import (
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/bls12381"
)

// SealChoice refers to the process that receivers indicate the index of secret.
// The input argument beta is the index.
func SealChoice(beta *big.Int, pkA, pkB *bls12381.PointG1) (Y, L *bls12381.PointG1, err error) {
	// random number l
	var l *big.Int
	l, err = RandomFieldElement(rand.Reader)
	if err != nil {
		return
	}

	// create G1 engine
	g1 := bls12381.NewG1()

	// calculate L = l * G
	L = g1.MulScalar(g1.New(), g1.One(), l)

	// calculate Y = beta * pkA + l * pkB
	Y = g1.MulScalar(g1.New(), pkA, beta)
	Y = g1.Add(Y, Y, g1.MulScalar(g1.New(), pkB, l))

	return
}

// CalculateKeyPoints refers to the process that sender creates some sealed key points
// given by the sender calculated Y point.
func CalculateKeyPoints(Y, L, pkA *bls12381.PointG1, count int64) (kps []*bls12381.PointG1, LPrime *bls12381.PointG1, err error) {
	// random number t
	var t *big.Int
	t, err = RandomFieldElement(rand.Reader)
	if err != nil {
		return
	}

	// create G1 Engine
	g1 := bls12381.NewG1()

	// calculate puzzles
	kps = make([]*bls12381.PointG1, count)
	for i := int64(1); i <= count; i++ {
		kps[i-1] = calculateKeyPoint(g1, t, Y, pkA, big.NewInt(i))
	}

	// calculate LPrime = t * L
	LPrime = g1.MulScalar(g1.New(), L, t)

	return
}

func calculateKeyPoint(g1 *bls12381.G1, t *big.Int, yp, pkA *bls12381.PointG1, ordinal *big.Int) (kpi *bls12381.PointG1) {
	// kpi = t * yp - i * t * pkA
	kpi = g1.MulScalar(g1.New(), yp, t)
	temp := g1.MulScalar(g1.New(), pkA, new(big.Int).Mul(ordinal, t))
	g1.Add(kpi, kpi, g1.Neg(temp, temp))

	return
}

// RevealKeyPoint refers to the process that receiver reveals real key point
// given by the sender calculated sealed key point.
func RevealKeyPoint(LPrime *bls12381.PointG1, skB *big.Int) *bls12381.PointG1 {
	// create G1 Engine
	g1 := bls12381.NewG1()

	// calculate kpB = skB * LPrime
	return g1.MulScalar(g1.New(), LPrime, skB)
}
