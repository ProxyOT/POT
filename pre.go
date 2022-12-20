package pot

import (
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/bls12381"
)

type Encryptor func(key []byte) (err error)

type Decryptor func(key []byte) (err error)

func Encrypt(publicKey *bls12381.PointG1, encryptor Encryptor) (A *bls12381.PointG1, err error) {
	r, err := RandomFieldElement(rand.Reader)
	if err != nil {
		return
	}

	// create engines
	g1 := bls12381.NewG1()
	g2 := bls12381.NewG2()
	gt := bls12381.NewGT()
	pairing := bls12381.NewPairingEngine()

	// Ca = (A, B) = (r*PkA, rGt + Pm) =  (ra*G, rGt + Pm)
	A = g1.MulScalar(g1.New(), publicKey, r)
	B := pairing.AddPair(g1.MulScalar(g1.New(), g1.One(), r), g2.One()).Result()
	err = encryptor(gt.ToBytes(B))

	return
}

func GenerateReKey(a, b *big.Int) (rkAB *bls12381.PointG2) {
	// create G2 engine
	g2 := bls12381.NewG2()

	// rkAB = a^-1 * pkB = (b/a) * G
	ia := new(big.Int).ModInverse(a, Order)    // a^-1 mod Order
	rkAB = g2.MulScalar(g2.New(), g2.One(), b) // b * G
	rkAB = g2.MulScalar(rkAB, rkAB, ia)        // (b/a)*G

	return
}

func ReEncrypt(A *bls12381.PointG1, rkAB *bls12381.PointG2) (APrime *bls12381.E) {
	// APrime = pairing(A, rkAB)
	return bls12381.NewPairingEngine().AddPair(A, rkAB).Result()
}

func GtPointScalarMul(gt *bls12381.GT, p *bls12381.E, e *big.Int) *bls12381.E {
	q, n := &bls12381.E{}, gt.New()
	n.Set(p)
	l := e.BitLen()
	for i := 0; i < l; i++ {
		if e.Bit(i) == 1 {
			gt.Add(q, q, n)
		}
		gt.Add(n, n, n)
	}
	return q
}

func DecryptByReceiver(APrime *bls12381.E, b *big.Int, decryptor Decryptor) (err error) {
	// create Gt engine
	gt := bls12381.NewGT()

	ib := new(big.Int).ModInverse(b, Order) // b^-1 mod
	B := gt.New()
	gt.Exp(B, APrime, ib) // B = ibGt * APrime = rGt
	err = decryptor(gt.ToBytes(B))

	return
}

func DecryptByOwner(A *bls12381.PointG1, a *big.Int, decryptor Decryptor) (err error) {
	// create engines
	g1 := bls12381.NewG1()
	g2 := bls12381.NewG2()
	gt := bls12381.NewGT()
	pairing := bls12381.NewPairingEngine()

	ia := new(big.Int).ModInverse(a, Order)     // a^-1 mod Order
	rG := g1.MulScalar(g1.New(), A, ia)         // rG = a^-1 * A
	B := pairing.AddPair(rG, g2.One()).Result() // B = rGt
	err = decryptor(gt.ToBytes(B))

	return
}
