package pot

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/bls12381"
)

var (
	Order = bls12381.NewG1().Q()
)

// RandomFieldElement returns k where k is a random, non-zero number read from r.
func RandomFieldElement(r io.Reader) (*big.Int, error) {
	var k *big.Int
	var err error

	for {
		k, err = rand.Int(r, Order)
		if err != nil {
			return nil, err
		}
		if k.Sign() > 0 {
			break
		}
	}

	return k, nil
}

// RandomG1Point returns a random point on G1.
func RandomG1Point(r io.Reader) (*big.Int, *bls12381.PointG1, error) {
	k, err := RandomFieldElement(r)
	if err != nil {
		return nil, nil, err
	}

	g1 := bls12381.NewG1()

	return k, g1.MulScalar(g1.New(), g1.One(), k), nil
}

// RandomG2Point returns a random point on G2.
func RandomG2Point(r io.Reader) (*big.Int, *bls12381.PointG2, error) {
	k, err := RandomFieldElement(r)
	if err != nil {
		return nil, nil, err
	}

	g2 := bls12381.NewG2()

	return k, g2.MulScalar(g2.New(), g2.One(), k), nil
}

// G1PointToBytes converts a point on G1 to bytes.
func G1PointToBytes(g1 *bls12381.G1, p *bls12381.PointG1) []byte {
	return g1.ToBytes(p)
}

// G2PointToBytes converts a point on G2 to bytes.
func G2PointToBytes(g2 *bls12381.G2, p *bls12381.PointG2) []byte {
	return g2.ToBytes(p)
}

// GtPointToBytes converts a point on GT to bytes.
func GtPointToBytes(gt *bls12381.GT, p *bls12381.E) []byte {
	return gt.ToBytes(p)
}

// G1PointToString converts a point on G1 to a string.
func G1PointToString(g1 *bls12381.G1, p *bls12381.PointG1) string {
	return hex.EncodeToString(G1PointToBytes(g1, p))
}

// G2PointToString converts a point on G2 to a string.
func G2PointToString(g2 *bls12381.G2, p *bls12381.PointG2) string {
	return hex.EncodeToString(G2PointToBytes(g2, p))
}

// GtPointToString converts a point on GT to a string.
func GtPointToString(gt *bls12381.GT, p *bls12381.E) string {
	return hex.EncodeToString(GtPointToBytes(gt, p))
}

// DeriveFieldElementFromBytes derives a field element k by the following rules:
// (1) Calculate h = SHA256(bytes)
// (2) Calculate k = BigInt(h) % Order
// (3) If k == 0, calculate h = SHA256(h), then jump to (2)
func DeriveFieldElementFromBytes(bs []byte) *big.Int {
	var h = sha256.Sum256(bs)
	var k = new(big.Int)
	for {
		k.SetBytes(h[:])
		k.Mod(k, Order)
		if k.Sign() > 0 {
			break
		}
		h = sha256.Sum256(h[:])
	}
	return k
}
