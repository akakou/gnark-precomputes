package gnarkprecomputes

import (
	b "github.com/akakou/gnark-precomputes/curve/bls12381"
	curve_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

type CorePreparedVerifyingKey[
	Vector any,
	G1Jac any,
	Proof any,
] interface {
	VerifyPrepared(
		proof Proof,
		publicWitness Vector,
		preparedPublicWitness G1Jac,
	) error

	PreparePublicInputs(publicWitness Vector) (G1Jac, error)
}

func FromBLS12381GnarkKey(gk groth16.VerifyingKey, circuit PreparableCircuit) (PreparedVerifyingKey[fr_bls12381.Vector, *curve_bls12381.G1Jac, *groth16_bls12381.Proof], error) {
	ck, err := b.FromGnarkKey(gk.(*groth16_bls12381.VerifyingKey), circuit.PreparableIndex())
	vk := PreparedVerifyingKey[fr_bls12381.Vector, *curve_bls12381.G1Jac, *groth16_bls12381.Proof]{
		VK: ck,
	}
	return vk, err
}
