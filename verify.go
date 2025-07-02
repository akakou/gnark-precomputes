package gnarkprecomputes

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

type PreparedVerifyingKey[
	Vector any,
	G1Jac any,
	Proof any,
] struct {
	VK CorePreparedVerifyingKey[Vector, G1Jac, Proof]
}

type PreparableCircuit interface {
	PreparableIndex() int
}

func (vk *PreparedVerifyingKey[Vector, G1Jac, Proof]) PreparePublicInputs(publicWitness witness.Witness) (G1Jac, error) {
	return vk.VK.PreparePublicInputs(publicWitness.Vector().(Vector))
}

func (vk *PreparedVerifyingKey[Vector, G1Jac, Proof]) VerifyPrepared(
	proof groth16.Proof,
	publicWitness witness.Witness,
	preparedPublicWitness any,
) error {
	return vk.VK.VerifyPrepared(proof.(Proof), publicWitness.Vector().(Vector), preparedPublicWitness.(G1Jac))
}
