package gnarkprecomputes_test

import (
	"fmt"
	"testing"

	gnarkprecomputes "github.com/akakou/gnark-precomputes"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"
)

type Circuit struct {
	A frontend.Variable   `gnark:",public"`
	B []frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	res := frontend.Variable(0)
	for _, c := range circuit.B {
		res = api.Add(res, c)
	}

	api.AssertIsEqual(res, circuit.A)
	return nil
}

func (circuit *Circuit) NonPrecomputables() []int {
	return []int{1}
}

func prepare(assert *require.Assertions) (groth16.Proof, groth16.VerifyingKey, Circuit, Circuit) {
	A := 0
	B := make([]frontend.Variable, 100)
	for i := 0; i < 100; i++ {
		B[i] = frontend.Variable(i + 1)
		A = A + i + 1
	}

	fmt.Printf("expect: %v and %v\n", A, B)

	assign := Circuit{
		A: frontend.Variable(A),
		B: B,
	}

	circuit := Circuit{
		A: 0,
		B: make([]frontend.Variable, 100),
	}

	wit, err := frontend.NewWitness(&assign, ecc.BLS12_381.ScalarField())
	assert.NoError(err)

	pubWit, err := wit.Public()
	assert.NoError(err)

	cs, err := frontend.Compile(
		ecc.BLS12_381.ScalarField(),
		r1cs.NewBuilder,
		&circuit,
	)
	assert.NoError(err)

	pk, gvk, err := groth16.Setup(cs)
	assert.NoError(err)

	proof, err := groth16.Prove(cs, pk, wit)
	assert.NoError(err)

	err = groth16.Verify(proof, gvk, pubWit)
	assert.NoError(err)

	return proof, gvk, circuit, assign
}

func TestProofAndVerify(t *testing.T) {
	assert := require.New(t)

	proof, gvk, circuit, assign := prepare(assert)

	precomputes := Circuit{
		A: assign.A,
		B: append(assign.B[0:0:0], assign.B...),
	}
	precomputes.B[0] = frontend.Variable(0)

	ok := Circuit{
		A: assign.A,
		B: append(assign.B[0:0:0], assign.B...),
	}

	failed := Circuit{
		A: assign.A,
		B: append(assign.B[0:0:0], assign.B...),
	}

	failed.B[0] = frontend.Variable(0)

	vk, err := gnarkprecomputes.FromBLS12381GnarkKey(gvk, &circuit)
	assert.NoError(err)

	prepareWit, err := frontend.NewWitness(&precomputes, bls12381.ID.ScalarField())
	assert.NoError(err)
	preparePubWit, err := prepareWit.Public()
	prepared, err := vk.PreparePublicInputs(preparePubWit)
	assert.NoError(err)

	err = VerifyOne(vk, prepared, proof, ok, assert)
	assert.NoError(err)

	err = VerifyOne(vk, prepared, proof, failed, assert)
	assert.Error(err)

}

func VerifyOne(vk gnarkprecomputes.PreparedVerifyingKey[fr.Vector, *bls12381.G1Jac, *groth16_bls12381.Proof], prepared any, proof groth16.Proof, circuit Circuit, assert *require.Assertions) error {
	wit, err := frontend.NewWitness(&circuit, ecc.BLS12_381.ScalarField())
	assert.NoError(err)

	pubWit, err := wit.Public()
	assert.NoError(err)

	err = vk.VerifyPrepared(proof, pubWit, prepared)
	return err
}
