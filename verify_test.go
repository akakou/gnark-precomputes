package gnarkprecomputes_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	gnarkprecomputes "github.com/akakou/gnark-precomputes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"
)

type Circuit struct {
	A frontend.Variable   `gnark:",public"`
	B []frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	res := frontend.Variable(1)
	for _, c := range circuit.B {
		res = api.Mul(res, c)
	}

	api.AssertIsEqual(res, circuit.A)
	return nil
}

func (circuit *Circuit) PreparableIndex() int {
	return 1
}

func TestProofAndVerify(t *testing.T) {
	assert := require.New(t)

	precomputes := Circuit{
		B: make([]frontend.Variable, 100),
	}
	res := 1
	for i := 0; i < 100; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(10))
		precomputes.B[i] = r

		res = res * int(r.Int64())
	}

	precomputes.A = 0

	assign := Circuit{
		A: res,
		B: []frontend.Variable{0},
	}

	circuit := Circuit{
		B: make([]frontend.Variable, 100),
	}

	cs, err := frontend.Compile(
		ecc.BLS12_381.ScalarField(),
		r1cs.NewBuilder,
		&circuit,
	)
	assert.NoError(err)

	witness, err := frontend.NewWitness(&precomputes, ecc.BLS12_381.ScalarField())
	assert.NoError(err)

	publicWitness, err := witness.Public()
	assert.NoError(err)

	witness2, err := frontend.NewWitness(&assign, ecc.BLS12_381.ScalarField())
	assert.NoError(err)

	publicWitness2, err := witness2.Public()
	assert.NoError(err)

	pk, gvk, err := groth16.Setup(cs)
	assert.NoError(err)

	vk, err := gnarkprecomputes.FromBLS12381GnarkKey(gvk, &circuit)
	assert.NoError(err)

	proof, err := groth16.Prove(cs, pk, witness)
	assert.NoError(err)

	err = groth16.Verify(proof, gvk, publicWitness)
	assert.NoError(err)

	prepared, err := vk.PreparePublicInputs(publicWitness)
	assert.NoError(err)

	err = vk.VerifyPrepared(proof, publicWitness2, prepared)
	assert.NoError(err, "proof should verify")
}
