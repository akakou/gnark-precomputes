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
	A frontend.Variable
	B [100]frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	res := frontend.Variable(1)
	for _, c := range circuit.B {
		res = api.Mul(res, c)
	}

	api.AssertIsEqual(res, circuit.A)
	return nil
}
func TestProofAndVerify(t *testing.T) {
	assert := require.New(t)

	var assignment Circuit
	res := 1
	for i := 0; i < 100; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(10))

		assignment.B[i] = r
		res = res * int(r.Int64())
	}
	assignment.A = res

	var circuit Circuit
	cs, err := frontend.Compile(
		ecc.BLS12_381.ScalarField(),
		r1cs.NewBuilder,
		&circuit,
	)
	assert.NoError(err)

	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	assert.NoError(err)

	publicWitness, err := witness.Public()
	assert.NoError(err)

	pk, gvk, err := groth16.Setup(cs)
	assert.NoError(err)

	vk, err := gnarkprecomputes.FromBLS12381GnarkKey(gvk, 1)
	assert.NoError(err)

	proof, err := groth16.Prove(cs, pk, witness)
	assert.NoError(err)

	err = groth16.Verify(proof, gvk, publicWitness)
	assert.NoError(err)

	prepared, err := vk.PreparePublicInputs(publicWitness)
	assert.NoError(err)

	err = vk.VerifyPrepared(proof, publicWitness, prepared)
	assert.NoError(err, "proof should verify")
}
