// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package bls12381

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	// groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	// fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	groth16_bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
)

var (
	errPairingCheckFailed         = errors.New("pairing doesn't match")
	errCorrectSubgroupCheckFailed = errors.New("points in the proof are not in the correct subgroup")
)

type PreparedVerifyingKey struct {
	GnarkKey       *groth16_bls12381.VerifyingKey
	PreparedParams *PreparedVKParams
}

type PreparedVKParams struct {
	e               curve.GT
	deltaNeg        curve.G2Affine
	gammaNeg        curve.G2Affine
	preComputeIndex int
}

func isValid(proof *groth16_bls12381.Proof) bool {
	return proof.Ar.IsInSubGroup() && proof.Krs.IsInSubGroup() && proof.Bs.IsInSubGroup()
}

func FromGnarkKey(vk *groth16_bls12381.VerifyingKey, preComputeIndex int) (*PreparedVerifyingKey, error) {
	var params PreparedVKParams
	var err error

	params.e, err = curve.Pair([]curve.G1Affine{vk.G1.Alpha}, []curve.G2Affine{vk.G2.Beta})
	if err != nil {
		return nil, err
	}

	params.deltaNeg.Neg(&vk.G2.Delta)
	params.gammaNeg.Neg(&vk.G2.Gamma)
	params.preComputeIndex = preComputeIndex

	return &PreparedVerifyingKey{
		PreparedParams: &params,
		GnarkKey:       vk,
	}, nil
}

// compute e(Σx.[Kvk(t)]1, -[γ]2)
func (verifyingKey *PreparedVerifyingKey) PreparePublicInputs(publicWitness fr.Vector) (*curve.G1Jac, error) {
	vk := verifyingKey.GnarkKey
	params := verifyingKey.PreparedParams

	var kSum curve.G1Jac

	if _, err := kSum.MultiExp(vk.G1.K[1+params.preComputeIndex:], publicWitness[params.preComputeIndex:], ecc.MultiExpConfig{}); err != nil {
		return nil, err
	}

	return &kSum, nil
}

func (verifyingKey *PreparedVerifyingKey) VerifyPrepared(
	proof *groth16_bls12381.Proof,
	publicWitness fr.Vector,
	preparedPublicWitness *curve.G1Jac,
) error {
	params := verifyingKey.PreparedParams
	vk := verifyingKey.GnarkKey

	// check that the points in the proof are in the correct subgroup
	if !isValid(proof) {
		return errCorrectSubgroupCheckFailed
	}

	var doubleML curve.GT
	chDone := make(chan error, 1)

	// compute (eKrsδ, eArBs)
	go func() {
		var errML error
		doubleML, errML = curve.MillerLoop([]curve.G1Affine{proof.Krs, proof.Ar}, []curve.G2Affine{params.deltaNeg, proof.Bs})
		chDone <- errML
		close(chDone)
	}()

	prepared := curve.G1Jac{}
	prepared.Set(preparedPublicWitness)

	var kSum curve.G1Jac
	if _, err := kSum.MultiExp(vk.G1.K[1:params.preComputeIndex+1], publicWitness[:params.preComputeIndex], ecc.MultiExpConfig{}); err != nil {
		return err
	}

	prepared.AddMixed(&vk.G1.K[0])
	prepared.AddAssign(&kSum)

	for i := range proof.Commitments {
		prepared.AddMixed(&proof.Commitments[i])
	}

	var kSumAff curve.G1Affine
	kSumAff.FromJacobian(&prepared)

	right, err := curve.MillerLoop([]curve.G1Affine{kSumAff}, []curve.G2Affine{params.gammaNeg})
	if err != nil {
		return err
	}

	// wait for (eKrsδ, eArBs)
	if err := <-chDone; err != nil {
		return err
	}

	right = curve.FinalExponentiation(&right, &doubleML)
	if !params.e.Equal(&right) {
		return errPairingCheckFailed
	}

	return nil
}
