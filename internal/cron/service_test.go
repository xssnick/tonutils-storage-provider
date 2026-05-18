package cron

import (
	"bytes"
	"testing"

	"github.com/xssnick/tonutils-go/tvm/cell"
)

func TestBuildCronStateInitFromDataProofMatchesTonutilsProofBody(t *testing.T) {
	code := cell.BeginCell().MustStoreUInt(0xAABBCCDD, 32).EndCell()
	dataLeaf := cell.BeginCell().MustStoreUInt(0x11, 8).EndCell()
	data := cell.BeginCell().MustStoreUInt(0x22, 8).MustStoreRef(dataLeaf).EndCell()

	fullState := cell.BeginCell().
		MustStoreUInt(0b00110, 5).
		MustStoreRef(code).
		MustStoreRef(data).
		EndCell()

	proofBuilder := cell.NewMerkleProofBuilder(fullState)
	proofRoot := proofBuilder.Root()
	proofRootSlice, err := proofRoot.BeginParse()
	if err != nil {
		t.Fatalf("failed to parse traced state init: %v", err)
	}
	if _, err = proofRootSlice.LoadUInt(5); err != nil {
		t.Fatalf("failed to read traced state init flags: %v", err)
	}
	codeSlice, err := proofRootSlice.LoadRef()
	if err != nil {
		t.Fatalf("failed to load traced code ref: %v", err)
	}
	if _, err = codeSlice.LoadUInt(32); err != nil {
		t.Fatalf("failed to read traced code ref: %v", err)
	}

	proof, err := proofBuilder.CreateProof()
	if err != nil {
		t.Fatalf("failed to create tonutils state proof: %v", err)
	}

	proofBody, err := cell.UnwrapProof(proof, fullState.Hash())
	if err != nil {
		t.Fatalf("failed to unwrap tonutils state proof: %v", err)
	}

	fromNotification, err := buildCronStateInitFromDataProof(code, data.Hash(0), data.Depth(0))
	if err != nil {
		t.Fatalf("failed to build state init from data proof: %v", err)
	}

	if !bytes.Equal(fromNotification.Hash(0), fullState.Hash(0)) {
		t.Fatal("state init built from data proof does not match full state hash")
	}
	if !bytes.Equal(fromNotification.Hash(0), proofBody.Hash(0)) {
		t.Fatal("state init built from data proof does not match tonutils proof body hash")
	}
	if got := fromNotification.LevelMask().Mask; got != proofBody.LevelMask().Mask {
		t.Fatalf("unexpected proof body level mask: got %d, want %d", got, proofBody.LevelMask().Mask)
	}
}
