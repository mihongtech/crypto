package merkle

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tmrand "github.com/mihongtech/tendermint/libs/rand"
	. "github.com/mihongtech/tendermint/libs/test"

	"github.com/mihongtech/crypto/tmhash"
)

type testItem []byte

func (tI testItem) Hash() []byte {
	return []byte(tI)
}

func TestHashFromByteSlices(t *testing.T) {
	testcases := map[string]struct {
		slices     [][]byte
		expectHash string // in hex format
	}{
		"nil":          {nil, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
		"empty":        {[][]byte{}, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
		"single":       {[][]byte{{1, 2, 3}}, "4b41bc3558731767a4b19187a64f8d171878ef5a45bfd73670815c2c66387d75"},
		"single blank": {[][]byte{{}}, "2daef60e7a0b8f5e024c81cd2ab3109f2b4f155cf83adeb2ae5532f74a157fdf"},
		"two":          {[][]byte{{1, 2, 3}, {4, 5, 6}}, "f97a1c8fff5fedd243ae80c1c2b08a0c960e4bd5660ad65062a66e4ae523250e"},
		"many": {
			[][]byte{{1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}},
			"5d7bf1382f761d7794d2f169362b803dad17d5efaba080c53c0bc256a7408fb5",
		},
	}
	for name, tc := range testcases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			hash := HashFromByteSlices(tc.slices)
			assert.Equal(t, tc.expectHash, hex.EncodeToString(hash))
		})
	}
}

func TestProof(t *testing.T) {

	// Try an empty proof first
	rootHash, proofs := ProofsFromByteSlices([][]byte{})
	require.Equal(t, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", hex.EncodeToString(rootHash))
	require.Empty(t, proofs)

	total := 100

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(tmrand.Bytes(tmhash.Size))
	}

	rootHash = HashFromByteSlices(items)

	rootHash2, proofs := ProofsFromByteSlices(items)

	require.Equal(t, rootHash, rootHash2, "Unmatched root hashes: %X vs %X", rootHash, rootHash2)

	// For each item, check the trail.
	for i, item := range items {
		proof := proofs[i]

		// Check total/index
		require.EqualValues(t, proof.Index, i, "Unmatched indicies: %d vs %d", proof.Index, i)

		require.EqualValues(t, proof.Total, total, "Unmatched totals: %d vs %d", proof.Total, total)

		// Verify success
		err := proof.Verify(rootHash, item)
		require.NoError(t, err, "Verification failed: %v.", err)

		// Trail too long should make it fail
		origAunts := proof.Aunts
		proof.Aunts = append(proof.Aunts, tmrand.Bytes(32))
		err = proof.Verify(rootHash, item)
		require.Error(t, err, "Expected verification to fail for wrong trail length")

		proof.Aunts = origAunts

		// Trail too short should make it fail
		proof.Aunts = proof.Aunts[0 : len(proof.Aunts)-1]
		err = proof.Verify(rootHash, item)
		require.Error(t, err, "Expected verification to fail for wrong trail length")

		proof.Aunts = origAunts

		// Mutating the itemHash should make it fail.
		err = proof.Verify(rootHash, MutateByteSlice(item))
		require.Error(t, err, "Expected verification to fail for mutated leaf hash")

		// Mutating the rootHash should make it fail.
		err = proof.Verify(MutateByteSlice(rootHash), item)
		require.Error(t, err, "Expected verification to fail for mutated root hash")
	}
}

func TestHashAlternatives(t *testing.T) {

	total := 100

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(tmrand.Bytes(tmhash.Size))
	}

	rootHash1 := HashFromByteSlicesIterative(items)
	rootHash2 := HashFromByteSlices(items)
	require.Equal(t, rootHash1, rootHash2, "Unmatched root hashes: %X vs %X", rootHash1, rootHash2)
}

func BenchmarkHashAlternatives(b *testing.B) {
	total := 100

	items := make([][]byte, total)
	for i := 0; i < total; i++ {
		items[i] = testItem(tmrand.Bytes(tmhash.Size))
	}

	b.ResetTimer()
	b.Run("recursive", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HashFromByteSlices(items)
		}
	})

	b.Run("iterative", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = HashFromByteSlicesIterative(items)
		}
	})
}

func Test_getSplitPoint(t *testing.T) {
	tests := []struct {
		length int64
		want   int64
	}{
		{1, 0},
		{2, 1},
		{3, 2},
		{4, 2},
		{5, 4},
		{10, 8},
		{20, 16},
		{100, 64},
		{255, 128},
		{256, 128},
		{257, 256},
	}
	for _, tt := range tests {
		got := getSplitPoint(tt.length)
		require.EqualValues(t, tt.want, got, "getSplitPoint(%d) = %v, want %v", tt.length, got, tt.want)
	}
}
