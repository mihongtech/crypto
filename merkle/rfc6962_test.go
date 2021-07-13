package merkle

// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// These tests were taken from https://github.com/google/trillian/blob/master/merkle/rfc6962/rfc6962_test.go,
// and consequently fall under the above license.
import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/mihongtech/crypto/tmhash"
)

func TestRFC6962Hasher(t *testing.T) {
	_, leafHashTrail := trailsFromByteSlices([][]byte{[]byte("L123456")})
	leafHash := leafHashTrail.Hash
	_, leafHashTrail = trailsFromByteSlices([][]byte{{}})
	emptyLeafHash := leafHashTrail.Hash
	_, emptyHashTrail := trailsFromByteSlices([][]byte{})
	emptyTreeHash := emptyHashTrail.Hash
	for _, tc := range []struct {
		desc string
		got  []byte
		want string
	}{
		// Check that empty trees return the hash of an empty string.
		// echo -n '' | sha256sum
		{
			desc: "RFC6962 Empty Tree",
			want: "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"[:tmhash.Size*2],
			got:  emptyTreeHash,
		},

		// Check that the empty hash is not the same as the hash of an empty leaf.
		// echo -n 00 | xxd -r -p | sha256sum
		{
			desc: "RFC6962 Empty Leaf",
			want: "2daef60e7a0b8f5e024c81cd2ab3109f2b4f155cf83adeb2ae5532f74a157fdf"[:tmhash.Size*2],
			got:  emptyLeafHash,
		},
		// echo -n 004C313233343536 | xxd -r -p | sha256sum
		{
			desc: "RFC6962 Leaf",
			want: "b62d3c1e4d175631cb0e267ac43f4fe7d45ab328085a0a0841a5dd99d72665be"[:tmhash.Size*2],
			got:  leafHash,
		},
		// echo -n 014E3132334E343536 | xxd -r -p | sha256sum
		{
			desc: "RFC6962 Node",
			want: "ceaddc3c5fbab603a1aa11181127a75c34acfd1a0bcd1ac67e3fa9ed55a5d5b6"[:tmhash.Size*2],
			got:  innerHash([]byte("N123"), []byte("N456")),
		},
	} {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			wantBytes, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatalf("hex.DecodeString(%x): %v", tc.want, err)
			}
			if got, want := tc.got, wantBytes; !bytes.Equal(got, want) {
				t.Errorf("got %x, want %x", got, want)
			}
		})
	}
}

func TestRFC6962HasherCollisions(t *testing.T) {
	// Check that different leaves have different hashes.
	leaf1, leaf2 := []byte("Hello"), []byte("World")
	_, leafHashTrail := trailsFromByteSlices([][]byte{leaf1})
	hash1 := leafHashTrail.Hash
	_, leafHashTrail = trailsFromByteSlices([][]byte{leaf2})
	hash2 := leafHashTrail.Hash
	if bytes.Equal(hash1, hash2) {
		t.Errorf("leaf hashes should differ, but both are %x", hash1)
	}
	// Compute an intermediate subtree hash.
	_, subHash1Trail := trailsFromByteSlices([][]byte{hash1, hash2})
	subHash1 := subHash1Trail.Hash
	// Check that this is not the same as a leaf hash of their concatenation.
	preimage := append(hash1, hash2...)
	_, forgedHashTrail := trailsFromByteSlices([][]byte{preimage})
	forgedHash := forgedHashTrail.Hash
	if bytes.Equal(subHash1, forgedHash) {
		t.Errorf("hasher is not second-preimage resistant")
	}
	// Swap the order of nodes and check that the hash is different.
	_, subHash2Trail := trailsFromByteSlices([][]byte{hash2, hash1})
	subHash2 := subHash2Trail.Hash
	if bytes.Equal(subHash1, subHash2) {
		t.Errorf("subtree hash does not depend on the order of leaves")
	}
}
