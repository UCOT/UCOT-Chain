// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
)

type GroupSignature struct {
	Sig    	[]byte 		 	`json:"sigs"`
	IIndex 	uint64 		 	`json:"i"`
	hash 	atomic.Value 	`json:"hash, omitempty"`
}

type GroupSignatures []*GroupSignature

func NewGroupSignature(i uint64, sig []byte) *GroupSignature {
	gsig := &GroupSignature{
		Sig:    sig,
		IIndex: i,
	}
	return gsig
}


// Hash hashes the RLP encoding of groupSig.
// It uniquely identifies the GroupSignature.
func (groupSig *GroupSignature) Hash() common.Hash {
	if hash := groupSig.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(groupSig)
	groupSig.hash.Store(v)
	return v
}

func CalcGroupSigHash(groupSig GroupSignatures) common.Hash {
	return rlpHash(groupSig)
}
