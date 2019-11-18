// Copyright 2017 The go-ethereum Authors
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

package dbft

import (
	"crypto/ecdsa"
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
)

// Speaker states
const (
	WaitingForPeriod = iota
	SentPreReq
	SentAllTxResp
)

// Delegate states
const (
	NoPreReq = iota
	HasPreReq
	SentTxReq
	HasTxResp
)

// Round holds important information about the current round of dbft consensus
type Round struct {
}

func (d *Dbft) newRound(chain consensus.ChainReader, block *types.Block, chans *consensusChannels) (*Round, error) {
}

func CalcPIndex(number uint64, view uint64, num_miners uint64) uint64 {
	return (number - view) % num_miners
}

func (round *Round) isSpeaker() bool {
	return round.pIndex == round.iIndex
}

// Returns a map of addresses to their indexes
func getAddrToIindex(list []common.Address) map[common.Address]uint64 {
	newMap := make(map[common.Address]uint64)

	for index, value := range list {
		newMap[value] = uint64(index)
	}
	return newMap
}

// Returns a random permutation of an address list
// Used to determine the order of a list of miners, given the parent number
// they were voted in as the seed.
func shuffleAddrList(list []common.Address, seed int64) []common.Address {
	r := rand.New(rand.NewSource(seed))
	nums := r.Perm(len(list))

	newList := make([]common.Address, 0, len(list))
	for _, value := range nums {
		newList = append(newList, list[value])
	}
	return newList
}
