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
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/params"
	// "github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

// API is a user facing RPC API to allow controlling the signer
// mechanisms of dbft scheme.
type API struct {
	chain consensus.ChainReader
	dbft  *Dbft
}

// GetSnapshot retrieves the state snapshot at a given block.
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*SnapShot, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.dbft.SnapShot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSnapshotAtHash retrieves the state snapshot at a given block.
func (api *API) GetSnapshotAtHash(hash common.Hash) (*SnapShot, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	return api.dbft.SnapShot(api.chain, header.Number.Uint64(), header.Hash(), nil)
}

// GetSigners retrieves the list of authorized signers at the specified block.
// Here the signer is the node who broadcasts the newblock
func (api *API) GetSigners(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.dbft.SnapShot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

// GetSignersAtHash retrieves the state snapshot at a given block.
// Here the signer is the node who broadcasts the newblock
func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash)
	if header == nil {
		return nil, errUnknownBlock
	}
	snap, err := api.dbft.SnapShot(api.chain, header.Number.Uint64(), header.Hash(), nil)
	if err != nil {
		return nil, err
	}
	return snap.signers(), nil
}

type GroupSigFormatter struct {
	Sig    string `json:"sigs"`
	IIndex uint64 `json:"i"`
}

// GetGroupSigsAtNumber retrieves the group signature at a given block.
func (api *API) GetGroupSigsAtNumber(number *rpc.BlockNumber) ([]GroupSigFormatter, error) {
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader()
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64()))
	}
	// Ensure we have an actually valid block and return its snapshot
	if header == nil {
		return nil, errUnknownBlock
	}
	sigsRLP, _ := api.chain.GetGroupSigRLP(header.Hash())
	sigs := new([]types.GroupSignature)
	if err := rlp.Decode(bytes.NewReader(sigsRLP), sigs); err != nil {
		return nil, err
	}
	sigstr := make([]GroupSigFormatter, len(*sigs))
	for i, v := range *sigs {
		sigstr[i].Sig = common.ToHex(v.Sig)
		sigstr[i].IIndex = v.IIndex
	}
	return sigstr, nil
	// return *sigs, nil
}

// GetGroupSigsAtHash retrieves the group signature at a given block.
func (api *API) GetGroupSigsAtHash(blockHash common.Hash) ([]GroupSigFormatter, error) {
	header := api.chain.GetHeaderByHash(blockHash)
	if header == nil {
		return nil, errUnknownBlock
	}
	sigsRLP, _ := api.chain.GetGroupSigRLP(blockHash)
	sigs := new([]types.GroupSignature)
	if err := rlp.Decode(bytes.NewReader(sigsRLP), sigs); err != nil {
		return nil, err
	}
	sigstr := make([]GroupSigFormatter, len(*sigs))
	for i, v := range *sigs {
		sigstr[i].Sig = common.ToHex(v.Sig)
		sigstr[i].IIndex = v.IIndex
	}
	return sigstr, nil
	// return *sigs, nil
}

var voteList []common.Address
var votingAt uint64

// User enters a list of comma separated addresses, which he desires to be the next mining list.
func (api *API) UpdateVote(addrStr string, updatedVotingAt uint64) error {
	updatedVoteList := make([]common.Address, 0, int(params.MaxMinersAllowed))

	// Check that all addresses are valid
	addrListStr := strings.Split(addrStr, ",")
	for _, addr := range addrListStr {
		addr = strings.Trim(addr, " ")
		if !common.IsHexAddress(addr) {
			fmt.Printf("\"%s\" is not a valid address. Please ensure that all addresses are valid, and comma separated.\n", addr)
			return errors.New("Invalid address string")
		}
		updatedVoteList = append(updatedVoteList, common.HexToAddress(addr))
	}

	// Check list length
	if len(updatedVoteList) < int(params.MinMinersAllowed) {
		fmt.Println("You have entered too few addresses. There must be at least", int(params.MinMinersAllowed), "addresses in your list")
		return errors.New("Too few addresses")
	} else if len(updatedVoteList) > int(params.MaxMinersAllowed) {
		fmt.Println("You have entered too many addresses. There may be at most", int(params.MaxMinersAllowed), "addresses in your list")
		return errors.New("Too many addresses")
	}

	// Check that there are no duplicates
	sorted := sortAddrAsc(updatedVoteList)
	for i := 0; i < len(sorted)-1; i++ {
		if sorted[i] == sorted[i+1] {
			fmt.Printf("You have entered the address \"%s\" more than once. Please remove any duplicates and try again.\n", sorted[i].Hex())
			return errors.New("Duplicate addresses not allowed")
		}
	}

	// Check that the vote isn't already equal to the current mining pool
	if api.IsVoteInEffect(updatedVoteList) {
		voteList = nil
		fmt.Println("Your vote is exactly the same as the current miner list. Please add or remove an address")
		return errors.New("Vote the same as miner list")
	}

	// Check that votingAt is at a block larger than the current block
	currentNumber := api.chain.CurrentHeader().Number.Uint64()
	if updatedVotingAt <= currentNumber {
		fmt.Println("The block you are trying to vote at has already been created")
		return errors.New("Invalid votingAt")
	}

	if err := api.dbft.setVote(updatedVoteList, updatedVotingAt); err != nil {
		return err
	}
	voteList = updatedVoteList
	votingAt = updatedVotingAt

	// Display entered vote to user
	api.CheckVote()
	fmt.Println("Your vote has been successfully updated!")
	return nil
}

// Prints out the current list of miners
func (api *API) GetMinerList() error {
	miners := api.chain.GetLastVote()
	fmt.Println("-------------------------------------------")
	fmt.Println("The Current Mining List:")
	for i, vote := range miners {
		str := strconv.Itoa(i+1) + ": "
		str += vote.String()
		fmt.Println(str)
	}
	fmt.Println("-------------------------------------------")
	return nil
}

// Clears the user's vote
func (api *API) ClearVote() error {
	voteList = nil
	votingAt = 0
	api.dbft.clearVote()
	fmt.Println("All votes successfully cleared from list!")
	return nil
}

// Allows a user to check their vote
func (api *API) CheckVote() error {
	if api.IsVoteInEffect(voteList) {
		votingAt = 0
		voteList = nil
	}
	fmt.Println("-------------------------------------------")
	if len(voteList) == 0 {
		fmt.Println("Your voting list is empty. Use updateVote to input your own vote.")
	} else {
		fmt.Println("Miners You Are Voting For:")
		for i, vote := range voteList {
			str := strconv.Itoa(i+1) + ": "
			str += vote.String()
			fmt.Println(str)
		}
	}
	fmt.Println("Your vote will be made on block", votingAt)
	fmt.Println("-------------------------------------------")
	return nil
}

// Returns whether the current voting list is the also the current mining list.
func (api *API) IsVoteInEffect(currVoteList []common.Address) bool {
	miners := api.chain.GetLastVote()
	if bytes.Compare(common.AddrToByteSlice(sortAddrAsc(miners)), common.AddrToByteSlice(sortAddrAsc(currVoteList))) == 0 {
		return true
	} else {
		return false
	}
}

// An API just for me to write personal tests
func (api *API) Test() {
	header := api.chain.GetHeaderByNumber(63)
	fmt.Println("Header 63 Coinbase", header.Coinbase.Hex())
}

// APIs to test the Byzantine faulty
func (api *API) SetByzantine(byzantine bool) {
	api.dbft.setByzantine(byzantine)
	fmt.Println("-------------------------------------------")
	fmt.Println("Byzantine is set to:", byzantine)
	fmt.Println("-------------------------------------------")
}

func (api *API) GetByzantine() {
	byzantine := api.dbft.getByzantine()
	fmt.Println("-------------------------------------------")
	fmt.Println("Byzantined:", byzantine)
	fmt.Println("-------------------------------------------")
}
