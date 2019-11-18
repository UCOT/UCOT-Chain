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

// Package dbft implements the delegated bft consensus engine.

package dbft

import (
	"bytes"
	"errors"
	"math/big"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"
)

const (
	checkpointInterval = 1024                    // Number of blocks after which to save the snapshot to the database
	snapshotsInMemory  = 128                     // Number of recent vote snapshots to keep in memory
	signaturesInMemory = 4096                    // Number of recent block signatures to keep in memory
	wiggleTime         = 1000 * time.Millisecond // Random delay (per signer) to allow concurrent signers

	scriptN = 262144
	scriptP = 1
)

// Protocol constants.
var (
	blockPeriod = uint64(10)        // Default minimum difference between two consecutive block's timestamps
	epochLength = uint64(999999999) // Default number of blocks after which to checkpoint and record the unattended signers
	MinePeriod  = uint64(0)         // Default minimum difference between two mining operation's timestamps

	uncleHash = types.CalcUncleHash(nil)

	diff = big.NewInt(1) // Assume difficulty is one, add this to todo list for further uses.

	changeViewDivision = float64(3)
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidTx is returned when invalid transactions are found in validation process.
	errInvalidTx = errors.New("invalid transactions involve")

	// errInvalidInitialStae is returned when there is at least one validator having different state from others (h, v).
	errInvalidInitialState = errors.New("not starting from the state")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// errExtraSigners is returned if non-checkpoint block contain more than one signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains more than extra signer list")

	// errExtraUnknownSigners is returned if non-checkpoint block contain an unknown signer data in
	// their extra-data fields.
	errExtraUnknownSigners = errors.New("non-checkpoint block contains an unknown extra signer list")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is not either
	// of 1 , or if the value does not match the turn of the signer.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// ErrInvalidTimestamp is returned if the coinbase is not part of the current
	// mining list.
	errInvalidCoinbase = errors.New("invalid coinbase")

	// errUnauthorized is returned if a header is signed by a non-authorized entity.
	errUnauthorized = errors.New("unauthorized signer")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidSnapShotChain = errors.New("invalid snapshot chain")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of missing signers (i.e. non divisible by 20 bytes, or not the correct
	// ones).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errUpdatedList is returned if the length of this field is invalid
	errUpdatedList = errors.New("invalid updated miner list")

	// errUpdatedListOrdered is returned if the order is invalid
	errUpdatedListOrdered = errors.New("invalid order of the updated miner list")

	// errUpdatedListMisMatch is returned if the list updated does not matched with the local's list
	errUpdatedListMisMatch = errors.New("Updated miner list does not matched")
)

// SignerFn is a signer callback function to request a hash to be signed by a
// backing account.
// // Sign all the things!
// sighash, err := signFn(accounts.Account{Address: signer}, sigHash(header).Bytes())
type SignerFn func(accounts.Account, []byte) ([]byte, error)

// sigHash returns the hash which is used as input for the DBFT
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func sigHash(header *types.Header) (hash common.Hash) {
}

// Dbft is the Delegated Byzantine Fault Tolerance consensus engine
type Dbft struct {
	ctx    *node.ServiceContext
	config *params.DbftConfig
	db     ethdb.Database

	txPool TxPool

	eventMux     *event.TypeMux
	events       *event.TypeMuxSubscription
	votingEvents *event.TypeMuxSubscription

	// // See const
	recentsSnaps *lru.ARCCache
	signatures   *lru.ARCCache

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the signer fields

	isLight bool // Flag to indicate if the local node is a light node

	// Voting System
	isVoting    bool             // Flag to indicate if the local node has started a voting round
	votingAt    uint64           // Holds the block number that the current voting stored in will take place
	updatedList []common.Address // List updated that is being sent with the block where the local node becomes the speaker

	// For a new view counting, separated from deList.VIndex
	view uint64

	// For Byzantine test
	isByzantine bool // Flag to indicate if the local node is byzantined
	// checkVoteCount uint64 // Counter for checkVote, reset every time Prepare is running
}

// New creates a Dbft consensus engine with the initial
// signers set to the ones provided by the user.
func New(ctx *node.ServiceContext, config *params.DbftConfig, db ethdb.Database, eventMux *event.TypeMux, isLight bool) *Dbft { //***
	// Set any missing consensus parameters to their defaults
	conf := *config

	conf.Epoch = epochLength
	conf.Period = blockPeriod

	recentsSnaps, _ := lru.NewARC(snapshotsInMemory)
	signatures, _ := lru.NewARC(signaturesInMemory)

	return &Dbft{
		ctx:    ctx,
		config: &conf,
		db:     db,

		eventMux:     eventMux,
		recentsSnaps: recentsSnaps,
		signatures:   signatures,
		isLight:      isLight,
		isVoting:     false,
		votingAt:     0,
		updatedList:  make([]common.Address, 0, params.MaxMinersAllowed),
		view:         0,

		isByzantine: false,
	}
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (d *Dbft) Author(header *types.Header) (common.Address, error) {
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (d *Dbft) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).

// This function is called by InsertChain() in blockchain.go
func (d *Dbft) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (d *Dbft) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header, addrList []common.Address) error {
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (d *Dbft) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (d *Dbft) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles are not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (d *Dbft) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return d.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (d *Dbft) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
}

// Returns a snapshot containing a count of how many times each signer has contributed.
// SnapShot chain is always one block behind the canonical chain
func (d *Dbft) SnapShot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*SnapShot, error) {
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (d *Dbft) Prepare(chain consensus.ChainReader, header *types.Header) error {
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (d *Dbft) Authorize(signer common.Address, signFn SignerFn) {
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (d *Dbft) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {

	// // Run Consensus
	// newBlock, err := d.Consensus(chain, block, stop)
	// d.closeChannels()
	// log.Trace("Number of Goroutines", "number", runtime.NumGoroutine())

}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (d *Dbft) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)
	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, nil), nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (d *Dbft) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return big.NewInt(1)
}

func (d *Dbft) GetConsensusConfig() params.ConsensusConfig {
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer signing.
func (d *Dbft) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "dbft",
		Version:   "1.0",
		Service:   &API{chain: chain, dbft: d},
		Public:    false,
	}}
}
