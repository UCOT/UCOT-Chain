// extra.go is responsible for manipulation of the extradata field.

package dbft

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// AddrListHash returns the hash value of a set of addresses.
func AddrListHash(addrList []common.Address) (hash common.Hash) {
}

// EliminateSigningField eliminates the proposer address in the extra-data field prior to validation.
func EliminateSigningField(header *types.Header) *types.Header {
}

// Add the current signer (P) to extra-data field, while every Epoch blocks, add the signers that have never signed
func (d *Dbft) addSigner(round *Round, block *types.Block, iIndex uint64) *types.Block {
}

// Randomly permute a list of addresses based on a random value generated from the parent header
func orderAddr(list []common.Address, parent *types.Header) []common.Address {
}

// insertSigner offsets the missing field back to the initial field.
func insertSigner(initial []byte, insert []byte) []byte {
}

// setVote realizes an event for voting.
// TODO: this needs to be moved elsewhere as it has nothing to do with the extra-data field.
func (d *Dbft) setVote(addrList []common.Address, votingAt uint64) error {
}

// getVote returns the requiring fields regarding the voteing.
// TODO: this needs to be moved elsewhere as it has nothing to do with the extra-data field.
func (d *Dbft) getVote() (bool, uint64, []common.Address) {
}

// clearVote suspends a pending voting.
// TODO: this needs to be moved elsewhere as it has nothing to do with the extra-data field.
func (d *Dbft) clearVote() {
}
