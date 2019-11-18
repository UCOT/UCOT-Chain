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
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
)

type SnapShot struct {
	config   *params.DbftConfig
	sigcache *lru.ARCCache

	Number  uint64                    `json:"number"`
	Hash    common.Hash               `json:"hash"`
	Signers map[common.Address]uint64 `json:"signers"`
}

func NewSnapShot(config *params.DbftConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, signers []common.Address) *SnapShot {
	snap := &SnapShot{
		config:   config,
		sigcache: sigcache,
		Number:   number,
		Hash:     hash,
		Signers:  make(map[common.Address]uint64),
	}
	for _, signer := range signers {
		snap.Signers[signer] = 0
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapShot(config *params.DbftConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*SnapShot, error) {
	blob, err := db.Get(append([]byte("dbft-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(SnapShot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *SnapShot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("dbft-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot.
func (s *SnapShot) copy() *SnapShot {
	cpy := &SnapShot{
		config:   s.config,
		sigcache: s.sigcache,
		Number:   s.Number,
		Hash:     s.Hash,
		Signers:  make(map[common.Address]uint64),
	}
	for signer, count := range s.Signers {
		cpy.Signers[signer] = count
	}
	return cpy
}

// apply creates a new authorization snapshot by applying the given () to
// the original one.
func (s *SnapShot) apply(headers []*types.Header) (*SnapShot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidSnapShotChain
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidSnapShotChain
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	for _, header := range headers {
		signer := header.SignerAddress()
		if _, ok := snap.Signers[signer]; !ok {
			return nil, errUnauthorized
		}

		if len(header.Extra) > types.VanityLength+types.SealLength+common.AddressLength && header.Number.Uint64() != 0 {
			addrs := make([]common.Address, 0, params.MaxMinersAllowed)
			for i := 0; i < header.NumSigners(); i++ {
				addrs = append(addrs, header.IthSigner(i))
			}
			snap.updateSigners(addrs)
		}

		// Accumulate the count, ignore if the signer has been voted out.
		if _, ok := snap.Signers[signer]; !ok {
			snap.Signers[signer] += 1
		}

		// Signers get recorded every Epoch blocks. Initialised back to zero
		if header.Number.Uint64()%s.config.Epoch == 0 {
			for k, _ := range snap.Signers {
				snap.Signers[k] = 0
			}
		}
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

func (s *SnapShot) updateSigners(signers []common.Address) {
	// Re-initialize
	for _, addr := range s.signers() {
		delete(s.Signers, addr)
	}

	for _, signer := range signers {
		s.Signers[signer] = 0
	}

}

// signers retrieves the list of authorized signers in ascending order.
func (s *SnapShot) signers() []common.Address {
	signers := make([]common.Address, 0, len(s.Signers))
	for signer := range s.Signers {
		signers = append(signers, signer)
	}
	signersOrder := sortAddrAsc(signers)
	return signersOrder
}
