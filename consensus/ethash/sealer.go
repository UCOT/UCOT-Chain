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

// *** denotes the UCOT dedicated code

package ethash

import (
	crand "crypto/rand"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the block's difficulty requirements.
func (ethash *Ethash) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	// Calculate delta h
	var delta_h float64
	recent := chain.GetRecentCoinbase(block.Header(), nil, false)
	Dh := int64(block.NumberU64()-recent)
	if recent < math.MaxUint64 && recent < block.NumberU64() {
		// delta_h = math.Log10(float64(block.NumberU64()-recent))
		delta_h = math.Pow(float64(Dh-128), 3) / 1024000 + 2
		log.Info("check in seal, come here","Dh",Dh,"delta_h",delta_h,"recent",recent,"coinbase",common.ToHex(block.Header().Coinbase[:8]))
		// if block.NumberU64()-recent <= core.MiningLogAtDepth {
		// 	//log.Info("check in seal, come here","delta_h",delta_h,"recent",recent,"coinbase",common.ToHex(block.Header().Coinbase[:8]))
		// 	delta_h = maths.Pow(float64(512+5-128), 3) / 1024000 + 2 
		// }
	} else {
		log.Info("check in seal, or here?","delta_h",delta_h,"recent",recent,"coinbase",common.ToHex(block.Header().Coinbase[:8]))
		// delta_h = math.Log10(2)
		delta_h = math.Pow(float64(512+5-128), 3) / 1024000 + 2 
	}
	log.Info("check delta_h in seal", "delta_h", delta_h,"number",block.NumberU64(),"recent",recent, "coinbase",common.ToHex(block.Header().Coinbase[:8]))

	// Calculate CoinAge
	age := chain.GetCoinAge(block.Header())
	log.Trace("check age in seal","age",age,"number",block.NumberU64(),"coinbase",common.ToHex(block.Header().Coinbase[:8]))

	// If we're running a fake PoW, simply return a 0 nonce immediately
	if ethash.config.PowMode == ModeFake || ethash.config.PowMode == ModeFullFake {
		header := block.Header()
		header.Nonce, header.MixDigest = types.BlockNonce{}, common.Hash{}
		return block.WithSeal(header), nil
	}
	// If we're running a shared PoW, delegate sealing to it
	if ethash.shared != nil {
		return ethash.shared.Seal(chain, block, stop)
	}
	// Create a runner and the multiple search threads it directs
	abort := make(chan struct{})
	found := make(chan *types.Block)

	ethash.lock.Lock()
	threads := ethash.threads
	if ethash.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			ethash.lock.Unlock()
			return nil, err
		}
		ethash.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	ethash.lock.Unlock()
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0 // Allows disabling local mining without extra logic around local/remote
	}
	var pend sync.WaitGroup
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			ethash.mine(delta_h, age, block, id, nonce, abort, found)
		}(i, uint64(ethash.rand.Int63()))
	}
	// Wait until sealing is terminated or a nonce is found
	var result *types.Block
	select {
	case <-stop:
		// Outside abort, stop all miner threads
		close(abort)
	case result = <-found:
		// One of the threads found a block, abort all others
		close(abort)
	case <-ethash.update:
		// Thread count was changed on user request, restart
		close(abort)
		pend.Wait()
		return ethash.Seal(chain, block, stop)
	}
	// Wait for all miners to terminate and return the block
	pend.Wait()
	return result, nil
}

// mine is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
func (ethash *Ethash) mine(delta_h float64, age float64, block *types.Block, id int, seed uint64, abort chan struct{}, found chan *types.Block) {
	// Extract some data from the header
	var (
		header  = block.Header()
		hash    = header.HashNoNonce().Bytes()
		target  = new(big.Int).Div(maxUint256, header.Difficulty)
		number  = header.Number.Uint64()
		dataset = ethash.dataset(number)
	)
	// UCOT Hybrid pos with pow, Hash(B) <= Age(A)*LOG2(delta_h)*M/D
	var (
		dh_big = new(big.Float).SetFloat64(delta_h)
		age_big = new(big.Float).SetFloat64(age)
		targetPoS = new(big.Float).SetInt(target)
	)
	targetPoS.Mul(targetPoS, dh_big)
	targetPoS.Mul(targetPoS, age_big)
	// log.Info("check", "coinbase",block.Coinbase(), "number",block.NumberU64(),"age",age_big,"dh_big",dh_big,"target",targetPoS) 
	// Start generating random nonces until we abort or find a good one
	var (
		attempts = int64(0)
		nonce    = seed
	)
	logger := log.New("miner", id)
	//logger.Trace("Started ethash search for new nonces", "seed", seed)
search:
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			//logger.Trace("Ethash nonce search aborted", "attempts", nonce-seed)
			ethash.hashrate.Mark(attempts)
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			attempts++
			if (attempts % (1 << 15)) == 0 {
				ethash.hashrate.Mark(attempts)
				attempts = 0
			}
			// Compute the PoW value of this nonce
			digest, result := hashimotoFull(dataset.dataset, hash, nonce)
			// We manage to apply POS comparison ***
			if new(big.Float).SetInt(new(big.Int).SetBytes(result)).Cmp(targetPoS) <= 0 { 
			// if new(big.Int).SetBytes(result).Cmp(target) <= 0 {
				// Correct nonce found, create a new header with it
				log.Trace("check pow in seal", "number",header.Number,"ours", new(big.Float).SetInt(new(big.Int).SetBytes(result)), "header", targetPoS, "D", header.Difficulty, "dh_big", dh_big,"age_big",age_big)
				header = types.CopyHeader(header)
				header.Nonce = types.EncodeNonce(nonce)
				header.MixDigest = common.BytesToHash(digest)

				// Seal and return a block (if still needed)
				select {
				case found <- block.WithSeal(header):
					logger.Trace("Ethash nonce found and reported", "attempts", nonce-seed, "nonce", nonce)
				case <-abort:
					logger.Trace("Ethash nonce found but discarded", "attempts", nonce-seed, "nonce", nonce)
				}
				break search
			}
			nonce++
		}
	}
	// Datasets are unmapped in a finalizer. Ensure that the dataset stays live
	// during sealing so it's not unmapped while being read.
	runtime.KeepAlive(dataset)
}
