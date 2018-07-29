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
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	set "gopkg.in/fatih/set.v0"

	// UCOT dedicated
	maths "math"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core"
)

// Ethash proof-of-work protocol constants.
var (
	FrontierBlockReward    *big.Int = big.NewInt(5e+18) // Block reward in wei for successfully mining a block
	ByzantiumBlockReward   *big.Int = big.NewInt(3e+18) // Block reward in wei for successfully mining a block upward from Byzantium
	maxUncles                       = 2                 // Maximum number of uncles allowed in a single block
	allowedFutureBlockTime          = 15 * time.Second  // Max time from current time allowed for blocks, before they're considered future blocks

	// UCOT dedicated
	UCTBlockReward         *big.Int = big.NewInt(1e+18) // Block reward in wei for successfully mining a block in UCT-Token
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errLargeBlockTime    = errors.New("timestamp too big")
	errZeroBlockTime     = errors.New("timestamp equals parent's")
	errTooManyUncles     = errors.New("too many uncles")
	errDuplicateUncle    = errors.New("duplicate uncle")
	errUncleIsAncestor   = errors.New("uncle is ancestor")
	errDanglingUncle     = errors.New("uncle's parent is not ancestor")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidMixDigest  = errors.New("invalid mix digest")
	errInvalidPoW        = errors.New("invalid proof-of-work")
)

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
func (ethash *Ethash) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum ethash engine.
func (ethash *Ethash) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	// If we're running a full engine faking, accept any input as valid
	if ethash.config.PowMode == ModeFullFake {
		return nil
	}
	// Short circuit if the header is known, or it's parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	return ethash.verifyHeader(chain, header, parent, false, seal, nil) 
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (ethash *Ethash) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// If we're running a full engine faking, accept any input as valid
	if ethash.config.PowMode == ModeFullFake || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for i := 0; i < len(headers); i++ {
			results <- nil
		}
		return abort, results
	}

	// Spawn as many workers as allowed threads
	workers := runtime.GOMAXPROCS(0)
	if len(headers) < workers {
		workers = len(headers)
	}

	// Create a task channel and spawn the verifiers
	var (
		inputs = make(chan int)
		done   = make(chan int, workers)
		errors = make([]error, len(headers))
		abort  = make(chan struct{})
	)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				errors[index] = ethash.verifyHeaderWorker(chain, headers, seals, index)
				done <- index
			}
		}()
	}

	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			inputs  = inputs
		)
		for {
			select {
			case inputs <- in:
				if in++; in == len(headers) {
					// Reached end of headers. Stop sending to workers.
					inputs = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- errors[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (ethash *Ethash) verifyHeaderWorker(chain consensus.ChainReader, headers []*types.Header, seals []bool, index int) error {
	var parent *types.Header
	if index == 0 {
		parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	} else if headers[index-1].Hash() == headers[index].ParentHash {
		parent = headers[index-1]
	}
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	if chain.GetHeader(headers[index].Hash(), headers[index].Number.Uint64()) != nil {
		return nil // known block
	}
	// Slice the past 512 ancestor for CoinAge and Delta_h
	var (
		ancestors_pos = make([]*types.Header, 0, core.CoinbaseSearchingLimit)
	    grandParents *types.Header
	)
	if index < core.MiningLogAtDepth {
		if headers[index].Number.Uint64() < core.MiningLogAtDepth {
			grandParents = chain.GetHeaderByNumber(0)
		} else {
			grandParents = chain.GetHeaderByNumber(headers[index].Number.Uint64()-core.MiningLogAtDepth)
		}
		ancestors_pos = append(ancestors_pos, grandParents)
	} else {
		grandParents = headers[index-core.MiningLogAtDepth]
	}
	for i := index-core.MiningLogAtDepth; len(ancestors_pos) < core.CoinbaseSearchingLimit && i >= 0; grandParents = headers[i] {
		ancestors_pos = append(ancestors_pos, grandParents)
		i--
		if i < 0 {
			break
		}
	}
	if len(ancestors_pos) < core.CoinbaseSearchingLimit && grandParents.Number.Uint64() > 0 { // retrieve headers from database if the size is insufficient
		current := chain.GetHeader(grandParents.ParentHash, grandParents.Number.Uint64()-1)
		for ; len(ancestors_pos) < core.CoinbaseSearchingLimit && current.Number.Uint64() >= 0; current = chain.GetHeader(current.ParentHash, current.Number.Uint64()-1) {
			ancestors_pos = append(ancestors_pos, current)
			if current.Number.Uint64() == 0 {
				break
			}
		}
	}
	return ethash.verifyHeader(chain, headers[index], parent, false, seals[index], ancestors_pos)
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the stock Ethereum ethash engine.
func (ethash *Ethash) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	// If we're running a full engine faking, accept any input as valid
	if ethash.config.PowMode == ModeFullFake {
		return nil
	}
	// Verify that there are at most 2 uncles included in this block
	if len(block.Uncles()) > maxUncles {
		return errTooManyUncles
	}
	// Gather the set of past uncles and ancestors
	uncles, ancestors := set.New(), make(map[common.Hash]*types.Header)

	number, parent := block.NumberU64()-1, block.ParentHash()

	for i := 0; i < 7; i++ { // Within depth of 7
		ancestor := chain.GetBlock(parent, number)
		if ancestor == nil {
			break
		}
		ancestors[ancestor.Hash()] = ancestor.Header()
		for _, uncle := range ancestor.Uncles() {
			uncles.Add(uncle.Hash())
		}
		parent, number = ancestor.ParentHash(), number-1
	}
	ancestors[block.Hash()] = block.Header()
	uncles.Add(block.Hash())

	// Verify each of the uncles that it's recent, but not an ancestor
	for _, uncle := range block.Uncles() {
		// Make sure every uncle is rewarded only once
		hash := uncle.Hash()
		if uncles.Has(hash) {
			return errDuplicateUncle
		}
		uncles.Add(hash)

		// Make sure the uncle has a valid ancestry
		if ancestors[hash] != nil {
			return errUncleIsAncestor
		}
		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == block.ParentHash() {
			return errDanglingUncle
		}
		if err := ethash.verifyHeader(chain, uncle, ancestors[uncle.ParentHash], true, true, nil); err != nil {
			return err
		}
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum ethash engine.
// See YP section 4.3.4. "Block Header Validity"
func (ethash *Ethash) verifyHeader(chain consensus.ChainReader, header, parent *types.Header, uncle bool, seal bool, ancestors_pos []*types.Header) error {
	// Ensure that the header's extra-data section is of a reasonable size
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	// Ensure that the header's balance section is of a reasonable size
	if uint64(len(header.CoinAge)) > params.MaximumBalanceSize {
		return fmt.Errorf("coin age too long: %d > %d", len(header.CoinAge), params.MaximumBalanceSize)
	}
	// Ensure that the header's balance section is of a reasonable size
	if new(big.Int).SetBytes(header.CoinMined).Cmp(params.ReleaseTotal) > 0 {
		return fmt.Errorf("invalid coin-mined")
	}

	// Verify the header's timestamp
	if uncle {
		if header.Time.Cmp(math.MaxBig256) > 0 {
			return errLargeBlockTime
		}
	} else {
		if header.Time.Cmp(big.NewInt(time.Now().Add(allowedFutureBlockTime).Unix())) > 0 {
			return consensus.ErrFutureBlock
		}
	}
	if header.Time.Cmp(parent.Time) <= 0 {
		return errZeroBlockTime
	}
	// Verify the block's difficulty based in it's timestamp and parent's difficulty
	expected := ethash.CalcDifficulty(chain, header.Time.Uint64(), parent)

	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, expected)
	}
	// Verify that the gas limit is <= 2^63-1
	cap := uint64(0x7fffffffffffffff)
	if header.GasLimit > cap {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, cap)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	// Verify that the gas limit remains within allowed bounds
	diff := int64(parent.GasLimit) - int64(header.GasLimit)
	if diff < 0 {
		diff *= -1
	}
	limit := parent.GasLimit / params.GasLimitBoundDivisor

	if uint64(diff) >= limit || header.GasLimit < params.MinGasLimit {
		return fmt.Errorf("invalid gas limit: have %d, want %d += %d", header.GasLimit, parent.GasLimit, limit)
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verify the engine specific seal securing the block
	if seal {
		if err := ethash.VerifySeal(chain, header, ancestors_pos, uncle); err != nil {
			return err
		}
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyDAOHeaderExtraData(chain.Config(), header); err != nil {
		return err
	}
	if err := misc.VerifyForkHashes(chain.Config(), header, uncle); err != nil {
		return err
	}
	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func (ethash *Ethash) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	return CalcDifficulty(chain.Config(), time, parent)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func CalcDifficulty(config *params.ChainConfig, time uint64, parent *types.Header) *big.Int {
	next := new(big.Int).Add(parent.Number, big1)
	switch {
	case config.IsByzantium(next):
		return calcDifficultyByzantium(time, parent)
	case config.IsHomestead(next):
		return calcDifficultyHomestead(time, parent)
	default:
		return calcDifficultyFrontier(time, parent)
	}
}

// Some weird constants to avoid constant memory allocs for them.
var (
	expDiffPeriod = big.NewInt(100000)
	big1          = big.NewInt(1)
	big2          = big.NewInt(2)
	big9          = big.NewInt(9)
	big10         = big.NewInt(10)
	bigMinus99    = big.NewInt(-99)
	big2999999    = big.NewInt(2999999)
)

// calcDifficultyByzantium is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time given the
// parent block's time and difficulty. The calculation uses the Byzantium rules.
func calcDifficultyByzantium(time uint64, parent *types.Header) *big.Int {
	// https://github.com/ethereum/EIPs/issues/100.
	// algorithm:
	// diff = (parent_diff +
	//         (parent_diff / 2048 * max((2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9), -99))
	//        ) + 2^(periodCount - 2)

	bigTime := new(big.Int).SetUint64(time)
	bigParentTime := new(big.Int).Set(parent.Time)

	// holds intermediate values to make the algo easier to read & audit
	x := new(big.Int)
	y := new(big.Int)

	// (2 if len(parent_uncles) else 1) - (block_timestamp - parent_timestamp) // 9
	x.Sub(bigTime, bigParentTime)
	x.Div(x, big9)
	if parent.UncleHash == types.EmptyUncleHash {
		x.Sub(big1, x)
	} else {
		x.Sub(big2, x)
	}
	// max((2 if len(parent_uncles) else 1) - (block_timestamp - parent_timestamp) // 9, -99)
	if x.Cmp(bigMinus99) < 0 {
		x.Set(bigMinus99)
	}
	// parent_diff + (parent_diff / 2048 * max((2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9), -99))
	y.Div(parent.Difficulty, params.DifficultyBoundDivisor)
	x.Mul(y, x)
	x.Add(parent.Difficulty, x)

	// minimum difficulty can ever be (before exponential factor)
	if x.Cmp(params.MinimumDifficulty) < 0 {
		x.Set(params.MinimumDifficulty)
	}
	// calculate a fake block number for the ice-age delay:
	//   https://github.com/ethereum/EIPs/pull/669
	//   fake_block_number = min(0, block.number - 3_000_000
	fakeBlockNumber := new(big.Int)
	if parent.Number.Cmp(big2999999) >= 0 {
		fakeBlockNumber = fakeBlockNumber.Sub(parent.Number, big2999999) // Note, parent is 1 less than the actual block number
	}
	// for the exponential factor
	periodCount := fakeBlockNumber
	periodCount.Div(periodCount, expDiffPeriod)

	// the exponential factor, commonly referred to as "the bomb"
	// diff = diff + 2^(periodCount - 2)
	if periodCount.Cmp(big1) > 0 {
		y.Sub(periodCount, big2)
		y.Exp(big2, y, nil)
		x.Add(x, y)
	}
	return x
}

// calcDifficultyHomestead is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time given the
// parent block's time and difficulty. The calculation uses the Homestead rules.
func calcDifficultyHomestead(time uint64, parent *types.Header) *big.Int {
	// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
	// algorithm:
	// diff = (parent_diff +
	//         (parent_diff / 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99))
	//        ) + 2^(periodCount - 2)

	bigTime := new(big.Int).SetUint64(time)
	bigParentTime := new(big.Int).Set(parent.Time)

	// holds intermediate values to make the algo easier to read & audit
	x := new(big.Int)
	y := new(big.Int)

	// 1 - (block_timestamp - parent_timestamp) // 10
	x.Sub(bigTime, bigParentTime)
	x.Div(x, big10)
	x.Sub(big1, x)

	// max(1 - (block_timestamp - parent_timestamp) // 10, -99)
	if x.Cmp(bigMinus99) < 0 {
		x.Set(bigMinus99)
	}
	// (parent_diff + parent_diff // 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99))
	y.Div(parent.Difficulty, params.DifficultyBoundDivisor)
	x.Mul(y, x)
	x.Add(parent.Difficulty, x)

	// minimum difficulty can ever be (before exponential factor)
	if x.Cmp(params.MinimumDifficulty) < 0 {
		x.Set(params.MinimumDifficulty)
	}
	// for the exponential factor
	periodCount := new(big.Int).Add(parent.Number, big1)
	periodCount.Div(periodCount, expDiffPeriod)

	// the exponential factor, commonly referred to as "the bomb"
	// diff = diff + 2^(periodCount - 2)
	if periodCount.Cmp(big1) > 0 {
		y.Sub(periodCount, big2)
		y.Exp(big2, y, nil)
		x.Add(x, y)
	}
	return x
}

// calcDifficultyFrontier is the difficulty adjustment algorithm. It returns the
// difficulty that a new block should have when created at time given the parent
// block's time and difficulty. The calculation uses the Frontier rules.
func calcDifficultyFrontier(time uint64, parent *types.Header) *big.Int {
	diff := new(big.Int)
	adjust := new(big.Int).Div(parent.Difficulty, params.DifficultyBoundDivisor)
	bigTime := new(big.Int)
	bigParentTime := new(big.Int)

	bigTime.SetUint64(time)
	bigParentTime.Set(parent.Time)

	if bigTime.Sub(bigTime, bigParentTime).Cmp(params.DurationLimit) < 0 {
		diff.Add(parent.Difficulty, adjust)
	} else {
		diff.Sub(parent.Difficulty, adjust)
	}
	if diff.Cmp(params.MinimumDifficulty) < 0 {
		diff.Set(params.MinimumDifficulty)
	}

	periodCount := new(big.Int).Add(parent.Number, big1)
	periodCount.Div(periodCount, expDiffPeriod)
	if periodCount.Cmp(big1) > 0 {
		// diff = diff + 2^(periodCount - 2)
		expDiff := periodCount.Sub(periodCount, big2)
		expDiff.Exp(big2, expDiff, nil)
		diff.Add(diff, expDiff)
		diff = math.BigMax(diff, params.MinimumDifficulty)
	}
	return diff
}

// VerifySeal implements consensus.Engine, checking whether the given block satisfies
// the PoW difficulty requirements.
func (ethash *Ethash) VerifySeal(chain consensus.ChainReader, header *types.Header, ancestors_pos []*types.Header, uncle bool) error {
	// If we're running a fake PoW, accept any seal as valid
	if ethash.config.PowMode == ModeFake || ethash.config.PowMode == ModeFullFake {
		time.Sleep(ethash.fakeDelay)
		if ethash.fakeFail == header.Number.Uint64() {
			return errInvalidPoW
		}
		return nil
	}
	// If we're running a shared PoW, delegate verification to it
	if ethash.shared != nil {
		return ethash.shared.VerifySeal(chain, header, ancestors_pos, uncle)
	}
	// Ensure that we have a valid difficulty for the block
	if header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}
	// Recompute the digest and PoW value and verify against the header
	number := header.Number.Uint64()

	cache := ethash.cache(number)
	size := datasetSize(number)
	if ethash.config.PowMode == ModeTest {
		size = 32 * 1024
	}
	digest, result := hashimotoLight(size, cache.cache, header.HashNoNonce().Bytes(), header.Nonce.Uint64())
	// Caches are unmapped in a finalizer. Ensure that the cache stays live
	// until after the call to hashimotoLight so it's not unmapped while being used.
	runtime.KeepAlive(cache)

	if !bytes.Equal(header.MixDigest[:], digest) {
		return errInvalidMixDigest
	}
	target := new(big.Int).Div(maxUint256, header.Difficulty)

	// UCOT dedicated. UCOT Hybrid pos with pow, Hash(B) <= Age(A)*LOG2(delta_h)*M/D
	delta_h, age := ethash.getCoinAgeAndDeltaH(chain, header, ancestors_pos, uncle)
	var (
		dh_big = new(big.Float).SetFloat64(delta_h)
		age_big = new(big.Float).SetFloat64(age)
		targetPoS = new(big.Float).SetInt(target)
	)
	targetPoS.Mul(targetPoS, dh_big)
	targetPoS.Mul(targetPoS, age_big)
	if new(big.Float).SetInt(new(big.Int).SetBytes(result)).Cmp(targetPoS) > 0 { 
	// if new(big.Int).SetBytes(result).Cmp(target) > 0 {
		log.Error("check pow in verify", "number",header.Number, "coinbase",common.ToHex(header.Coinbase[:8]),"ours", new(big.Float).SetInt(new(big.Int).SetBytes(result)), "header", targetPoS, "D", header.Difficulty, "dh_big", dh_big,"age_big",age_big)
		return errInvalidPoW
	}
	return nil
}

func (ethash *Ethash) getCoinAgeAndDeltaH(chain consensus.ChainReader, header *types.Header, ancestors_pos []*types.Header, uncle bool) (float64, float64) {
	// Calculate delta h
	var delta_h float64
	log.Info("check size of ancestors_pos", "size",len(ancestors_pos))
	recent := chain.GetRecentCoinbase(header, ancestors_pos, uncle)
	Dh := int64(header.Number.Uint64()-recent)
	if recent < maths.MaxUint64 && recent < header.Number.Uint64() {
		// delta_h = maths.Log10(float64(header.Number.Uint64()-recent))
		delta_h = maths.Pow(float64(Dh-128), 3) / 1024000 + 2
		log.Info("check in verify, come here","Dh", Dh, "delta_h", delta_h, "recent", recent, "coinbase", common.ToHex(header.Coinbase[:8]))
		// if header.Number.Uint64()-recent <= core.MiningLogAtDepth {
		// 	//log.Trace("check in verify, come here","delta_h",delta_h,"recent",recent,"coinbase",common.ToHex(header.Coinbase[:8]))
		// 	delta_h = maths.Pow(float64(512+5-128), 3) / 1024000 + 2  
		// }
	} else {
		log.Info("check in verify, or here?","delta_h",delta_h,"recent",recent,"coinbase",common.ToHex(header.Coinbase[:8]))
		// delta_h = maths.Log10(2) 
		delta_h = maths.Pow(float64(512+5-128), 3) / 1024000 + 2 
	}
	log.Info("check delta_h in verify", "delta_h",delta_h, "number",header.Number.Uint64(),"recent",recent, "coinbase",common.ToHex(header.Coinbase[:8]))

	// Calculate CoinAge
	age := chain.GetCoinAge(header)
		log.Trace("check age in verify","age",age,"number",header.Number.Uint64(),"coinbase",common.ToHex(header.Coinbase[:8]))
	return delta_h, age
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the ethash protocol. The changes are done inline.
func (ethash *Ethash) Prepare(chain consensus.ChainReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = ethash.CalcDifficulty(chain, header.Time.Uint64(), parent)
	return nil
}

// Finalize implements consensus.Engine, accumulating the block and uncle rewards,
// setting the final state and assembling the block.
func (ethash *Ethash) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, noValidate bool) (*types.Block, error) {
	// Record the balance in the CoinAge field
	pastCoinAge(chain, header)
	// Accumulate any block and uncle rewards and commit the final state root
	reward_final, err := accumulateRewards(chain, chain.Config(), state, header, uncles, noValidate)
	if err != nil {
		return nil, err
	}
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.CoinMined = reward_final.Bytes()
	// Header seems complete, assemble into a block and return
	block := types.NewBlock(header, txs, uncles, receipts)
	rawdb.WriteTokenBalance(chain.GetChainDb(), block.HashNoNonce(), header.Number.Uint64(), reward_final) // At this point, header has not been completed yet.
	return block, nil
}

// Some weird constants to avoid constant memory allocs for them.
var (
	big8  = big.NewInt(8)
	big32 = big.NewInt(32)
)

// AccumulateRewards credits the coinbase of the given block with the mining
// reward. The total reward consists of the static block reward and rewards for
// included uncles. The coinbase of each uncle block is also rewarded.
func accumulateRewards(chain consensus.ChainReader, config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header, noValidate bool) (*big.Int, error) {
	blockReward := UCTBlockReward
	// Accumulate the rewards for the miner and any included uncles
	reward := new(big.Int).Set(blockReward)
	r := new(big.Int)
	rewardThisRound := new(big.Int)
	uncleReward := make(map[common.Address]*big.Int)
	for _, uncle := range uncles {
		r.Add(uncle.Number, big8)
		r.Sub(r, header.Number)
		r.Mul(r, blockReward)
		r.Div(r, big8)
		uncleReward[uncle.Coinbase] = r
		// state.AddBalance(uncle.Coinbase, r)
		rewardThisRound.Add(rewardThisRound, r)

		r.Div(blockReward, big32)
		reward.Add(reward, r)
	}
	// state.AddBalance(header.Coinbase, reward)
	rewardThisRound.Add(rewardThisRound, reward)
	rewardTotal, err, normal := checkDeadLine(chain, header, rewardThisRound, noValidate)
	if err != nil {
		return big.NewInt(0), err
	} else if !normal && err == nil {
		state.AddBalance(header.Coinbase, rewardTotal)
		return params.ReleaseTotal, nil
	} else {
		for uncle, r := range uncleReward {
			state.AddBalance(uncle, r)
		}
		state.AddBalance(header.Coinbase, reward)
	}
	return rewardTotal, nil
}

func pastCoinAge(chain consensus.ChainReader, header *types.Header) {
	var (
		coinAge = new(big.Int)
		parent *types.Header
		count int
	)
	if header.Number.Uint64() < core.MiningLogAtDepth {
		parent = chain.GetHeaderByNumber(0)
	} else {
		parent = chain.GetHeaderByNumber(header.Number.Uint64()-core.MiningLogAtDepth)
	}
	for ; header.Number.Uint64()-parent.Number.Uint64() < core.CoinAgeWindow+core.MiningLogAtDepth && parent.Number.Uint64() >= 0; parent = chain.GetHeader(parent.ParentHash, parent.Number.Uint64()-1) {
		count += 1
		state, _ := chain.StateAt(parent.Root)
		coinAge.Add(coinAge, chain.GetPastBalance(state, header))
		if parent.Number.Uint64() == 0 {
			break
		}
	}
	log.Trace("check count in pastCoinAge","count",count,"parent_num",header.Number.Uint64())
	header.CoinAge = coinAge.Bytes()
}

func checkDeadLine(chain consensus.ChainReader, header *types.Header, total *big.Int, noValidate bool) (*big.Int, error, bool) {
	if header.Number.Uint64() > 1 {
		var released = new(big.Int)
		if noValidate {
			released.SetBytes(chain.GetHeader(header.ParentHash, header.Number.Uint64()-1).CoinMined)
		} else {
			// We use HashNoNonce because the header has not been completely when Writing.
			released = rawdb.ReadTokenBalance(chain.GetChainDb(), chain.GetHeader(header.ParentHash, header.Number.Uint64()-1).HashNoNonce(), header.Number.Uint64()-1)
			if released == nil {
				log.Error("check header in checkDeadLine", "num",header.Number.Uint64()-1, "hash", chain.GetHeader(header.ParentHash, header.Number.Uint64()-1).HashNoNonce())
				return big.NewInt(0), errors.New("Can't find the total token balance"), false
			}
			if parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1); released.Cmp(new(big.Int).SetBytes(parent.CoinMined)) != 0 {
				log.Error("invalid header coinMined", "header_coinMined", new(big.Int).SetBytes(parent.CoinMined), "released", released)
				return big.NewInt(0), errors.New("Invalid total token balance"), false
			}	
		}

		extern := new(big.Int).Add(released, total)
		if extern.Cmp(params.ReleaseTotal) > 0 {
			return new(big.Int).Sub(params.ReleaseTotal, released), nil, false
		}
		return extern, nil, true
	} else {
		return total, nil, true
	}
}

