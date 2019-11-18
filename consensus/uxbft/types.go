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
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	lru "github.com/hashicorp/golang-lru"
)

// TxPool wraps all methods required to retrieve the txpool. deprecated
type TxPool interface{}
type QuitMiningEvent struct{}
type GetTxPoolEvent struct{ Txpool TxPool } // deprecated

// ConsensusEvents:
type RoundStateEvent struct{}

type PrepareReqEvent struct{}
type GetPrepareReqEvent struct{ PreReq *PrepareRequest }

type PrepareRespEvent struct{}
type GetPrepareRespEvent struct{}

type ChangeViewEvent struct{}
type GetChangeViewEvent struct{}

type AdvertToNewViewEvent struct{}
type GetAdvertToNewViewEvent struct{}

type SendTxReqEvent struct{}
type GetTxReqEvent struct{}
type SendTxRespEvent struct{}
type GetTxRespEvent struct{}

type PrepareRequest struct{}
type ControlPreReq struct{}

type PrepareResponse struct{}
type ControlPreResp struct{}

type TxRequest struct{}
type ControlTxRequest struct{}

type TxResponse struct{}

type ChangeView struct{}
type ControlChangeV struct{}

type NewViewBroadCast struct{}
type ControlNewViewBroadCast struct{}

type VoteEvent struct{}

type consensusChannels struct{}

func newConsensusChannels() *consensusChannels {}

// The sigcache is often the signatures
func NewPrepareReq(header *types.Header, headerSig []byte, round *Round, config *params.DbftConfig, sigcache *lru.ARCCache) (*ControlPreReq, error) {
}
func NewPrepareResp(round *Round, config *params.DbftConfig, sigcache *lru.ARCCache) (*ControlPreResp, error) {
}

func NewChangeView(round *Round) (*ControlChangeV, error)                                {}
func NewBroadcastNewView(round *Round, newView uint64) (*ControlNewViewBroadCast, error) {}

func NewTxRequest(round *Round) (*ControlTxRequest, error)                {}
func NewTxResponse(txs types.Transactions, i uint64) (*TxResponse, error) {}

func signHeader(header *types.Header, prikey *ecdsa.PrivateKey) (sig []byte, err error) {}
func sigchangeV(changeV *ChangeView) (hash common.Hash)                                 {}
func sigBroadcastNewV(NewV *NewViewBroadCast) (hash common.Hash)                        {}
func sigTxReq(txReq *TxRequest) (hash common.Hash)                                      {}

// TODO: These are pretty bad APIs
func (control *ControlPreReq) Get() *PrepareRequest             {}
func (control *ControlPreResp) Get() *PrepareResponse           {}
func (control *ControlChangeV) Get() *ChangeView                {}
func (control *ControlNewViewBroadCast) Get() *NewViewBroadCast {}
func (control *ControlNewViewBroadCast) GetNewV() uint64        {}
func (control *ControlTxRequest) Get() *TxRequest               {}
