// Copyright 2015 The go-ethereum Authors
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

package eth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/dbft"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/fetcher"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	// txChanSize is the size of channel listening to TxPreEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096000
)

var (
	daoChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

// errIncompatibleConfig is returned if the requested protocols and configs are
// not compatible (low protocol version restrictions and high requirements).
var errIncompatibleConfig = errors.New("incompatible configuration")

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type ProtocolManager struct {
	networkId      	uint64
	addr           	common.Address
	nodeID         	string

	fastSync       	uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	acceptTxs      	uint32 // Flag whether we're considered synchronised (enables transaction processing)

	inRound 		bool
	view 	  	   	uint64
	pIndex 			uint64
	iIndex 			uint64

	// txpool      txPool
	txpool         	*core.TxPool
	blockchain     	*core.BlockChain
	chainconfig    	*params.ChainConfig
	maxPeers       	int

	downloader     	*downloader.Downloader
	fetcher        	*fetcher.Fetcher
	peers          	*peerSet

	SubProtocols []p2p.Protocol

	eventMux        *event.TypeMux
	txCh            chan core.TxPreEvent
	txSub           event.Subscription
	minedBlockSub   *event.TypeMuxSubscription

	// dbft
	dbftSub     	*event.TypeMuxSubscription
	addrToNodeID    map[common.Address]string
	peerID    		[]interface{} // Slice of all NodeIDs of peers.

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   	chan *peer
	txsyncCh    	chan *txsync
	quitSync    	chan struct{}
	noMorePeers 	chan struct{}

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup
}

// NewProtocolManager returns a new ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the ethereum network.
func NewProtocolManager(config *params.ChainConfig, mode downloader.SyncMode, networkId uint64, mux *event.TypeMux, txpool *core.TxPool, engine consensus.Engine, blockchain *core.BlockChain, chaindb ethdb.Database, ctx *node.ServiceContext) (*ProtocolManager, error) {
	//Get Address and NodeID
	miners := blockchain.GetLastVote()

	addressToNodeID := ctx.GetConfig().P2P.AddressNodeMapping
	_, _, localAddr, err := dbft.GetNodeConfig(ctx)
	if err != nil {
		return nil, err
	}

	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		networkId:       networkId,
		addr: 			 localAddr,
		nodeID: 		 dbft.HexToID(false, dbft.GetNodeID(ctx)).(string),
		eventMux:        mux,
		txpool:          txpool,
		blockchain:      blockchain,
		chainconfig:     config,
		peers:           newPeerSet(),
		newPeerCh:       make(chan *peer),
		noMorePeers:     make(chan struct{}),
		txsyncCh:        make(chan *txsync),
		quitSync:        make(chan struct{}),
		addrToNodeID: 	 addressToNodeID,
		peerID:    		 dbft.AddrListToNodeList(addressToNodeID, miners),
	}
	// Dbft only allows FullSync due to the process of consensus protocol
	if _, ok := engine.(*dbft.Dbft); ok {
		log.Trace("DBFT only allows FullSync for validation nodes")
		mode = downloader.FullSync
	}
	// Figure out whether to allow fast sync or not
	if mode == downloader.FastSync && blockchain.CurrentBlock().NumberU64() > 0 {
		log.Warn("Blockchain not empty, fast sync disabled")
		mode = downloader.FullSync
	}
	if mode == downloader.FastSync {
		manager.fastSync = uint32(1)
	}
	// Initiate a sub-protocol for every implemented version we can handle
	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		// Skip protocol version if incompatible with the mode of operation
		if mode == downloader.FastSync && version < eth63 {
			continue
		}
		// Compatible; initialise the sub-protocol
		version := version // Closure for the run
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				peer := manager.newPeer(int(version), p, rw)
				// log.Trace("Showing the eth/peers")
				// fmt.Println(peer.String())
				select {
				case manager.newPeerCh <- peer:
					manager.wg.Add(1)
					defer manager.wg.Done()
					return manager.handle(peer)
				case <-manager.quitSync:
					return p2p.DiscQuitting
				}
			},
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}
	if len(manager.SubProtocols) == 0 {
		return nil, errIncompatibleConfig
	}
	// Construct the different synchronisation mechanisms
	manager.downloader = downloader.New(mode, chaindb, manager.eventMux, blockchain, nil, manager.removePeer)

	validator := func(header *types.Header) error {
		return engine.VerifyHeader(blockchain, header, true)
	}
	heighter := func() uint64 {
		return blockchain.CurrentBlock().NumberU64()
	}
	inserter := func(blocks types.Blocks) (int, error) {
		// If fast sync is running, deny importing weird blocks
		if atomic.LoadUint32(&manager.fastSync) == 1 {
			log.Warn("Discarded bad propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash())
			return 0, nil
		}
		atomic.StoreUint32(&manager.acceptTxs, 1) // Mark initial sync done on any fetcher import
		return manager.blockchain.InsertChain(blocks)
	}
	manager.fetcher = fetcher.New(blockchain.GetBlockByHash, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer)

	return manager, nil
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	log.Debug("Removing Ethereum peer", "peer", id)

	// Unregister the peer from the downloader and Ethereum peer set
	pm.downloader.UnregisterPeer(id)
	if err := pm.peers.Unregister(id); err != nil {
		log.Error("Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers

	// broadcast transactions
	pm.txCh = make(chan core.TxPreEvent, txChanSize)
	pm.txSub = pm.txpool.SubscribeTxPreEvent(pm.txCh) 

	if !pm.isMiner() {
		log.Trace("Start txBroadcastLoop")
		go pm.txBroadcastLoop()
	} else {
		log.Warn("Local is a miner. txBroadcastLoop disabled.", "nodeID", pm.nodeID)
	}

	// broadcast mined blocks
	pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})
	go pm.minedBroadcastLoop()

	// dbft consensus
	pm.dbftSub = pm.eventMux.Subscribe(
		dbft.RoundStateEvent{},
		dbft.PrepareReqEvent{},
		dbft.PrepareRespEvent{},
		dbft.ChangeViewEvent{},
		dbft.AdvertToNewViewEvent{},
		dbft.SendTxReqEvent{},
		dbft.SendTxRespEvent{},
	)
	go pm.dbftLoop()

	// start sync handlers
	go pm.syncer()
	go pm.txsyncLoop()
}

func (pm *ProtocolManager) Stop() {
	log.Info("Stopping Ethereum protocol")

	pm.txSub.Unsubscribe()         // quits txBroadcastLoop
	pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop
	pm.dbftSub.Unsubscribe()       // quits dbftLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	log.Info("Ethereum protocol stopped")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer) error {
	if pm.peers.Len() >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
		return p2p.DiscTooManyPeers
	}
	p.Log().Debug("Ethereum peer connected", "name", p.Name())

	// Execute the Ethereum handshake
	var (
		genesis = pm.blockchain.Genesis()
		head    = pm.blockchain.CurrentHeader()
		hash    = head.Hash()
		number  = head.Number.Uint64()
		td      = pm.blockchain.GetTd(hash, number)
	)
	if err := p.Handshake(pm.networkId, td, hash, genesis.Hash()); err != nil {
		p.Log().Debug("Ethereum handshake failed", "err", err)
		return err
	}
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	// Register the peer locally
	if err := pm.peers.Register(p); err != nil {
		p.Log().Error("Ethereum peer registration failed", "err", err)
		return err
	}
	defer pm.removePeer(p.id)

	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := pm.downloader.RegisterPeer(p.id, p.version, p); err != nil {
		return err
	}
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	pm.syncTransactions(p)

	// If we're DAO hard-fork aware, validate any remote peer with regard to the hard-fork
	if daoBlock := pm.chainconfig.DAOForkBlock; daoBlock != nil {
		// Request the peer's DAO fork header for extra-data validation
		if err := p.RequestHeadersByNumber(daoBlock.Uint64(), 1, 0, false); err != nil {
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		p.forkDrop = time.AfterFunc(daoChallengeTimeout, func() {
			p.Log().Debug("Timed out DAO fork-check, dropping")
			pm.removePeer(p.id)
		})
		// Make sure it's cleaned up if the peer dies off
		defer func() {
			if p.forkDrop != nil {
				p.forkDrop.Stop()
				p.forkDrop = nil
			}
		}()
	}
	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil {
			p.Log().Debug("Ethereum message handling failed", "err", err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	defer msg.Discard()

	// Handle the message depending on its contents
	switch {
	case msg.Code == StatusMsg:
		// Status messages should never arrive after the handshake
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")

	// Block header query, collect the requested headers and reply
	case msg.Code == GetBlockHeadersMsg:
		// Decode the complex header query
		var query getBlockHeadersData
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		hashMode := query.Origin.Hash != (common.Hash{})

		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Header
			unknown bool
		)
		for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit && len(headers) < downloader.MaxHeaderFetch {
			// Retrieve the next header satisfying the query
			var origin *types.Header
			if hashMode {
				origin = pm.blockchain.GetHeaderByHash(query.Origin.Hash)
			} else {
				origin = pm.blockchain.GetHeaderByNumber(query.Origin.Number)
			}
			if origin == nil {
				break
			}
			number := origin.Number.Uint64()
			headers = append(headers, origin)
			bytes += estHeaderRlpSize

			// Advance to the next header of the query
			switch {
			case query.Origin.Hash != (common.Hash{}) && query.Reverse:
				// Hash based traversal towards the genesis block
				for i := 0; i < int(query.Skip)+1; i++ {
					if header := pm.blockchain.GetHeader(query.Origin.Hash, number); header != nil {
						query.Origin.Hash = header.ParentHash
						number--
					} else {
						unknown = true
						break
					}
				}
			case query.Origin.Hash != (common.Hash{}) && !query.Reverse:
				// Hash based traversal towards the leaf block
				var (
					current = origin.Number.Uint64()
					next    = current + query.Skip + 1
				)
				if next <= current {
					infos, _ := json.MarshalIndent(p.Peer.Info(), "", "  ")
					p.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
					unknown = true
				} else {
					if header := pm.blockchain.GetHeaderByNumber(next); header != nil {
						if pm.blockchain.GetBlockHashesFromHash(header.Hash(), query.Skip+1)[query.Skip] == query.Origin.Hash {
							query.Origin.Hash = header.Hash()
						} else {
							unknown = true
						}
					} else {
						unknown = true
					}
				}
			case query.Reverse:
				// Number based traversal towards the genesis block
				if query.Origin.Number >= query.Skip+1 {
					query.Origin.Number -= query.Skip + 1
				} else {
					unknown = true
				}

			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += query.Skip + 1
			}
		}
		return p.SendBlockHeaders(headers)

	case msg.Code == BlockHeadersMsg:
		// A batch of headers arrived to one of our previous requests
		var headers []*types.Header
		if err := msg.Decode(&headers); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// If no headers were received, but we're expending a DAO fork check, maybe it's that
		if len(headers) == 0 && p.forkDrop != nil {
			// Possibly an empty reply to the fork header checks, sanity check TDs
			verifyDAO := true

			// If we already have a DAO header, we can check the peer's TD against it. If
			// the peer's ahead of this, it too must have a reply to the DAO check
			if daoHeader := pm.blockchain.GetHeaderByNumber(pm.chainconfig.DAOForkBlock.Uint64()); daoHeader != nil {
				if _, td := p.Head(); td.Cmp(pm.blockchain.GetTd(daoHeader.Hash(), daoHeader.Number.Uint64())) >= 0 {
					verifyDAO = false
				}
			}
			// If we're seemingly on the same chain, disable the drop timer
			if verifyDAO {
				p.Log().Debug("Seems to be on the same side of the DAO fork")
				p.forkDrop.Stop()
				p.forkDrop = nil
				return nil
			}
		}
		// Filter out any explicitly requested headers, deliver the rest to the downloader
		filter := len(headers) == 1
		if filter {
			// If it's a potential DAO fork check, validate against the rules
			if p.forkDrop != nil && pm.chainconfig.DAOForkBlock.Cmp(headers[0].Number) == 0 {
				// Disable the fork drop timer
				p.forkDrop.Stop()
				p.forkDrop = nil

				// Validate the header and either drop the peer or continue
				if err := misc.VerifyDAOHeaderExtraData(pm.chainconfig, headers[0]); err != nil {
					p.Log().Debug("Verified to be on the other side of the DAO fork, dropping")
					return err
				}
				p.Log().Debug("Verified to be on the same side of the DAO fork")
				return nil
			}
			// Irrelevant of the fork checks, send the header to the fetcher just in case
			headers = pm.fetcher.FilterHeaders(p.id, headers, time.Now())
		}
		if len(headers) > 0 || !filter {
			err := pm.downloader.DeliverHeaders(p.id, headers)
			if err != nil {
				log.Debug("Failed to deliver headers", "err", err)
			}
		}

	case msg.Code == GetBlockBodiesMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			hash   common.Hash
			bytes  int
			bodies []rlp.RawValue
		)
		for bytes < softResponseLimit && len(bodies) < downloader.MaxBlockFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block body, stopping if enough was found
			if data := pm.blockchain.GetBodyRLP(hash); len(data) != 0 {
				bodies = append(bodies, data)
				bytes += len(data)
			}
		}
		return p.SendBlockBodiesRLP(bodies)

	case msg.Code == BlockBodiesMsg:
		// A batch of block bodies arrived to one of our previous requests
		var request blockBodiesData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver them all to the downloader for queuing
		trasactions := make([][]*types.Transaction, len(request))
		uncles := make([][]*types.Header, len(request))
		groupSig := make([][]*types.GroupSignature, len(request))

		for i, body := range request {
			trasactions[i] = body.Transactions
			uncles[i] = body.Uncles
			groupSig[i] = body.GroupSignatures
		}

		if len(groupSig) == 0 && len(request) != 0 {
			log.Error("Failed to fetch groupSigs")
			break
		}
		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		//filter := len(trasactions) > 0 || len(uncles) > 0 || len(groupSig) > 0
		filter := len(trasactions) > 0 || len(uncles) > 0
		if filter {
			trasactions, uncles, groupSig = pm.fetcher.FilterBodies(p.id, trasactions, uncles, groupSig, time.Now())
		}
		//if len(trasactions) > 0 || len(uncles) > 0 || len(groupSig) > 0 || !filter {
		if len(trasactions) > 0 || len(uncles) > 0 || !filter {
			err := pm.downloader.DeliverBodies(p.id, trasactions, uncles, groupSig)
			if err != nil {
				log.Debug("Failed to deliver bodies", "err", err)
			}
		}

	case p.version >= eth63 && msg.Code == GetNodeDataMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash  common.Hash
			bytes int
			data  [][]byte
		)
		for bytes < softResponseLimit && len(data) < downloader.MaxStateFetch {
			// Retrieve the hash of the next state entry
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested state entry, stopping if enough was found
			if entry, err := pm.blockchain.TrieNode(hash); err == nil {
				data = append(data, entry)
				bytes += len(entry)
			}
		}
		return p.SendNodeData(data)

	case p.version >= eth63 && msg.Code == NodeDataMsg:
		// A batch of node state data arrived to one of our previous requests
		var data [][]byte
		if err := msg.Decode(&data); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverNodeData(p.id, data); err != nil {
			log.Debug("Failed to deliver node state data", "err", err)
		}

	case p.version >= eth63 && msg.Code == GetReceiptsMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash     common.Hash
			bytes    int
			receipts []rlp.RawValue
		)
		for bytes < softResponseLimit && len(receipts) < downloader.MaxReceiptFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block's receipts, skipping if unknown to us
			results := pm.blockchain.GetReceiptsByHash(hash)
			if results == nil {
				if header := pm.blockchain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
					continue
				}
			}
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(results); err != nil {
				log.Error("Failed to encode receipt", "err", err)
			} else {
				receipts = append(receipts, encoded)
				bytes += len(encoded)
			}
		}
		return p.SendReceiptsRLP(receipts)

	case p.version >= eth63 && msg.Code == ReceiptsMsg:
		// A batch of receipts arrived to one of our previous requests
		var receipts [][]*types.Receipt
		if err := msg.Decode(&receipts); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverReceipts(p.id, receipts); err != nil {
			log.Debug("Failed to deliver receipts", "err", err)
		}

	case msg.Code == NewBlockHashesMsg:
		var announces newBlockHashesData
		if err := msg.Decode(&announces); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		// Mark the hashes as present at the remote node
		for _, block := range announces {
			p.MarkBlock(block.Hash)
		}
		// Schedule all the unknown hashes for retrieval
		unknown := make(newBlockHashesData, 0, len(announces))
		for _, block := range announces {
			if !pm.blockchain.HasBlock(block.Hash, block.Number) {
				unknown = append(unknown, block)
			}
		}
		for _, block := range unknown {
			pm.fetcher.Notify(p.id, block.Hash, block.Number, time.Now(), p.RequestOneHeader, p.RequestBodies)
		}

	case msg.Code == NewBlockMsg:
		// Retrieve and decode the propagated block
		var request newBlockData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		request.Block.ReceivedAt = msg.ReceivedAt
		request.Block.ReceivedFrom = p

		if request.Block.GroupSignatures() == nil { //***
			log.Trace("This propagation does not contain any groupSignature.")
			break
		}

		// Mark the peer as owning the block and schedule it for import
		p.MarkBlock(request.Block.Hash())
		pm.fetcher.Enqueue(p.id, request.Block)

		// Assuming the block is importable by the peer, but possibly not yet done so,
		// calculate the head hash and TD that the peer truly must have.
		var (
			trueHead = request.Block.ParentHash()
			trueTD   = new(big.Int).Sub(request.TD, request.Block.Difficulty())
		)
		// Update the peers total difficulty if better than the previous
		if _, td := p.Head(); trueTD.Cmp(td) > 0 {
			p.SetHead(trueHead, trueTD)

			// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
			// a singe block (as the true TD is below the propagated block), however this
			// scenario should easily be covered by the fetcher.
			currentBlock := pm.blockchain.CurrentBlock()
			if trueTD.Cmp(pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64())) > 0 {
				go pm.synchronise(p)
			}
		}

	case msg.Code == TxMsg:
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if atomic.LoadUint32(&pm.acceptTxs) == 0 {
			break
		}
		// Transactions can be processed, parse all of them and deliver to the pool
		var txs []*types.Transaction
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		for i, tx := range txs {
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			p.MarkTransaction(tx.Hash())
		}
		pm.txpool.AddRemotes(txs)

	// dbft messages
	case msg.Code == PrepareRequestMsg:
		log.Trace("A prepareRequestMsg has been received.")
		if pm.isSpeaker() {
			log.Trace("Local is the speaker this round. Drop this msg.")
			break
		}
		var preReq *dbft.PrepareRequest
		if err := msg.Decode(&preReq); err != nil {
			return errResp(ErrSpeaker, "msg %v: %v", msg, err)
		}
		go pm.eventMux.Post(dbft.GetPrepareReqEvent{preReq})

	case msg.Code == PrepareResponseMsg:
		log.Trace("A prepareResponseMsg has been received.")
		if pm.isSpeaker() {
			log.Trace("Local is the speaker this round. Drop this msg.")
			break
		} else {
			var preResp *dbft.PrepareResponse
			if err := msg.Decode(&preResp); err != nil {
				return errResp(ErrPreResp, "msg %v: %v", msg, err)
			}

			go pm.eventMux.Post(dbft.GetPrepareRespEvent{preResp})
		}

	case msg.Code == ChangeViewMsg:
		log.Trace("A ChangeViewMsg has been received.")
		var changeV *dbft.ControlChangeV
		if err := msg.Decode(&changeV); err != nil {
			return errResp(ErrChangeV, "msg %v: %v", msg, err)
		}
		log.Trace("Check status", "height", changeV.Get().Height, "view", changeV.Get().View, "i", changeV.Get().IIndex, "newView", changeV.Get().ViewNew)
		go pm.eventMux.Post(dbft.GetChangeViewEvent{changeV})

	case msg.Code == BroadcastNewViewMsg:
		log.Trace("A BroadcastNewViewMsg has been received.")
		var newV *dbft.ControlNewViewBroadCast
		if err := msg.Decode(&newV); err != nil {
			return errResp(ErrNewV, "msg %v: %v", msg, err)
		}
		go pm.eventMux.Post(dbft.GetAdvertToNewViewEvent{newV})

	case msg.Code == TxRequestMsg:
		log.Trace("A TxRequestMsg has been received.")
		if !pm.isSpeaker() {
			var txReq *dbft.ControlTxRequest
			if err := msg.Decode(&txReq); err != nil {
				return errResp(ErrTxReq, "msg %v: %v", msg, err)
			}
			log.Trace("Rejected txreq", "height", txReq.TxReq.Height, "i", txReq.TxReq.IIndex, "p", txReq.TxReq.PIndex, "v", txReq.TxReq.VIndex )
			log.Trace("Local is not the speaker this round. Drop this msg.")
			break
		} else {
			var txReq *dbft.ControlTxRequest
			if err := msg.Decode(&txReq); err != nil {
				return errResp(ErrTxReq, "msg %v: %v", msg, err)
			}
			go pm.eventMux.Post(dbft.GetTxReqEvent{txReq})
		}

	case msg.Code == TxResponseMsg:
		log.Trace("A TxReponseMsg has been received.")
		var txResp *dbft.TxResponse
		if err := msg.Decode(&txResp); err != nil {
			return errResp(ErrTxResp, "msg %v: %v", msg, err)
		}
		go pm.eventMux.Post(dbft.GetTxRespEvent{txResp})

	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	calcElapsed := func(start mclock.AbsTime) time.Duration {
		now := mclock.Now()
		elapsed := time.Duration(now) - time.Duration(start)
		return elapsed
	}

	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := pm.blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), pm.blockchain.GetTd(block.ParentHash(), block.NumberU64()-1))
		} else {
			log.Error("Propagating dangling block", "number", block.Number(), "hash", hash)
			return
		}
		
		// Priority Broadcasting. Prioritise the speaker and the one before.
		if !pm.isSpeaker() && pm.isMiner() {

			var (
				firstSpeakerID  interface{} //Current speaker
				secondSpeakerID interface{} //The next speaker if change view were to occur
			)
		
			firstSpeakerID = pm.peerID[pm.pIndex];

			log.Trace("Broadcasting block to speaker", "ID", firstSpeakerID.(string))
			firstPeer := pm.peers.Peer(firstSpeakerID.(string))
			if firstPeer != nil {
				startElapased := mclock.Now()
				firstPeer.SendNewBlock(block, td)
				elapsed := calcElapsed(startElapased)
				log.Trace("First broadcast succeeded", "elapsed", common.PrettyDuration(elapsed))
			}

			prevPIndex := (pm.pIndex + uint64(len(pm.peerID)) - 1) % uint64(len(pm.peerID))
			secondSpeakerID = pm.peerID[prevPIndex]

			log.Trace("Broadcasting block to previous speaker", "ID", secondSpeakerID.(string))
			secondPeer := pm.peers.Peer(secondSpeakerID.(string))
			if secondSpeakerID.(string) == pm.nodeID {
				log.Trace("Local node, do not broadcast")
			} else if secondPeer != nil {
				startElapased := mclock.Now()
				secondPeer.SendNewBlock(block, td)
				elapsed := calcElapsed(startElapased)
				log.Trace("Second transferring succeeded", "elapsed", common.PrettyDuration(elapsed))
			}
			log.Trace("Finished priority sending")

			// Remove first and second speaker from peers
			for k, v := range peers {
				if v.id == firstSpeakerID.(string) {
					peers = append(peers[:k], peers[k+1:]...)
					break
				}
			}
			for k, v := range peers {
				if v.id == secondSpeakerID.(string) {
					peers = append(peers[:k], peers[k+1:]...)
					break
				}
			}
		}

		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		startElapased := mclock.Now()
		for _, peer := range transfer {
			peer.SendNewBlock(block, td)
		}
		elapsed := calcElapsed(startElapased)
		log.Info("All broadcasting to nodes finished", "elapsed", common.PrettyDuration(elapsed))
		log.Trace("Propagated block", "hash", hash, "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// Otherwise if the block is indeed in our own chain, announce it
	if pm.blockchain.HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			peer.SendNewBlockHashes([]common.Hash{hash}, []uint64{block.NumberU64()})
		}
		log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}

// BroadcastTx will propagate a transaction to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTx(hash common.Hash, tx *types.Transaction) {
	// Broadcast transaction to a batch of peers not knowing about it
	peers := pm.peers.PeersWithoutTx(hash)
	//FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]

	for _, peer := range peers {
		peer.SendTransactions(types.Transactions{tx})
	}
	log.Trace("Broadcast transaction", "hash", hash, "recipients", len(peers))
}

func (pm *ProtocolManager) BroadcastPreReq(preReq *dbft.PrepareRequest) {
	if !pm.inRound {
		log.Trace("Mining disabled. Don't broadcast")
		return
	}

	targetPeerID := make([]interface{}, len(pm.peerID))
	copy(targetPeerID, pm.peerID)
	for k, v := range targetPeerID {
		if v == pm.nodeID {
			targetPeerID = append(targetPeerID[:k], targetPeerID[k+1:]...)
		}
	}
	peers := make([]*peer, 0, len(targetPeerID))
	var peerCount int
	for _, v := range targetPeerID {
		peers = append(peers, pm.peers.Peer(v.(string)))
	}
	for _, peer := range peers {
		if peer != nil {
			peer.SendPrepareReq(preReq)
			peerCount += 1
		}
	}

	log.Trace("Broadcast PrepareRequest", "hash", preReq.Header.Hash(), "recipients", peerCount)
}

func (pm *ProtocolManager) BroadcastPreResp(preResp *dbft.PrepareResponse) {
	if !pm.inRound {
		log.Trace("Mining disabled. Don't broadcast")
		return
	}

	targetPeerID := make([]interface{}, len(pm.peerID))
	copy(targetPeerID, pm.peerID)
	for k, v := range targetPeerID {
		if v == pm.nodeID {
			targetPeerID = append(targetPeerID[:k], targetPeerID[k+1:]...)
		}
	}
	peers := make([]*peer, 0, len(targetPeerID))
	var peerCount int
	for _, v := range targetPeerID {
		peers = append(peers, pm.peers.Peer(v.(string)))
	}
	for _, peer := range peers {
		if peer != nil {
			peer.SendPrepareResp(preResp)
			peerCount += 1
		}
	}
	log.Trace("Broadcast PrepareResponse", "recipients", peerCount)
}

func (pm *ProtocolManager) BroadcastChangeV(changeV *dbft.ControlChangeV) {
	if !pm.inRound {
		log.Trace("Mining disabled. Don't broadcast")
		return
	}

	targetPeerID := make([]interface{}, len(pm.peerID))
	copy(targetPeerID, pm.peerID)
	for k, v := range targetPeerID {
		if v == pm.nodeID {
			targetPeerID = append(targetPeerID[:k], targetPeerID[k+1:]...)
		}
	}
	peers := make([]*peer, 0, len(targetPeerID))
	var peerCount int
	for _, v := range targetPeerID {
		peers = append(peers, pm.peers.Peer(v.(string)))
	}
	for _, peer := range peers {
		if peer != nil {
			peer.SendChangeView(changeV)
			peerCount += 1
		}
	}
	log.Trace("Broadcast ChangeView", "newView", changeV.Get().ViewNew, "recipients", peerCount)
}

func (pm *ProtocolManager) SendTxRequest(txReq *dbft.ControlTxRequest) {
	if !pm.inRound {
		log.Trace("Mining disabled. Don't broadcast")
		return
	}

	speakerID := pm.peerID[txReq.Get().PIndex]
	peer := pm.peers.Peer(speakerID.(string))
	if peer != nil {
		peer.SendTxRequest(txReq)
	}

	// log.Trace("peerID", "0", pm.peerID[0].(string), "1", pm.peerID[1].(string), "2", pm.peerID[2].(string), "3", pm.peerID[3].(string))
	log.Trace("Send SendTxRequest", "Height", txReq.Get().Height, "p", txReq.Get().PIndex, "i", txReq.Get().IIndex, "v", txReq.Get().VIndex)
}

func (pm *ProtocolManager) SendTxResponse(txResp *dbft.TxResponse) {
	if !pm.inRound {
		log.Trace("Mining disabled. Don't broadcast")
		return
	}

	peerID := pm.peerID[txResp.IIndex]
	peer := pm.peers.Peer(peerID.(string))
	if peer != nil {
		peer.SendTxResponse(txResp)
	}

	log.Trace("Send SendTxResponse", "i", txResp.IIndex, "count", len(txResp.Txs))
}

func (pm *ProtocolManager) BroadcastNewV(newV *dbft.ControlNewViewBroadCast) {
	if !pm.inRound {
		log.Trace("Mining disabled. Don't broadcast")
	}

	targetPeerID := make([]interface{}, len(pm.peerID))
	copy(targetPeerID, pm.peerID)
	for k, v := range targetPeerID {
		if v == pm.nodeID {
			targetPeerID = append(targetPeerID[:k], targetPeerID[k+1:]...)
		}
	}
	peers := make([]*peer, 0, len(targetPeerID))
	var peerCount int
	for _, v := range targetPeerID {
		peers = append(peers, pm.peers.Peer(v.(string)))
	}
	for _, peer := range peers {
		if peer != nil {
			if err := peer.SendNewV(newV); err != nil {
				log.Error("SendNewV fails", "err", err)
				break
			}
			peerCount += 1
		}
	}
	log.Trace("Broadcast NewV", "newView", newV.GetNewV(), "recipients", peerCount)
}

// Mined broadcast loop
func (pm *ProtocolManager) minedBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range pm.minedBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case core.NewMinedBlockEvent:
			pm.BroadcastBlock(ev.Block, true)  // First propagate block to peers
			pm.BroadcastBlock(ev.Block, false) // Only then announce to the rest
		}
	}
}

func (pm *ProtocolManager) txBroadcastLoop() {
	for {
		select {
		case event := <-pm.txCh:
			pm.BroadcastTx(event.Tx.Hash(), event.Tx)

		// Err() channel will be closed when unsubscribing.
		case <-pm.txSub.Err():
			return
		}
	}
}

func (pm *ProtocolManager) dbftLoop() {
	// Consensus Engine fetch txpool first
	go pm.eventMux.Post(dbft.GetTxPoolEvent{pm.getTxPool()})
	// automatically stops if unsubscribe
	for obj := range pm.dbftSub.Chan() {
		switch event := obj.Data.(type) {
		case dbft.RoundStateEvent:
			log.Trace("A RoundStateEvent has been received in local dbftLoop.")
			pm.inRound = event.InRound
			pm.view = event.View
			pm.pIndex = event.PIndex
			pm.iIndex = event.IIndex
			miners := pm.blockchain.GetLastVote()
			pm.peerID = dbft.AddrListToNodeList(pm.addrToNodeID, miners)
			// log.Trace("peerID", "0", pm.peerID[0].(string), "1", pm.peerID[1].(string), "2", pm.peerID[2].(string), "3", pm.peerID[3].(string))
		case dbft.PrepareReqEvent:
			log.Trace("A prepareReqEvent has been received in local dbftLoop to be sent out.")
			pm.BroadcastPreReq(event.PreReq)
		case dbft.PrepareRespEvent:
			log.Trace("A prepareRespEvent has been received in local dbftLoop to be sent out.")
			pm.BroadcastPreResp(event.PreResp)
		case dbft.ChangeViewEvent:
			log.Trace("A changeViewEvent has been received in local dbftLoop to be sent out.")
			pm.BroadcastChangeV(event.ChangeV)
		case dbft.AdvertToNewViewEvent:
			log.Trace("A AdvertToNewViewEvent has been received in local dbftLoop to be sent out.")
			pm.BroadcastNewV(event.ViewNew)
		case dbft.SendTxReqEvent:
			log.Trace("A SendTxReqEvent has been received in local dbftLoop to be sent out.")
			pm.SendTxRequest(event.TxReq)
		case dbft.SendTxRespEvent:
			log.Trace("A SendTxRespEvent has been received in local dbftLoop to be sent out.")
			pm.SendTxResponse(event.TxResp)
		}
	}
}

func (pm *ProtocolManager) getTxPool() *core.TxPool {
	return pm.txpool
}

func (pm *ProtocolManager) txFromMiners(tx *types.Transaction, addrlist map[common.Address]uint64, signer types.Signer) bool {
	checkExist := func(addr common.Address, list map[common.Address]uint64) bool {
		_, exist := list[addr]
		return exist
	}
	if addr, err := types.Sender(signer, tx); err == nil {
		return checkExist(addr, addrlist)
	}
	return false
}

// NodeInfo represents a short summary of the Ethereum sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Network    uint64              `json:"network"`    // Ethereum network ID (1=Frontier, 2=Morden, Ropsten=3, Rinkeby=4)
	Difficulty *big.Int            `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis    common.Hash         `json:"genesis"`    // SHA3 hash of the host's genesis block
	Config     *params.ChainConfig `json:"config"`     // Chain configuration for the fork rules
	Head       common.Hash         `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (pm *ProtocolManager) NodeInfo() *NodeInfo {
	currentBlock := pm.blockchain.CurrentBlock()
	return &NodeInfo{
		Network:    pm.networkId,
		Difficulty: pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64()),
		Genesis:    pm.blockchain.Genesis().Hash(),
		Config:     pm.blockchain.Config(),
		Head:       currentBlock.Hash(),
	}
}


func (pm *ProtocolManager) isMiner() bool {
	for _, peerID := range pm.peerID {
		if pm.nodeID == peerID {
			return true;
		}
	}
	return false;
}

func (pm *ProtocolManager) isSpeaker() bool {
	return pm.pIndex == pm.iIndex
}

func (pm *ProtocolManager) priorPIndex() uint64 {
	pIndex := pm.pIndex
	miners := pm.blockchain.GetLastVote()
	pIndex += uint64(len(miners)) - 1
	pIndex %= uint64(len(miners))
	return pIndex
}







