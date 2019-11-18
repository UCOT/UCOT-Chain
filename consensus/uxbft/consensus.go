//consensus.go is responsible for the consensus algorithm for dbft.

package dbft

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// Main entry
func (d *Dbft) Consensus(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
}

// Rounds regarding the view number
func (d *Dbft) ConsensusRound(chain consensus.ChainReader, round *Round) {}

func (d *Dbft) voteHandler(chain consensus.ChainReader, round *Round) {}

// Waits block period before sending the request.
// Returns whether it was successful, or it received a quit event.
func (d *Dbft) prepareRequestHandler(chain consensus.ChainReader, round *Round) bool {}

// Handles all the incoming events for the speaker
func (d *Dbft) speakerHandler(chain consensus.ChainReader, round *Round) {}

// Handler all the incoming events for the non-speakers.
func (d *Dbft) delegateHandler(chain consensus.ChainReader, round *Round) {}

// Closes the channels. This will also stop the speaker/delegate handler
func (d *Dbft) closeChannels() {}

// TODO: Move these to another file
func (d *Dbft) sendTxRequest(round *Round) {}

func (d *Dbft) broadcastChangeView(round *Round) *ControlChangeV {}
func (d *Dbft) broadcastNewView(round *Round, newView uint64)    {}

// Sums up how many nodes are going for each view, and returns the view number
// if there are enough nodes going for it. Returns 0 if not enough nodes going
// for any view.
func (d *Dbft) checkChangeView(round *Round, changeViews map[common.Address]*ControlChangeV) uint64 {}

// Calculates the time needed before changing view
func (d *Dbft) changeViewTime(view uint64) float64 {}

// Calculates the minimum required nodes to have 2/3 consensus.
// This is 3 when numMiners is 4
func (d *Dbft) RequiredNodes(numMiners uint64) int {
}

// Post the round state to the protocol manager.
func (d *Dbft) postRoundState(round *Round, isMining bool) {
}

// Verify the AdvertChangeView
func (d *Dbft) verifyBroadcastChangeView(chain consensus.ChainReader, round *Round, changeNewView *NewViewBroadCast) error {
}

// Sanity check for incoming messages.
// TODO: Many are the same, see if we can ignore them.
func (d *Dbft) verify(msg interface{}, round *Round) error {
}

// TODO, this might need to be depreciated
func (d *Dbft) validateTx(txs []*types.Transaction) (common.Hash, error) {
}

// Rather we need to invoke validateContent for state validation
func (d *Dbft) validateContent(chain consensus.ChainReader, block *types.Block, speaker common.Address) (common.Hash, error) {
}
