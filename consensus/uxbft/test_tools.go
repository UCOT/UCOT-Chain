//malicious_test.go holds functions related to bft test.

package dbft

import (
	"bytes"
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

const (
	PIndexTampered = iota
	MaliciousAdvertNewView
	MaliciousVoting
)

var byzTestModeNumber = 0

func (d *Dbft) setByzantine(byzantine bool) {
	log.Trace("Set local Byzantine test", "byzantine", byzantine)
	d.isByzantine = byzantine
}

func (d *Dbft) getByzantine() bool {
	byzantine := d.isByzantine
	log.Trace("Get local Byzantine test", "byzantine", byzantine)
	return byzantine
}

func (d *Dbft) attackTest(round *Round) {
	if d.getByzantine() {
		switch {
		case byzTestModeNumber == PIndexTampered:
			log.Warn("PIndex attack starts")
			if round.pIndex == 0 {
				round.pIndex += 1
			} else {
				round.pIndex -= 1
			}

		case byzTestModeNumber == MaliciousAdvertNewView:
			log.Warn("MaliciousAdvertNewView attack starts")
			controlV := &ControlChangeV{
				ChangeV: &ChangeView{
					Height:  0,
					View:    0,
					IIndex:  0,
					ViewNew: 0,
				},
				SignedChangeV: make([]byte, 65),
			}
			fakeViews := make([]*ControlChangeV, 0, len(AddressList()))
			for i := 0; i < len(AddressList()); i++ {
				fakeViews = append(fakeViews, controlV)
			}
			newView := &NewViewBroadCast{
				ViewNew:      round.view + 1,
				Height:       round.number,
				PIndex:       round.pIndex,
				IIndex:       round.iIndex,
				VIndex:       round.view,
				ValidateView: fakeViews,
			}
			newVhash := sigBroadcastNewV(newView)
			sig, _ := crypto.Sign(newVhash[:], round.prikey)
			newControlView := &ControlNewViewBroadCast{
				NewView: newView,
				Sig:     sig,
			}
			go d.eventMux.Post(AdvertToNewViewEvent{
				ViewNew: newControlView,
			})
		case byzTestModeNumber == MaliciousVoting:
			log.Warn("MaliciousVoting attack starts")

		default:
		}
	}
}

func (d *Dbft) checkVotes(chain consensus.ChainReader) bool {
	if d.votingAt != 0 && d.votingAt < chain.CurrentHeader().Number.Uint64() {
		miners := chain.GetLastVote()
		if bytes.Compare(common.AddrToByteSlice(sortAddrAsc(miners)), common.AddrToByteSlice(sortAddrAsc(d.updatedList))) == 0 {
			log.Warn("Weird votingAt with the same voting")
			return false
		} else {
			log.Error("Current Voting somehow does not work, please fix it")
			return false
		}
	} else {
		return true
	}
}


func genVoteList(seed int64) []common.Address {
	MaxMiners := int(9)
	MinMiners := int(params.MinMinersAllowed)

	random := rand.New(rand.NewSource(int64(seed)))
	
	miners := random.Perm(MaxMiners)
	next_num_miners := random.Intn(MaxMiners-MinMiners+1)+MinMiners
	miners = miners[:next_num_miners]

	var voteList []common.Address
	addressList := AddressList();
	for i := 0; i < len(miners); i++ {
		voteList = append(voteList, addressList[miners[i]])
	}
	return voteList
}






