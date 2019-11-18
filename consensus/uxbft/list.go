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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/p2p/discover"
)

const (
	IDLength = 64
)

func BytesToID(temp []byte) *discover.NodeID {
	var id *discover.NodeID
	id.SetBytes(temp)
	return id
}

func HexToID(flag bool, s string) interface{} {
	if flag == true {
		return BytesToID(common.FromHex(s)) // 64B
	} else {
		return s[:16] // this is matched with eth/peers
	}
}

// test Node
func NodeList(flag bool) []interface{} {
	return []interface{}{
		HexToID(flag, "84f11bc47992cee61cdf17d5a99dfdac8f359f328d5c92d654d1cba9bdd88070260e4ccdfb1f70ec4ce75a429a68f0187dd5d4622921a7741437e3c33375b7c9"),
		HexToID(flag, "55d46624224fcdb233875107aeb20f8dccea9f717dedf1b5b7c0264800409d2f144316e946b5ff4646842280040a7f2128e3fc14a0aadea2d2c63334eef227a5"),
		HexToID(flag, "80af38d9fdbb9a59abeb5d4b65baec170fd236204858027fb33a78c240c575686bcd1013f8b955dba439291cd0f088ec1b724daf53f310d8dafb737998ad655b"),
		HexToID(flag, "91c45d9ff0580f94658f6b7b345026dd84d432510d89ec64a109568d83e2149a9791e60b446f7690e650899095d7fc3ed1d597ba3151900d2978d5ebdb7ec61e"),
	}
}

func AddressList() []common.Address {
	return []common.Address{
		common.HexToAddress("8cd57645db8586e4c5e05899d1e626c5a3e3392f"),
		common.HexToAddress("e5d2d92e6afc718c7bf457fd68363a7d39c4938b"),
		common.HexToAddress("0652212db454bb486b6f40277045bddc7c7f4877"),
		common.HexToAddress("a5bfcd25e39af967d4f47d031c2a7e3aa528f05d"),
	}
}

// Returns a list of nodeIDs in the correct order
func AddrListToNodeList(addrToNodeID map[common.Address]string, addrList []common.Address) []interface{} {
	nodeList := make([]interface{}, 0, len(addrList))
	for _, addr := range addrList {
		id := addrToNodeID[addr]
		if id != "" {
			nodeList = append(nodeList, HexToID(false, addrToNodeID[addr]))
		}
	}
	return nodeList
}
