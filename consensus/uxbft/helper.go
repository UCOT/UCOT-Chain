//function.go stores various helper functions

package dbft

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
)

// Sort a list of addresses in ascending order
func sortAddrAsc(addr []common.Address) []common.Address {
	sortedAddr := make([]common.Address, len(addr))
	copy(sortedAddr, addr)
	for i := 0; i < len(sortedAddr); i++ {
		for j := i + 1; j < len(sortedAddr); j++ {
			if bytes.Compare(sortedAddr[i][:], sortedAddr[j][:]) > 0 {
				sortedAddr[i], sortedAddr[j] = sortedAddr[j], sortedAddr[i]
			}
		}
	}
	return sortedAddr
}

func sortAddrDes(addr []common.Address) []common.Address {
	sortedAddr := make([]common.Address, len(addr))
	copy(sortedAddr, addr)
	for i := 0; i < len(sortedAddr); i++ {
		for j := i + 1; j < len(sortedAddr); j++ {
			if bytes.Compare(sortedAddr[i][:], sortedAddr[j][:]) < 0 {
				sortedAddr[i], sortedAddr[j] = sortedAddr[j], sortedAddr[i]
			}
		}
	}
	return sortedAddr
}

func addrInSlice(addr common.Address, list []common.Address) bool {
	for _, v := range list {
		if v == addr {
			return true
		}
	}
	return false
}

func IndexInSlice(i int, s []uint64) bool {
	for _, v := range s {
		if int(v) == i {
			return true
		}
	}
	return false
}

func addrIndex(addr common.Address, list []common.Address) int {
	for i, v := range list {
		if v == addr {
			return i
		}
	}
	return -1
}

func AddrIndex(addr common.Address, list []common.Address) int {
	for i, v := range list {
		if v == addr {
			return i
		}
	}
	return -1
}

func stringToUInt(str string) int64 {
	str_byte := []byte(str)
	var prod int64 = 1
	for _, i := range str_byte {
		prod *= int64(i)
	}
	return prod
}

func max(a uint64, b uint64) uint64 {
	if a > b {
		return a
	} else {
		return b
	}
}
