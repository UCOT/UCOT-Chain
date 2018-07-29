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

package params

import (
	"math"
	"math/big"

	// "github.com/ethereum/go-ethereum/log"
)
const (
	miningLogAtDepth = 5 // equals to miner/worker.go
	coinAgeWindow = 512
)

// Parameters of ucot-token
var (
	TokenTotal           *big.Int = TotalAmountToken("1050000000000000000000000000")
	ReleaseTotal         *big.Int = TotalAmountToken("210000000000000000000000000") // 0.21 billion UBI
)

// totalAmountToken represents the total amount of token released.
func TotalAmountToken(amount string) *big.Int {
	a := new(big.Int)
	result, _ := a.SetString(amount, 10)
	return result
}

// GetCoinAgeClasses returns the coin age associated with the given persentage.
func GetCoinAgeClasses(percentage float64) float64 {
	var (
		thresholds = []float64{-1, 5, 10, 20, 25, 100}
	)
	agesMap := ageCalculator(thresholds)
	for i := 0; i < len(thresholds); i++ {
		if percentage <= thresholds[i] {
			return agesMap[thresholds[i]]
		}
	}
	return agesMap[thresholds[0]]
}

func ageCalculator(thresholds []float64) map[float64]float64 {
	agesMap := make(map[float64]float64)
	for i := 0; i < len(thresholds); i++ {
		if thresholds[i] == -1 {
			agesMap[thresholds[i]] = 0
		} else {
			agesMap[thresholds[i]] = math.Log10(float64(coinAgeWindow+miningLogAtDepth-1))/math.Log10(float64(len(thresholds)-i)*2) // formulator
		}
	}
	return agesMap
}






