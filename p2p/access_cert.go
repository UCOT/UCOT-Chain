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

package p2p

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/read_local"
)

const (
	// Idendity_ip_addr = "172.31.0.40:33333"
	FileName = "/conf.txt"
)

// Read the remote IP from the local conf file
func ReadConf(path, node, key string) (string, error) {
	conf := new(read_local.Config)
	err := conf.InitConfig(path)
	if err != nil {
		return "", err
	}
	return conf.Read(node, key), nil
}

// Validate the format of the given IP address
func validateIP(ip string) bool {
	ip_port := strings.Split(ip, ":")
	port, err := strconv.Atoi(ip_port[1])
	if err != nil {
		return false
	}
	if net.ParseIP(ip_port[0]) == nil || port > 65535 {
		return false
	} else {
		return true
	}
}

// Fetch address from remote database
func FetchAddrAndValidate(address common.Address, path string) (bool, error) {
	log.Trace("Fetch address from remote database")

	remoteDB_IP, err := ReadConf(filepath.Join(path, "/geth", FileName), "default", "databaseIP")
	fmt.Println("remoteDB_IP", remoteDB_IP)
	if !validateIP(remoteDB_IP) {
		return false, errors.New("Invalid IP address in conf file")
	} else if err != nil {
		return false, err
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", remoteDB_IP)
	if err != nil {
		return false, err
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return false, err
	}
	go func() {
		output := make([]byte, 1+common.AddressLength)
		n := copy(output, []byte{2})
		copy(output[n:], address[:])

		_, err := conn.Write(output)
		if err != nil {
			log.Trace("Sending error", "err", err)
			conn.Close()
		}
	}()

	buf := make([]byte, 1)
	flag := []byte{0, 1} // false, true

	_, err = conn.Read(buf)
	if err != nil {
		conn.Close()
		return false, err
	}
	if bytes.Equal(buf[:], flag[:1]) {
		conn.Close()
		return false, errors.New("Invalid address")
	} else if bytes.Equal(buf[:], flag[1:]) {
		conn.Close()
		return true, nil
	} else {
		conn.Close()
		return false, errors.New("Invalid flag")
	}
}

// Joining
func sendRequest(conn net.Conn, access []byte, address []byte) {

	// var output []byte
	// output = append(output, []byte{0}...)
	// output = append(output, access...)
	// output = append(output, nonce...)
	// output = append(output, nodeID[:]...)
	// output = append(output, reqNodeID[:]...)

	// output := make([]byte, 1+md5Len*2+shaLen+pubLen*2)
	output := make([]byte, 1+shaLen+common.AddressLength)
	n := copy(output, []byte{0})
	n += copy(output[n:], access)
	copy(output[n:], address)
	fmt.Println("address",common.ToHex(address[:]))
	// n += copy(output[n:], access)
	// n += copy(output[n:], nonce)
	// n += copy(output[n:], nodeID[:])
	// copy(output[n:], reqNodeID[:])

	_, err := conn.Write(output)
	if err != nil {
		log.Trace("Sending error", "err", err)
		conn.Close()
	}
}

func getAccess(access []byte, path string) (bool, error) {
	// log.Trace("Check nodeID from request", "id", common.ToHex(reqNodeID[:]))

	remoteDB_IP, err := ReadConf(filepath.Join(path[:len(path)-len("/nodes")], FileName), "default", "databaseIP")
	fmt.Println("remoteDB_IP", remoteDB_IP)
	if !validateIP(remoteDB_IP) {
		return false, errors.New("Invalid IP address in conf file")
	} else if err != nil {
		return false, err
	}
	address, err := ReadConf(filepath.Join(path[:len(path)-len("/nodes")], FileName), "address", "address")
	if err != nil {
		return false, err
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", remoteDB_IP)
	if err != nil {
		return false, err
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return false, err
	}
	go sendRequest(conn, access, common.HexToAddress(address).Bytes())

	buf := make([]byte, 1)
	flag := []byte{0, 1} // false, true

	_, err = conn.Read(buf)
	if err != nil {
		fmt.Println("entering 1")
		conn.Close()
		return false, err
	}
	if bytes.Equal(buf[:], flag[:1]) {
		fmt.Println("entering 2")
		conn.Close()
		return false, errors.New("Incorrent hash")
	} else if bytes.Equal(buf[:], flag[1:]) {
		fmt.Println("entering 3")
		conn.Close()
		return true, nil
	} else {
		fmt.Println("entering 4")
		conn.Close()
		return false, errors.New("Invalid flag")
	}
}

// Disconnecting
func update(conn net.Conn, nodeID discover.NodeID, connected map[string]string) error {
	// output := make([]byte, shaLen*2)
	var output []byte

	bts, err := getBytes(connected)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	output = append(output, []byte{1}...)
	output = append(output, nodeID[:]...)
	output = append(output, bts...)

	// n := copy(output, accessWithNonce)
	// copy(output[n:], nonce)
	for {
		if _, err := conn.Write(output); err == nil {
			break
		} else {
			log.Trace("Sending error, retrying ...", "err", err)
		}
	}
	log.Trace("Sending successfully")
	return nil
}

// func discRequest(IP string) {
func updateServerDB(nodeID discover.NodeID, connected map[string]string, path string) {
	for id, _ := range connected {
		log.Trace("Check nodeID from updateDB request", "id", id)
	}
	for {
		remoteDB_IP, err := ReadConf(filepath.Join(path[:len(path)-len("/nodes")], FileName), "default", "databaseIP")
		if !validateIP(remoteDB_IP) {
			log.Error("Invalid IP address in conf file")
			continue
		} else if err != nil {
			fmt.Println(err.Error())
			continue
		}
		tcpAddr, err := net.ResolveTCPAddr("tcp", remoteDB_IP)
		if err != nil {
			continue
		}
		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			continue
		}
		err = update(conn, nodeID, connected)
		if err != nil {
			continue
		}
		conn.Close()
		break
	}
}

func getBytes(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
