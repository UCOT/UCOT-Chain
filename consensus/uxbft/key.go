//key.go holds functions related to key recovery from various messages.

package dbft

import (
	"crypto/ecdsa"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p/discover"
	lru "github.com/hashicorp/golang-lru"
)

// Returns the nodeID from the nodekey
func GetNodeID(ctx *node.ServiceContext) string {
	nodeKey := ctx.GetConfig().NodeKey()
	return discover.PubkeyID(&nodeKey.PublicKey).String()
}

// TODO: This func needs a rewrite, too many magic here.
func GetNodeConfig(ctx *node.ServiceContext) (string, string, common.Address, error) {

	checkFileName := func(files []os.FileInfo) bool {
		var count int
		for _, f := range files {
			if f.Name()[:3] == "UTC" {
				count += 1
			}
		}
		return count == 1
	}

	keydir := ctx.GetConfig().KeystoreDir()
	files, err := ioutil.ReadDir(keydir)
	if err != nil {
		return "", "", [20]byte{}, errors.New("Can't read the keystore file")
	}
	if len(files) == 0 {
		return "", "", [20]byte{}, errors.New("File does not exist")
	}
	if !checkFileName(files) {
		return "", "", [20]byte{}, errors.New("There exists more than one keystore file or invalid file name")
	}

	var addrStr string
	var filename string
	for i := 0; i < len(files); i++ {
		filename = filepath.Join(keydir, files[i].Name()) // Only one file
		if files[i].Name()[0] == '.' {
			continue
		}
		addrStr = filename[len(filename)-40:]
		if common.IsHexAddress(addrStr) {
			break
		}
	}
	addr := common.HexToAddress(addrStr)

	return keydir, filename, addr, nil
}

// ecrecover extracts the Ethereum account address from a signed header. If header does not exist, store in the cache
func ecrecover(header *types.Header, sigcache *lru.ARCCache, isLight bool) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known && !isLight { //***
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < types.SealLength {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-types.SealLength:] // getExtraSeal()

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(sigHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	if !isLight {
		sigcache.Add(hash, signer)
	}
	return signer, nil
}

//Empty interface describing objects that have a digital signature.
type keyRecoverable interface{}

//Gets the signed hash for an object. Used in key recovery.
func getSigHash(obj keyRecoverable) []byte {
	switch obj.(type) {
	case *types.Header:
		return sigHash(obj.(*types.Header)).Bytes()
	case *ChangeView:
		return sigchangeV(obj.(*ChangeView)).Bytes()
	case *NewViewBroadCast:
		return sigBroadcastNewV(obj.(*NewViewBroadCast)).Bytes()
	case *TxRequest:
		return sigTxReq(obj.(*TxRequest)).Bytes()
	default:
		return nil
	}
}

// Recovers the public key from a range of different formats.
func recoverPubKey(k keyRecoverable, sig []byte) (common.Address, error) {
	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(getSigHash(k), sig)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	return signer, nil
}

//Returns the private key of the current user.
func getPrivateKey(ctx *node.ServiceContext) (*ecdsa.PrivateKey, error) {
	keydir, filename, addr, err := GetNodeConfig(ctx)
	if err != nil {
		return nil, err
	}

	auth := ctx.GetConfig().PassPhrase
	if auth == "" {
		return nil, errors.New("Nil Passphrase")
	}
	ks := keystore.NewKeyStorePassphrase(keydir, scriptN, scriptP)
	key, err := ks.GetKey(addr, filename, auth)
	if err != nil {
		return nil, err
	} else {
		return key.PrivateKey, nil
	}
}
