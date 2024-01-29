/*
 * ===========================================================================================
 * Revision History:
 * Date                         Author                        Action
 * 2022/07/08                   Carel.Cheng                   Create
 *Revised content:
 *1.Change the path of the imported package
 * ===========================================================================================
 */

package crypto

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/healtw/go-web3/utils"
)

func VerifyProof(proofs []common.Hash, root []byte, data []byte) (bool, error) {
	computedHash := make([]byte, len(data))
	copy(computedHash[:], data[:])
	util := utils.NewUtils()
	for _, proof := range proofs {
		var err error
		var abiEncodePacked []byte
		if bytes.Compare(computedHash, proof[:]) <= 0 {
			abiEncodePacked, err = util.AbiEncodePacked(computedHash, proof[:])
		} else {
			abiEncodePacked, err = util.AbiEncodePacked(proof[:], computedHash)
		}
		if err != nil {
			return false, err
		}
		computedHash = Keccak256Hash(abiEncodePacked)

	}
	return bytes.Equal(computedHash, root), nil

}
