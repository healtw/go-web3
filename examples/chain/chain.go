/*
 * ===========================================================================================
 * Revision History:
 * Date                         Author                        Action
 * 2022/07/08                   Carel.Cheng                   Create
 *Revised content:
 *1.Change the path of the imported package
 * ===========================================================================================
 */

package main

import (
	"fmt"

	"github.com/healtw/go-web3"
)

func main() {

	// change to your rpc provider
	var rpcProvider = "https://rpc.flashbots.net"
	web3, err := web3.NewWeb3(rpcProvider)
	if err != nil {
		panic(err)
	}
	blockNumber, err := web3.Eth.GetBlockNumber()
	if err != nil {
		panic(err)
	}
	fmt.Println("Current block number: ", blockNumber)
}
