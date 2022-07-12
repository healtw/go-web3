package web3

import (
	"fmt"

	"github.com/healtw/go-web3/eth"
	"github.com/healtw/go-web3/rpc"
	"github.com/healtw/go-web3/utils"
)

type Web3 struct {
	Eth   *eth.Eth
	Utils *utils.Utils
	c     *rpc.Client
}

func NewWeb3(provider string) (*Web3, error) {
	return NewWeb3WithProxy(provider, "")
}

func NewWeb3WithProxy(provider, proxy string) (*Web3, error) {
	c, err := rpc.NewClient(provider, proxy)
	if err != nil {
		return nil, err
	}
	e := eth.NewEth(c)
	chainId, err := e.ChainID()

	// providerLowerStr := strings.ToLower(provider)

	// if strings.Contains(providerLowerStr, "ropsten") {
	// 	e.SetChainId(3)
	// } else if strings.Contains(providerLowerStr, "kovan") {
	// 	e.SetChainId(42)
	// } else if strings.Contains(providerLowerStr, "rinkeby") {
	// 	e.SetChainId(4)
	// } else if strings.Contains(providerLowerStr, "goerli") {
	// 	e.SetChainId(5)
	// } else {
	// 	e.SetChainId(1)
	// }

	fmt.Println("chainId.Int64(): " + err.Error())
	fmt.Println(chainId.Int64())

	e.SetChainId(chainId.Int64())
	u := utils.NewUtils()
	w := &Web3{
		Eth:   e,
		Utils: u,
		c:     c,
	}

	// Default poll timeout 2 hours
	w.Eth.SetTxPollTimeout(0)
	return w, nil
}

func (w *Web3) Version() (string, error) {
	var out string
	err := w.c.Call("web3_clientVersion", &out)
	return out, err
}
