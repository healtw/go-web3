package transport

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"eaglesdk/sdk/adapter"
	"eaglesdk/sdk/cert"

	"github.com/healtw/go-web3/rpc/codec"
	"github.com/valyala/fasthttp"
)

var (
	dialTimeout = time.Minute
)

type HTTP struct {
	addr       string
	proxy      string
	hostclient *fasthttp.HostClient
}

func NewHTTP(addr, proxy string) *HTTP {
	return newHTTP(addr, proxy)
}
func tlsClientConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(cert.CertPaxSys01))
	pool.AppendCertsFromPEM([]byte(cert.CertPaxR01))
	pool.AppendCertsFromPEM([]byte(cert.CertX3))

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if 0 == len(rawCerts) {
				return errors.New("RawCerts empty.")
			} else if 1 == len(rawCerts) {
				certificate, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return errors.New("RawCert data format error.")
				}

				verifyOptions := x509.VerifyOptions{
					Roots: pool,
				}
				_, err = certificate.Verify(verifyOptions)
				return err
			} else {
				return checkCerts(rawCerts, pool)
			}
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			if strings.HasSuffix(state.PeerCertificates[0].DNSNames[0], "paxengine.com.cn") {
				return nil
			}
			return errors.New("Host name is invalid.")
		},
	}
	return cfg
}
func checkCerts(rawCerts [][]byte, pool *x509.CertPool) error {
	length := len(rawCerts)

	for i := length - 1; i >= 0; i-- {
		certificate, err := x509.ParseCertificate(rawCerts[i])
		if err != nil {
			return errors.New("RawCert data format error.")
		}

		if i == length-1 {
			verifyOptions := x509.VerifyOptions{
				Roots: pool,
			}
			_, err = certificate.Verify(verifyOptions)
			if nil != err {
				return err
			}
		} else {
			certificateParent, err := x509.ParseCertificate(rawCerts[i+1])
			if err != nil {
				return errors.New("RawCert data format error.")
			}

			poolTmp := x509.NewCertPool()
			poolTmp.AddCert(certificateParent)
			verifyOptions := x509.VerifyOptions{
				Roots: poolTmp,
			}
			_, err = certificate.Verify(verifyOptions)
			if nil != err {
				return err
			}
		}
	}

	return nil
}

//no need http/https:
func getUrlAndPort(value string) string {
	var port string
	value1 := strings.ToLower(value)

	if strings.HasPrefix(value1, "http://") {
		value1 = strings.TrimLeft(value1, "http://")
		port = ":80"
	} else if strings.HasPrefix(value1, "https://") {
		value1 = strings.TrimLeft(value1, "https://")
		port = ":443"
	}

	if strings.Count(value1, ":") == 1 {
		return value1
	} else {
		Index := strings.Index(value1, "/")
		if Index == -1 {
			return value1 + port
		} else {
			head := value1[0:Index]
			tail := value1[Index:]
			// fmt.Println("\nhead:" + head + "\ntail:" + tail)
			return head + port + tail
		}
	}
}

func newHTTP(addr, proxy string) *HTTP {
	tlsConfig := tlsClientConfig()
	_IsTLS := true
	if strings.HasPrefix(addr, "http://") {
		_IsTLS = false
	}
	// adapter.Log("addr: [" + addr + "]")

	return &HTTP{
		addr: addr,
		hostclient: &fasthttp.HostClient{
			Addr: getUrlAndPort(addr),
			Dial: func(addr string) (net.Conn, error) {
				return fasthttp.DialTimeout(addr, dialTimeout)
			},
			IsTLS:     _IsTLS,
			TLSConfig: tlsConfig,
		},
	}
}

func (h *HTTP) Close() error {
	return nil
}

func (h *HTTP) Call(method string, out interface{}, params ...interface{}) error {
	request := codec.Request{
		Method:  method,
		Version: "2.0",
	}
	if len(params) > 0 {
		data, err := json.Marshal(params)
		if err != nil {
			return err
		}
		request.Params = data
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req := fasthttp.AcquireRequest()
	res := fasthttp.AcquireResponse()

	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(res)

	adapter.Log("h.addr:[" + h.addr + "]")
	adapter.Log("h.hostclient.Addr:[" + h.hostclient.Addr + "]")
	adapter.Log("h.hostclient.Name:[" + h.hostclient.Name + "]")
	req.SetRequestURI(h.addr)
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/json")
	req.SetBody(raw)

	if err := h.hostclient.Do(req, res); err != nil {
		return err
	}

	var response codec.Response
	if err := json.Unmarshal(res.Body(), &response); err != nil {
		return err
	}
	if response.Error != nil {
		return response.Error
	}

	// bt, _ := response.Result.MarshalJSON()
	// fmt.Println("bt: " + hex.EncodeToString(bt))
	if err := json.Unmarshal(response.Result, out); err != nil {
		return err
	}
	return nil
}

func (h *HTTP) Do(req *fasthttp.Request, res *fasthttp.Response) ([]byte, error) {
	if err := h.hostclient.Do(req, res); err != nil {
		return nil, err
	}

	return res.Body(), nil
}

func httpProxyDialer(proxy string, timeout time.Duration) fasthttp.DialFunc {
	if strings.Contains(proxy, "http://") {
		proxy = strings.TrimPrefix(proxy, "http://")
	}
	if strings.Contains(proxy, "https://") {
		proxy = strings.TrimPrefix(proxy, "https://")
	}
	return func(addr string) (net.Conn, error) {
		var auth string
		if strings.Contains(proxy, "@") {
			split := strings.Split(proxy, "@")
			auth = base64.StdEncoding.EncodeToString([]byte(split[0]))
			proxy = split[1]

		}

		conn, err := fasthttp.DialTimeout(proxy, timeout)
		if err != nil {
			return nil, err
		}

		req := "CONNECT " + addr + " HTTP/1.1\r\n"
		if auth != "" {
			req += "Proxy-Authorization: Basic " + auth + "\r\n"
		}
		req += "\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			return nil, err
		}

		res := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(res)

		res.SkipBody = true

		if err := res.Read(bufio.NewReader(conn)); err != nil {
			conn.Close()
			return nil, err
		}
		if res.Header.StatusCode() != 200 {
			conn.Close()
			return nil, fmt.Errorf("could not connect to proxy")
		}
		return conn, nil
	}
}
