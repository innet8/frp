// Copyright 2019 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nahid/gohttp"

	"github.com/fatedier/frp/pkg/config"
	frpNet "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/util"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/server/metrics"

	frpIo "github.com/fatedier/golib/io"
)

type HTTPProxy struct {
	*BaseProxy
	cfg *config.HTTPProxyConf

	closeFuncs []func()
	closed     bool
}

// CommReply 通用的返回结构体
type CommReply struct {
	Ret int    `json:"ret"`
	Msg string `json:"msg"`
	// Data interface{} `json:"data"`
}

func (pxy *HTTPProxy) Run() (remoteAddr string, err error) {
	xl := pxy.xl
	routeConfig := vhost.RouteConfig{
		RewriteHost:  pxy.cfg.HostHeaderRewrite,
		Headers:      pxy.cfg.Headers,
		Username:     pxy.cfg.HTTPUser,
		Password:     pxy.cfg.HTTPPwd,
		CreateConnFn: pxy.GetRealConn,
	}

	locations := pxy.cfg.Locations
	if len(locations) == 0 {
		locations = []string{""}
	}

	defer func() {
		if err != nil {
			pxy.Close()
		}
	}()

	addrs := make([]string, 0)
	for _, domain := range pxy.cfg.CustomDomains {
		if domain == "" {
			continue
		}

		routeConfig.Domain = domain
		for _, location := range locations {
			routeConfig.Location = location
			tmpDomain := routeConfig.Domain
			tmpLocation := routeConfig.Location

			// handle group
			if pxy.cfg.Group != "" {
				err = pxy.rc.HTTPGroupCtl.Register(pxy.name, pxy.cfg.Group, pxy.cfg.GroupKey, routeConfig)
				if err != nil {
					return
				}

				pxy.closeFuncs = append(pxy.closeFuncs, func() {
					pxy.rc.HTTPGroupCtl.UnRegister(pxy.name, pxy.cfg.Group, tmpDomain, tmpLocation)
				})
			} else {
				// no group
				err = pxy.rc.HTTPReverseProxy.Register(routeConfig)
				if err != nil {
					return
				}
				pxy.closeFuncs = append(pxy.closeFuncs, func() {
					pxy.rc.HTTPReverseProxy.UnRegister(tmpDomain, tmpLocation)
				})
			}
			addrs = append(addrs, util.CanonicalAddr(routeConfig.Domain, int(pxy.serverCfg.VhostHTTPPort)))
			xl.Info("http proxy listen for host [%s] location [%s] group [%s]", routeConfig.Domain, routeConfig.Location, pxy.cfg.Group)
			// 发布状态（上线）
			go pxy.statusOnline(routeConfig.Domain)
		}
	}

	if pxy.cfg.SubDomain != "" {
		routeConfig.Domain = pxy.cfg.SubDomain + "." + pxy.serverCfg.SubDomainHost
		for _, location := range locations {
			routeConfig.Location = location
			tmpDomain := routeConfig.Domain
			tmpLocation := routeConfig.Location

			// handle group
			if pxy.cfg.Group != "" {
				err = pxy.rc.HTTPGroupCtl.Register(pxy.name, pxy.cfg.Group, pxy.cfg.GroupKey, routeConfig)
				if err != nil {
					return
				}

				pxy.closeFuncs = append(pxy.closeFuncs, func() {
					pxy.rc.HTTPGroupCtl.UnRegister(pxy.name, pxy.cfg.Group, tmpDomain, tmpLocation)
				})
			} else {
				err = pxy.rc.HTTPReverseProxy.Register(routeConfig)
				if err != nil {
					return
				}
				pxy.closeFuncs = append(pxy.closeFuncs, func() {
					pxy.rc.HTTPReverseProxy.UnRegister(tmpDomain, tmpLocation)
				})
			}
			addrs = append(addrs, util.CanonicalAddr(tmpDomain, pxy.serverCfg.VhostHTTPPort))

			xl.Info("http proxy listen for host [%s] location [%s] group [%s]", routeConfig.Domain, routeConfig.Location, pxy.cfg.Group)
		}
	}
	remoteAddr = strings.Join(addrs, ",")
	return
}

func (pxy *HTTPProxy) GetConf() config.ProxyConf {
	return pxy.cfg
}

func (pxy *HTTPProxy) GetRealConn(remoteAddr string) (workConn net.Conn, err error) {
	xl := pxy.xl
	rAddr, errRet := net.ResolveTCPAddr("tcp", remoteAddr)
	if errRet != nil {
		xl.Warn("resolve TCP addr [%s] error: %v", remoteAddr, errRet)
		// we do not return error here since remoteAddr is not necessary for proxies without proxy protocol enabled
	}

	tmpConn, errRet := pxy.GetWorkConnFromPool(rAddr, nil)
	if errRet != nil {
		err = errRet
		return
	}

	var rwc io.ReadWriteCloser = tmpConn
	if pxy.cfg.UseEncryption {
		rwc, err = frpIo.WithEncryption(rwc, []byte(pxy.serverCfg.Token))
		if err != nil {
			xl.Error("create encryption stream error: %v", err)
			return
		}
	}
	if pxy.cfg.UseCompression {
		rwc = frpIo.WithCompression(rwc)
	}
	workConn = frpNet.WrapReadWriteCloserToConn(rwc, tmpConn)
	workConn = frpNet.WrapStatsConn(workConn, pxy.updateStatsAfterClosedConn)
	metrics.Server.OpenConnection(pxy.GetName(), pxy.GetConf().GetBaseInfo().ProxyType)
	return
}

func (pxy *HTTPProxy) updateStatsAfterClosedConn(totalRead, totalWrite int64) {
	name := pxy.GetName()
	proxyType := pxy.GetConf().GetBaseInfo().ProxyType
	metrics.Server.CloseConnection(name, proxyType)
	metrics.Server.AddTrafficIn(name, proxyType, totalWrite)
	metrics.Server.AddTrafficOut(name, proxyType, totalRead)
}

func (pxy *HTTPProxy) Close() {
	pxy.closed = true
	pxy.BaseProxy.Close()
	for _, closeFn := range pxy.closeFuncs {
		closeFn()
	}
}

// 发布状态（上线）
func (pxy *HTTPProxy) statusOnline(domain string) {
	xl := pxy.xl
	defer func() {
		if err := recover(); err != nil {
			xl.Error("panic error: %v", err)
			xl.Error(string(debug.Stack()))
		}
	}()

	if os.Getenv("FRPS_PUBLISH_URL") != "" {
		arr := strings.Split(domain, ".")
		devicesn := arr[0]
		params := map[string]interface{}{
			"action": "getdevice",
			"time":   strconv.FormatInt(time.Now().Unix(), 10),
		}
		var dataString string
		var keys []string
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dataString = dataString + k + "=" + params[k].(string) + "&"
		}
		h := md5.New()
		h.Write([]byte(dataString + devicesn))
		sign := hex.EncodeToString(h.Sum(nil))
		params["sign"] = strings.ToUpper(sign)
		//
		var ret int
		var deviceinfo string
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		for i := 0; i < 1000; i++ {
			if pxy.closed {
				break
			}
			if i != 0 {
				time.Sleep(10 * time.Second)
			}

			resp, _ := gohttp.NewRequest().JSON(params).Post("http://" + domain + ":6009/cgi-bin/console")
			if resp == nil {
				continue
			}
			deviceinfo, _ = resp.GetBodyAsString()

			var cr CommReply
			jerr := json.Unmarshal([]byte(deviceinfo), &cr)
			ret = cr.Ret
			if jerr != nil || ret != 1 {
				xl.Warn("cgi-bin/console request failed. try again in 10 seconds of %d times! host [%s]", i, domain)
				continue
			}

			gohttp.NewRequest().
				FormData(map[string]string{
					"act":        "online",
					"name":       pxy.GetName(),
					"runid":      pxy.GetUserInfo().RunID,
					"domain":     domain,
					"deviceinfo": base64.StdEncoding.EncodeToString([]byte(deviceinfo)),
					"timestamp":  timestamp,
				}).
				Post(os.Getenv("FRPS_PUBLISH_URL"))
			break
		}
	}
}
