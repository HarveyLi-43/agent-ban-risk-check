# 修复手册

按泄露类型查。先确认是哪一层，再改对应的配置。

## 一、srflx 与 HTTP 出口不一致

原因：UDP 没走代理。只开系统代理时，HTTP 走代理，UDP 从真实网卡直连。

### Clash Verge Rev / Mihomo

开 TUN 模式，并确认这三项：

```yaml
tun:
  enable: true
  stack: mixed          # gvisor 也行，system 在部分 Windows 上不稳
  auto-route: true
  dns-hijack:
    - any:53
  # UDP 必须跟着 TUN 走，不要在规则里给 UDP 加 DIRECT
```

如果规则里有 `AND,((NETWORK,udp),(DST-PORT,443)),DIRECT` 这类，删掉。

### sing-box

```json
{
  "inbounds": [{
    "type": "tun",
    "auto_route": true,
    "strict_route": true,
    "stack": "mixed"
  }]
}
```

`strict_route` 打开后，UDP 也会被接管。

### Surge

开启「增强模式」（Enhanced Mode）。仅开系统代理不够。

## 二、host 候选出现真实 IP

原因：浏览器关闭了 mDNS 混淆，或者用了不混淆的浏览器。

### Chromium 系（Chrome / Edge）

默认就混淆。出现真实地址，先查两处：

- `edge://flags` 或 `chrome://flags` 搜 `WebRTC`，确认没有关闭 `Anonymize local IPs exposed by WebRTC`。
- 企业策略 `WebRtcLocalIpsAllowedUrls` 是否被设置。

还不行就装扩展：

1. 装 **WebRTC Network Limiter**（Google 官方）。
2. 选项里选 **Use my proxy server only** 或 `disable_non_proxied_udp`。

### Firefox

在 `about:config` 里设：

```
media.peerconnection.ice.default_address_only = true
media.peerconnection.ice.no_host = true
```

### Safari

系统层面没开关。要么关 WebRTC（影响视频通话），要么用别的浏览器。

## 三、IPv6 反射地址 / IPv6 直接出网

两条路一起堵。

### 关掉系统 IPv6

Windows：

```
设置 → 网络和 Internet → 适配器选项 → 属性
→ 取消勾选 "Internet 协议版本 6 (TCP/IPv6)"
```

命令行方式（管理员）：

```powershell
Disable-NetAdapterBinding -Name "WLAN" -ComponentID ms_tcpip6
```

### 或者在客户端里接管 IPv6

Mihomo：

```yaml
tun:
  inet6-address:
    - fdfe:dcba:9876::1/126
ipv6: true
```

sing-box：在 tun inbound 里加 `"inet6_address": "fdfe:dcba:9876::1/126"`。

### DNS 层抑制 AAAA

fake-ip 模式下，客户端通常不返回 AAAA。确认：

```yaml
dns:
  ipv6: false
```

这时浏览器拿不到 IPv6 地址，自然不会走 IPv6。

## 四、出口三家不一致 / 特定站点走直连

原因：分流规则判错。

先定位是哪个域名：

```bash
curl -s https://api.ipify.org
curl -s https://ifconfig.me/ip
curl -s https://icanhazip.com
```

三个都试。哪个返回真实 IP，就把那个域名加进强制代理规则。

Mihomo：

```yaml
rules:
  - DOMAIN-SUFFIX,ipify.org,PROXY
  - DOMAIN-SUFFIX,ifconfig.me,PROXY
  - DOMAIN-SUFFIX,icanhazip.com,PROXY
```

放在规则列表靠前的位置。规则从上往下匹配，第一个命中的生效。

**顺带检查**：`browserleaks.com`、`ipleak.net`、`dnsleaktest.com` 这类检测站，经常不在规则集里，容易被 FINAL 规则判成直连。做检测前先确认它们走代理，否则测出来的结果是假的。

## 五、DNS 路径不明

目标是让域名解析也走代理。

Mihomo：

```yaml
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://223.5.5.5/dns-query     # 国内，直连
  fallback:
    - https://1.1.1.1/dns-query       # 海外，走代理
  fallback-filter:
    geoip: true
    geoip-code: CN
```

`fake-ip` 的作用：域名解析直接返回 `198.18.x.x`，真实解析在代理端完成。这样本机永远不会发出明文 DNS 查询。

sing-box：

```json
{
  "dns": {
    "servers": [
      { "tag": "fakeip", "address": "fakeip" },
      { "tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy" }
    ],
    "fakeip": { "enabled": true, "inet4_range": "198.18.0.0/15" }
  }
}
```

## 六、改完之后

按顺序验证，不要跳步：

1. 客户端原生检查通过：`mihomo -t`、`sing-box check -c config.json`、`surge-cli --check`。
2. 重载配置。
3. 重跑 `python scripts/audit.py`。
4. 确认 `report.md` 的总体结论变成 `CLEAN`。

任何一项没通过，先看报告里的「判定」段，它会指出具体是哪一层。

## 七、不要做的事

- 不要为了通过检测去关闭 IPv6 以外的系统功能。
- 不要用「关掉 WebRTC」来解决泄露。很多站点依赖它做视频，副作用比泄露本身大。
- 不要在检测过程中切换节点。出口跳变会让结果失去意义。
- 不要相信「检测页空白 = 安全」。空白通常意味着没测到，不是没泄露。
