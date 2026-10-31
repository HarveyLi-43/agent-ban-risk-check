#!/usr/bin/env python3
"""Proxy leak audit: five-layer check, standard library only.

Layers: egress consistency, WebRTC/ICE candidates, DNS path, IPv6 reachability,
TUN and proxy presence. Output is data first, verdict second, plain language last.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = {"User-Agent": "proxy-leak-audit/1.0"}
TIMEOUT = 6
TUN_WORDS = ("mihomo", "meta tunnel", "wintun", "clash", "sing-box", "singbox",
             "utun", "wireguard", "tailscale", "tun")
PRIVATE_V4 = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)")
FAKEIP = ("198.18.", "198.19.")


# ---------------------------------------------------------------- utilities

def fetch_text(url: str, timeout: int = TIMEOUT) -> str:
    req = Request(url, headers=UA)
    with urlopen(req, timeout=timeout) as resp:
        return resp.read(65536).decode("utf-8", "replace").strip()


def local_ipconfig() -> str:
    """Return raw adapter text for the current platform, best effort."""
    try:
        if sys.platform == "win32":
            raw = subprocess.run(["ipconfig", "/all"], capture_output=True,
                                 timeout=15).stdout
            return raw.decode("gbk", "ignore")
        if sys.platform == "darwin":
            return subprocess.run(["ifconfig"], capture_output=True,
                                  timeout=10).stdout.decode("utf-8", "ignore")
        return subprocess.run(["ip", "addr"], capture_output=True,
                              timeout=10).stdout.decode("utf-8", "ignore")
    except Exception:
        return ""


def port_open(host: str, port: int, timeout: float = 1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------- layer 1-2

def check_system_proxy() -> dict:
    out = {"platform": sys.platform, "enabled": False, "server": None,
           "host": None, "port": None, "source": None}
    if sys.platform == "win32":
        try:
            import winreg
            path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                out["enabled"] = bool(winreg.QueryValueEx(key, "ProxyEnable")[0])
                try:
                    out["server"] = winreg.QueryValueEx(key, "ProxyServer")[0]
                except OSError:
                    pass
            out["source"] = "registry"
        except Exception as exc:
            out["error"] = str(exc)
    else:
        for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                     "ALL_PROXY", "all_proxy"):
            value = os.environ.get(name)
            if value:
                out.update(enabled=True, server=value, source=name)
                break

    if out["server"]:
        first = out["server"].split(";")[0]
        if "=" in first:
            first = first.split("=", 1)[1]
        first = first.replace("http://", "").replace("https://", "").strip("/")
        if ":" in first:
            host, port = first.rsplit(":", 1)
            out["host"] = host
            if port.isdigit():
                out["port"] = int(port)
    return out


def check_tun() -> dict:
    text = local_ipconfig()
    out = {"present": False, "name": None, "has_ipv4": False, "raw_hint": []}
    if not text:
        return out
    blocks = re.split(r"\r?\n\r?\n", text)
    for block in blocks:
        low = block.lower()
        if any(word in low for word in TUN_WORDS):
            lines = [ln for ln in block.strip().splitlines() if ln.strip()]
            head = lines[0].strip().rstrip(":") if lines else ""
            desc = ""
            for line in lines:
                if ("描述" in line or "description" in line.lower()) and ":" in line:
                    desc = line.split(":", 1)[-1].strip()
                    break
            for prefix in ("未知适配器", "以太网适配器", "无线局域网适配器", "隧道适配器"):
                head = head.replace(prefix, "")
            out["present"] = True
            out["name"] = desc or head.strip()
            out["has_ipv4"] = bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", block))
            out["raw_hint"].append(head.strip())
            break
    return out


def check_listeners(proxy: dict) -> dict:
    common = [7890, 7891, 7897, 1080, 10808, 10809, 6152, 7899]
    found = []
    if proxy.get("host") and proxy.get("port"):
        if port_open(proxy["host"], proxy["port"]):
            found.append(proxy["port"])
    for port in common:
        if port not in found and port_open("127.0.0.1", port, 0.4):
            found.append(port)
    return {"listening": found, "any": bool(found)}


# ---------------------------------------------------------------- layer 3-4

def check_dns() -> dict:
    out = {"resolve": {}, "fakeip": False, "local_dns": [], "error": None}
    for host in ("www.google.com", "www.cloudflare.com", "github.com"):
        try:
            out["resolve"][host] = socket.gethostbyname(host)
        except OSError:
            out["resolve"][host] = None
    out["fakeip"] = any(v and v.startswith(FAKEIP) for v in out["resolve"].values())
    text = local_ipconfig()
    for line in text.splitlines():
        low = line.lower()
        if "dns" in low:
            for ip in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", line):
                if ip not in out["local_dns"]:
                    out["local_dns"].append(ip)
    out["local_dns"] = out["local_dns"][:4]
    return out


def check_ipv6() -> dict:
    out = {"has_aaaa": False, "peer": None, "reachable": False, "error": None,
           "local_global": []}
    try:
        infos = socket.getaddrinfo("api6.ipify.org", 443, socket.AF_INET6,
                                   socket.SOCK_STREAM)
        if infos:
            out["has_aaaa"] = True
            out["peer"] = infos[0][4][0]
            with socket.create_connection((out["peer"], 443), timeout=4):
                out["reachable"] = True
    except OSError as exc:
        out["error"] = str(exc)

    text = local_ipconfig()
    for ip in re.findall(r"[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){3,}", text.lower()):
        try:
            addr = ipaddress.IPv6Address(ip)
        except ValueError:
            continue
        if addr.is_global and not addr.teredo and not addr.sixtofour \
                and str(addr) not in out["local_global"]:
            out["local_global"].append(str(addr))
    out["local_global"] = out["local_global"][:6]
    return out


# ---------------------------------------------------------------- layer 5

def check_egress() -> dict:
    out = {"ip": None, "answers": {}, "consistent": None, "geo": None, "error": None}
    sources = [
        ("ipify", "https://api.ipify.org?format=json", True),
        ("ifconfig.me", "https://ifconfig.me/ip", False),
        ("icanhazip", "https://icanhazip.com", False),
    ]
    hits = []
    for name, url, is_json in sources:
        try:
            raw = fetch_text(url, 8)
            value = json.loads(raw).get("ip") if is_json else raw
            value = (value or "").strip().splitlines()[0]
            if value:
                out["answers"][name] = value
                hits.append(value)
        except Exception as exc:
            out["answers"][name] = None
            out["error"] = str(exc)
    if hits:
        out["ip"] = max(set(hits), key=hits.count)
        out["consistent"] = len(set(hits)) == 1
    if out["ip"]:
        try:
            raw = fetch_text(
                f"http://ip-api.com/json/{out['ip']}"
                "?fields=status,country,regionName,city,isp,as,hosting", 6)
            data = json.loads(raw)
            if data.get("status") == "success":
                out["geo"] = data
        except Exception:
            pass
    return out


# ---------------------------------------------------------------- browser

class BrowserHandler(BaseHTTPRequestHandler):
    asset = ""
    payload: dict = {}
    done = threading.Event()

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            body = self.asset.encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        if self.path != "/result":
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 262144))
        try:
            BrowserHandler.payload = json.loads(raw.decode("utf-8"))
        except Exception:
            BrowserHandler.payload = {"error": "invalid_payload"}
        self._send(200, b'{"ok":true}', "application/json")
        BrowserHandler.done.set()

    def log_message(self, *args) -> None:
        pass


def check_webrtc(asset_path: Path, wait: int, open_browser: bool,
                 port: int = 0) -> dict:
    if not asset_path.exists():
        return {"available": False, "error": "asset_missing"}
    BrowserHandler.asset = asset_path.read_text(encoding="utf-8")
    BrowserHandler.done.clear()
    server = ThreadingHTTPServer(("127.0.0.1", port), BrowserHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if open_browser:
        webbrowser.open(f"http://127.0.0.1:{port}/")
    else:
        print(f"请在浏览器打开：http://127.0.0.1:{port}/")
    if not BrowserHandler.done.wait(wait):
        server.shutdown()
        return {"available": False, "error": "timeout", "port": port}
    server.shutdown()
    data = dict(BrowserHandler.payload)
    data["available"] = True
    return data


# ---------------------------------------------------------------- judgement

def judge(report: dict) -> dict:
    findings = []
    level = "CLEAN"
    egress = report["egress"]
    rtc = report["webrtc"]
    dns = report["dns"]
    v6 = report["ipv6"]
    proxy = report["system_proxy"]
    tun = report["tun"]

    if egress.get("consistent") is False:
        level = "LEAK"
        findings.append(("egress_split", "多个检测服务返回不同出口 IP，可能有流量绕过了代理。"))
    if not proxy.get("enabled") and not tun.get("present") and not report["listeners"]["any"]:
        level = "LEAK" if level == "LEAK" else "CAUTION"
        findings.append(("no_proxy", "系统代理、TUN、常见代理端口都没有生效迹象。"))

    if not rtc.get("available"):
        if level == "CLEAN":
            level = "CAUTION"
        findings.append(("no_webrtc", "浏览器层没有取到数据，WebRTC 结论未覆盖。"))
    else:
        host = rtc.get("hostReal") or []
        if host:
            level = "LEAK"
            findings.append(("rtc_host", f"WebRTC 直接报出了本机地址：{', '.join(host)}。"))
        if rtc.get("srflxMismatch"):
            level = "LEAK"
            findings.append(("rtc_srflx", "STUN 看到的出口与网页出口不一致。"))
        if rtc.get("srflxV6"):
            level = "LEAK"
            findings.append(("rtc_v6", "出现了 IPv6 的 STUN 反射地址。"))

    if v6.get("reachable"):
        if level == "CLEAN":
            level = "CAUTION"
        findings.append(("ipv6_open", "IPv6 可以出网，需确认它是否也走了代理。"))

    if not dns.get("fakeip") and not dns.get("local_dns"):
        if level == "CLEAN":
            level = "CAUTION"
        findings.append(("dns_plain", "没有看到 fake-ip 或本机 DNS，域名解析路径不明。"))

    return {"level": level, "findings": [{"code": c, "text": t} for c, t in findings]}


PLAIN = {
    "CLEAN": "没查到你泄露真实地址。网页请求和 WebRTC 报的是同一个出口，本机内网地址和 IPv6 都没有露出去。",
    "CAUTION": "没有发现明确泄露，但有项目没测到或存在风险点。下面逐条写明了哪些没覆盖。",
    "LEAK": "检测到泄露。你的真实地址或真实网络路径至少有一处被网站看到了。先按下面的修复步骤处理，再重测一次。",
}

FIX = {
    "egress_split": [
        "检查代理客户端是不是分了多个出口组，或者有规则把检测站走了直连。",
        "把 api.ipify.org、ifconfig.me、icanhazip.com 加入强制代理规则后重测。",
    ],
    "no_proxy": [
        "先确认代理客户端在运行。",
        "开启系统代理或 TUN 模式。TUN 能接管 UDP，只开系统代理管不到 WebRTC。",
    ],
    "no_webrtc": [
        "让 Agent 在你日常用的浏览器里重新跑一次检测页。干净浏览器配置测不出你日常环境的扩展影响。",
    ],
    "rtc_host": [
        "浏览器开启了真实地址上报。Chromium 系默认用 mDNS 混淆，出现真实地址说明被改过。",
        "安装 WebRTC Network Limiter 扩展，选择 disable_non_proxied_udp。",
        "检查 edge://flags 或 chrome://flags 里是否关掉了 WebRTC 地址混淆。",
    ],
    "rtc_srflx": [
        "STUN 流量没有走代理。开 TUN 模式，并确认客户端开启了 UDP 转发。",
        "只开系统代理时，HTTP 走代理，UDP 仍然直连。这是最常见的泄露原因。",
    ],
    "rtc_v6": [
        "关闭系统 IPv6，或者在代理客户端里让 IPv6 也走节点。",
        "确认 DNS 没有返回 AAAA 记录，否则浏览器会优先尝试 IPv6。",
    ],
    "ipv6_open": [
        "用 curl -6 https://api6.ipify.org 确认 IPv6 出口是节点还是本地宽带。",
        "如果是本地宽带，关闭 IPv6，或在客户端里启用 IPv6 转发。",
    ],
    "dns_plain": [
        "开启代理客户端的 DNS 接管，多数客户端提供 fake-ip 模式。",
        "把系统 DNS 指向本机代理端口，避免明文 DNS 直连。",
    ],
}

NEXT_STEP = (
    "把 report.json 和下面这段话一起发给任意 AI，让它用大白话解释：\n"
    "「这是我代理环境体检的结构化结果。请用非技术语言告诉我：一、我有没有泄露真实 IP；"
    "二、如果有，是哪一层漏的；三、我该改哪几个设置。不要复述字段名，直接说人话。」"
)


def render(report: dict, verdict: dict) -> str:
    egress = report["egress"]
    rtc = report["webrtc"]
    dns = report["dns"]
    v6 = report["ipv6"]
    proxy = report["system_proxy"]
    tun = report["tun"]
    geo = egress.get("geo") or {}

    mark = {"CLEAN": "通过", "CAUTION": "待确认", "LEAK": "不通过"}
    lines = []
    add = lines.append

    add("# 代理环境体检报告")
    add("")
    add(f"生成时间：{report['generated_at']}　　主机：{report['host']}")
    add("")

    add("## 一、原始检测结果")
    add("")
    add("| 检查项 | 实测值 | 状态 |")
    add("| --- | --- | --- |")
    ip_text = egress.get("ip") or "未取到"
    if geo.get("country"):
        ip_text += f"（{geo.get('country')} {geo.get('city') or ''} {geo.get('isp') or ''}）".replace("  ", " ")
    add(f"| 出口 IP | `{ip_text}` | {'已代理' if egress.get('ip') else '未取到'} |")
    add(f"| 出口一致性 | {'三个服务一致' if egress.get('consistent') else '不一致或部分失败'} | "
        f"{'通过' if egress.get('consistent') else '待确认'} |")

    if rtc.get("available"):
        srflx = ", ".join(rtc.get("srflxV4") or []) or "无"
        host = ", ".join(rtc.get("hostReal") or []) or "未暴露"
        add(f"| WebRTC 反射地址 | `{srflx}` | "
            f"{'不通过' if rtc.get('srflxMismatch') else '通过'} |")
        add(f"| WebRTC 主机地址 | `{host}` | {'不通过' if rtc.get('hostReal') else '通过'} |")
        add(f"| mDNS 混淆 | {rtc.get('mdnsCount', 0)} 条随机名 | "
            f"{'生效' if rtc.get('mdnsCount') else '未生效'} |")
    else:
        add("| WebRTC | 未取到数据 | 待确认 |")

    add(f"| IPv6 出网 | {'可出网' if v6.get('reachable') else '不可用'} | "
        f"{'待确认' if v6.get('reachable') else '通过'} |")
    add(f"| 本地公网 IPv6 | {len(v6.get('local_global') or [])} 个 | 信息 |")
    add(f"| DNS 接管 | {'fake-ip' if dns.get('fakeip') else '未见 fake-ip'} | "
        f"{'通过' if dns.get('fakeip') else '待确认'} |")
    add(f"| TUN 网卡 | {tun.get('name') or '未发现'} | {'通过' if tun.get('present') else '待确认'} |")
    add(f"| 系统代理 | {proxy.get('server') or '未开启'} | "
        f"{'通过' if proxy.get('enabled') else '待确认'} |")
    add(f"| 本地监听端口 | {', '.join(str(p) for p in report['listeners']['listening']) or '无'} | 信息 |")
    add("")

    add("## 二、判定")
    add("")
    add(f"**总体结论：{verdict['level']}**（{'干净' if verdict['level'] == 'CLEAN' else '需处理'}）")
    add("")
    if verdict["findings"]:
        for item in verdict["findings"]:
            add(f"- {item['text']}")
    else:
        add("- 五项检查全部通过，没有发现泄露路径。")
    add("")

    add("## 三、结论解读")
    add("")
    add(PLAIN[verdict["level"]])
    add("")
    if verdict["level"] == "CLEAN":
        add("具体的判断依据有三条：")
        add("")
        add(f"1. 网页请求和 WebRTC 报的是同一个地址 `{egress.get('ip')}`，说明 STUN 也被代理接管了。")
        add(f"2. 浏览器只报出 {rtc.get('mdnsCount', 0)} 条随机主机名，没有出现你的内网地址。")
        add("3. IPv6 这条路不通，或者被 DNS 层挡掉了，所以没有第二条溢出通道。")
        add("")
        add("换句话说：网站看到的是你的节点，看不到你的真实位置。")
    elif verdict["level"] == "CAUTION":
        add("上面列出的项目没有测到，所以判不了。")
        add("")
        add("目前没有看到一个明确的问题，但不等于一定干净。补齐这些项目后再跑一次，才能给出确定结论。")
    else:
        add("上面列出的项目已经确认出问题，每一处都能让网站看到你的真实地址。")
        add("")
        add("按第四节的步骤逐条处理，改完再跑一次本检测。")
    add("")

    if verdict["findings"]:
        add("## 四、修复步骤")
        add("")
        for item in verdict["findings"]:
            steps = FIX.get(item["code"], [])
            if not steps:
                continue
            add(f"**{item['text']}**")
            add("")
            for step in steps:
                add(f"- {step}")
            add("")
    else:
        add("## 四、修复步骤")
        add("")
        add("不需要修复。保持当前配置即可。")
        add("")
        add("要长期保持干净，注意两件事：")
        add("")
        add("- 不要频繁切换节点。出口国家跳变本身就是异常信号。")
        add("- 代理客户端更新后重新跑一次本检测，确认 TUN 和 DNS 还在工作。")
        add("")

    add("## 五、交给其他 Agent")
    add("")
    add(NEXT_STEP)
    add("")
    add("结构化结果已写入同目录的 `report.json`。")
    add("")
    return "\n".join(lines)


# ---------------------------------------------------------------- main

def main() -> int:
    parser = argparse.ArgumentParser(description="代理环境体检")
    parser.add_argument("--out", default="audit-report", help="报告输出目录")
    parser.add_argument("--no-browser", action="store_true", help="跳过浏览器层检测")
    parser.add_argument("--no-open", action="store_true", help="不自动打开浏览器，只打印地址")
    parser.add_argument("--port", type=int, default=0, help="检测页监听端口，默认随机")
    parser.add_argument("--wait", type=int, default=75, help="等待浏览器返回的秒数")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    asset = root / "assets" / "browser-check.html"

    print("正在检查：出口 IP、系统代理、TUN、DNS、IPv6 …")
    report = {
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "platform": sys.platform,
        "system_proxy": check_system_proxy(),
        "tun": check_tun(),
        "dns": check_dns(),
        "ipv6": check_ipv6(),
        "egress": check_egress(),
    }
    report["listeners"] = check_listeners(report["system_proxy"])

    if args.no_browser:
        report["webrtc"] = {"available": False, "error": "skipped"}
    else:
        print("正在打开浏览器做 WebRTC 检测，测完会自动关闭 …")
        report["webrtc"] = check_webrtc(asset, args.wait, not args.no_open, args.port)
        if not report["webrtc"].get("available"):
            print(f"浏览器层未返回结果（{report['webrtc'].get('error')}），继续生成系统层报告。")

    verdict = judge(report)
    text = render(report, verdict)

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(
        json.dumps({"report": report, "verdict": verdict}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    (out_dir / "report.md").write_text(text, encoding="utf-8")

    print()
    print(text)
    print()
    print(f"报告已保存：{out_dir}")
    return 0 if verdict["level"] == "CLEAN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
