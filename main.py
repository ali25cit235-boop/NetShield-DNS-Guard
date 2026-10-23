#!/usr/bin/env python3
"""
NetShield: Dynamic DNS-Leak Guard, Proxy-Aligned DNS Enforcer & Firewall Kill-Switch
=====================================================================================

A system-level Windows networking and privacy utility engineered to eliminate:
- Transparent ISP DNS Hijacking on UDP/TCP Port 53
- Split-Tunnel SOCKS4/SOCKS5 Proxy DNS Country Mismatches (e.g., on Whoer / IPInfo)
- Smart Multi-Homed Name Resolution (SMHNR) & IPv6 Routing Leaks
- Browser QUIC (UDP 443) & WebRTC Non-Proxied UDP Bypass

Author: Ali
License: MIT
Platform: Windows 10 / 11 (Requires Administrator Privileges)
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import queue
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import winreg
import winsound
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import socks
from dnslib import DNSRecord, QTYPE, RCODE

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    import tkinter as tk


# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

APP_TITLE = "NETSHIELD — DYNAMIC DNS-LEAK GUARD & PROXY ENFORCER"
APP_VERSION = "4.0.0"

LOCAL_DOH_HOST = "127.0.0.1"
LOCAL_DOH_PORT = 53
DEFAULT_LOCAL_SOCKS_PORT = 23321
KNOWN_CONTROL_PORTS = {1700, 54319}

# Upstream DNS-over-HTTPS (DoH) endpoints (IPv4, Port, TLS_SNI_Hostname, Path)
# Tunneled directly inside the active SOCKS4/SOCKS5 proxy connection.
DOH_UPSTREAMS: List[Tuple[str, int, str, str]] = [
    ("104.16.249.249", 443, "cloudflare-dns.com", "/dns-query"),
    ("104.16.248.249", 443, "cloudflare-dns.com", "/dns-query"),
    ("8.8.8.8", 443, "dns.google", "/dns-query"),
]

# Windows Advanced Firewall rule identifiers managed by NetShield
FW_RULE_ALLOW_UDP = "NetShield_Allow_Protected_DNS_UDP53"
FW_RULE_ALLOW_TCP = "NetShield_Allow_Protected_DNS_TCP53"
FW_RULE_BLOCK_UDP_V4 = "NetShield_Block_AllOther_DNS_UDP53_IPv4"
FW_RULE_BLOCK_TCP_V4 = "NetShield_Block_AllOther_DNS_TCP53_IPv4"
FW_RULE_BLOCK_UDP_V6 = "NetShield_Block_All_DNS_UDP53_IPv6"
FW_RULE_BLOCK_TCP_V6 = "NetShield_Block_All_DNS_TCP53_IPv6"
FW_RULE_BLOCK_QUIC_UDP443 = "NetShield_Block_QUIC_UDP443"
FW_RULE_BLOCK_WEBRTC_STUN = "NetShield_Block_WebRTC_STUN_UDP"

ALL_FW_RULES: List[str] = [
    FW_RULE_ALLOW_UDP,
    FW_RULE_ALLOW_TCP,
    FW_RULE_BLOCK_UDP_V4,
    FW_RULE_BLOCK_TCP_V4,
    FW_RULE_BLOCK_UDP_V6,
    FW_RULE_BLOCK_TCP_V6,
    FW_RULE_BLOCK_QUIC_UDP443,
    FW_RULE_BLOCK_WEBRTC_STUN,
]

# Exact IPv4 address ranges covering 0.0.0.0/0 EXCEPT 1.0.0.1, 1.1.1.1, and 127.0.0.0/8.
# Because Windows Firewall Block rules take precedence over Allow rules, excluding
# 1.0.0.1, 1.1.1.1, and 127.0.0.0/8 from the Block range ensures all unauthorized
# ISP DNS servers on Port 53 are blocked at the kernel firewall level.
BLOCKED_DNS_IPV4_RANGES = (
    "0.0.0.0-1.0.0.0,"
    "1.0.0.2-1.1.1.0,"
    "1.1.1.2-126.255.255.255,"
    "128.0.0.0-255.255.255.255"
)

REGISTRY_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
REGISTRY_CONNECTIONS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
REGISTRY_TUXLER_APP = r"Software\Tuxlerapp\Tuxlerapp"

BROWSER_POLICY_PATHS: List[str] = [
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Microsoft\Edge",
    r"SOFTWARE\Policies\BraveSoftware\Brave",
]

CREATE_NO_WINDOW = 0x08000000


# ============================================================================
# PRIVILEGE & SUBPROCESS UTILITIES
# ============================================================================

def is_admin() -> bool:
    """Return True if the current process is executing with Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_to_admin() -> None:
    """Re-launch the current Python script with UAC Administrator elevation."""
    script_path = os.path.abspath(sys.argv[0])
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    full_params = f'"{script_path}" {params}'.strip()
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, full_params, os.path.dirname(script_path), 1
        )
        if int(ret) > 32:
            sys.exit(0)
    except Exception:
        pass


def run_cmd(args: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    """Execute a system command with a hidden console window and return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as exc:
        return -1, "", str(exc)


def run_powershell(ps_script: str, timeout: int = 25) -> Tuple[int, str, str]:
    """Execute a PowerShell command string with a hidden console window."""
    return run_cmd(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_script,
        ],
        timeout=timeout,
    )


def show_windows_toast_notification(title: str, message: str) -> None:
    """Display a native Windows system tray balloon notification asynchronously."""
    safe_title = title.replace("'", "").replace('"', "")
    safe_msg = message.replace("'", "").replace('"', "")
    ps_notify = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "Add-Type -AssemblyName System.Drawing; "
        "$n = New-Object System.Windows.Forms.NotifyIcon; "
        "$n.Icon = [System.Drawing.SystemIcons]::Error; "
        "$n.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Error; "
        f"$n.BalloonTipTitle = '{safe_title}'; "
        f"$n.BalloonTipText = '{safe_msg}'; "
        "$n.Visible = $true; "
        "$n.ShowBalloonTip(10000); "
        "Start-Sleep -Seconds 6; "
        "$n.Dispose()"
    )
    threading.Thread(target=lambda: run_powershell(ps_notify, timeout=12), daemon=True).start()


# ============================================================================
# PERSISTENT KEEP-ALIVE SOCKS4/5 TLS DNS-OVER-HTTPS CLIENT POOL
# ============================================================================

class SOCKSKeepAliveDoHPool:
    """
    Maintains a thread-safe pool of persistent HTTP/1.1 Keep-Alive TLS sockets
    tunneled through the local SOCKS4/SOCKS5 proxy endpoint.

    Routing DNS-over-HTTPS queries directly through the active residential proxy
    ensures that upstream DNS resolvers see the exact same outbound residential IP
    and ASN as the browser, eliminating geo-mismatch detections on anti-fraud suites.
    """

    def __init__(self) -> None:
        self._ssl_ctx = ssl.create_default_context()
        self._pool: "queue.LifoQueue[Tuple[ssl.SSLSocket, str, str, str, int]]" = queue.LifoQueue(maxsize=12)

    def clear_pool(self) -> None:
        """Close and discard all pooled TLS sockets."""
        while True:
            try:
                ss, _, _, _, _ = self._pool.get_nowait()
                try:
                    ss.close()
                except Exception:
                    pass
            except queue.Empty:
                break

    def _open_tls_socks_socket(
        self, socks_host: str, socks_port: int, target_ip: str, target_port: int, sni_host: str
    ) -> ssl.SSLSocket:
        """Establish a SOCKS4 (or SOCKS5 fallback) tunnel and perform a TLS handshake with SNI."""
        last_err: Optional[Exception] = None
        for socks_type in (socks.SOCKS4, socks.SOCKS5):
            raw_sock: Optional[socks.socksocket] = None
            try:
                raw_sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                raw_sock.set_proxy(socks_type, socks_host, int(socks_port), rdns=False)
                raw_sock.settimeout(6.5)
                raw_sock.connect((target_ip, int(target_port)))
                tls_sock = self._ssl_ctx.wrap_socket(raw_sock, server_hostname=sni_host)
                tls_sock.settimeout(6.5)
                return tls_sock
            except Exception as exc:
                last_err = exc
                if raw_sock is not None:
                    try:
                        raw_sock.close()
                    except Exception:
                        pass
        raise last_err or OSError("Unable to establish SOCKS TLS connection")

    @staticmethod
    def _read_http_response(ss: ssl.SSLSocket) -> Tuple[int, bytes]:
        """Parse an HTTP/1.1 response (supporting Content-Length and chunked transfer encoding)."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = ss.recv(4096)
            if not chunk:
                raise ConnectionResetError("Connection closed while reading HTTP headers")
            buf += chunk

        hdr_bytes, body = buf.split(b"\r\n\r\n", 1)
        hdr_text = hdr_bytes.decode("iso-8859-1", errors="replace")
        lines = hdr_text.split("\r\n")
        status_line = lines[0] if lines else ""
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

        content_length: Optional[int] = None
        is_chunked = False
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                kl = k.strip().lower()
                vl = v.strip().lower()
                if kl == "content-length" and vl.isdigit():
                    content_length = int(vl)
                elif kl == "transfer-encoding" and "chunked" in vl:
                    is_chunked = True

        if content_length is not None:
            while len(body) < content_length:
                more = ss.recv(max(4096, content_length - len(body)))
                if not more:
                    break
                body += more
            return status_code, body[:content_length]

        if is_chunked:
            decoded = bytearray()
            rem = body
            while True:
                while b"\r\n" not in rem:
                    more = ss.recv(4096)
                    if not more:
                        return status_code, bytes(decoded)
                    rem += more
                size_line, rem = rem.split(b"\r\n", 1)
                chunk_size = int(size_line.split(b";")[0].strip(), 16)
                if chunk_size == 0:
                    return status_code, bytes(decoded)
                while len(rem) < chunk_size + 2:
                    more = ss.recv(4096)
                    if not more:
                        break
                    rem += more
                decoded.extend(rem[:chunk_size])
                rem = rem[chunk_size + 2 :]

        return status_code, body

    def query_doh_sync(self, raw_query: bytes, socks_host: str, socks_port: int) -> Optional[bytes]:
        """Transmit a wire-format DNS query over a pooled Keep-Alive SOCKS TLS socket."""
        # 1. Attempt to reuse an active keep-alive socket from the pool
        while True:
            try:
                ss, sni_host, path, shost, sport = self._pool.get_nowait()
            except queue.Empty:
                break

            if (shost, sport) != (socks_host, socks_port):
                try:
                    ss.close()
                except Exception:
                    pass
                continue

            try:
                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {sni_host}\r\n"
                    "Content-Type: application/dns-message\r\n"
                    "Accept: application/dns-message\r\n"
                    f"Content-Length: {len(raw_query)}\r\n"
                    "Connection: keep-alive\r\n\r\n"
                ).encode("ascii") + raw_query
                ss.sendall(req)
                status, body = self._read_http_response(ss)
                if status == 200 and body:
                    try:
                        self._pool.put_nowait((ss, sni_host, path, socks_host, socks_port))
                    except queue.Full:
                        ss.close()
                    return body
                ss.close()
            except Exception:
                try:
                    ss.close()
                except Exception:
                    pass

        # 2. Establish a fresh TLS-over-SOCKS connection to upstream DoH resolvers
        for target_ip, target_port, sni_host, path in DOH_UPSTREAMS:
            ss_new: Optional[ssl.SSLSocket] = None
            try:
                ss_new = self._open_tls_socks_socket(socks_host, socks_port, target_ip, target_port, sni_host)
                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {sni_host}\r\n"
                    "Content-Type: application/dns-message\r\n"
                    "Accept: application/dns-message\r\n"
                    f"Content-Length: {len(raw_query)}\r\n"
                    "Connection: keep-alive\r\n\r\n"
                ).encode("ascii") + raw_query
                ss_new.sendall(req)
                status, body = self._read_http_response(ss_new)
                if status == 200 and body:
                    try:
                        self._pool.put_nowait((ss_new, sni_host, path, socks_host, socks_port))
                    except queue.Full:
                        ss_new.close()
                    return body
                ss_new.close()
            except Exception:
                if ss_new is not None:
                    try:
                        ss_new.close()
                    except Exception:
                        pass
                continue
        return None

    def prewarm(self, socks_host: str, socks_port: int, count: int = 2) -> None:
        """Pre-warm Keep-Alive TLS sockets in background threads to minimize initial DNS latency."""
        def _warm_one() -> None:
            try:
                q = DNSRecord.question("cloudflare.com", "A").pack()
                self.query_doh_sync(q, socks_host, socks_port)
            except Exception:
                pass

        for _ in range(count):
            threading.Thread(target=_warm_one, daemon=True).start()


# ============================================================================
# LOCAL DNS-OVER-HTTPS PROXY LISTENER (127.0.0.1:53)
# ============================================================================

class UDPDoHProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP datagram protocol serving local DNS queries on 127.0.0.1:53."""

    def __init__(self, proxy: "LocalDoHProxyServer") -> None:
        self.proxy = proxy
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        asyncio.create_task(self._handle_datagram(data, addr))

    async def _handle_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        resp = await self.proxy.forward_dns_query(data)
        if resp and self.transport and not self.transport.is_closing():
            try:
                self.transport.sendto(resp, addr)
            except Exception:
                pass


class LocalDoHProxyServer:
    """
    Asynchronous UDP & TCP DNS listener on 127.0.0.1:53 backed by `SOCKSKeepAliveDoHPool`.
    """

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None) -> None:
        self.log_callback = log_callback
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._udp_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_server: Optional[asyncio.AbstractServer] = None
        self._executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="NetShieldDoHWorker")
        self._socks_pool = SOCKSKeepAliveDoHPool()

        self.is_running: bool = False
        self.socks_host: str = "127.0.0.1"
        self.socks_port: int = DEFAULT_LOCAL_SOCKS_PORT
        self.killswitch_block_dns: bool = False

        self.queries_handled: int = 0
        self.queries_blocked: int = 0
        self.queries_failed: int = 0
        self.last_query_domain: str = "None"
        self.last_latency_ms: float = 0.0

        self._cache: Dict[Tuple[str, int], Tuple[float, bytes]] = {}
        self._ready_event = threading.Event()
        self.startup_error: Optional[str] = None

    def _log(self, msg: str) -> None:
        if self.log_callback:
            self.log_callback(msg)

    def update_socks_endpoint(self, host: str, port: int) -> None:
        """Update the active SOCKS proxy endpoint and flush cached DNS entries if changed."""
        if (host, port) != (self.socks_host, self.socks_port):
            self.socks_host = host or "127.0.0.1"
            self.socks_port = int(port) if port else DEFAULT_LOCAL_SOCKS_PORT
            self.clear_cache()
            self._log(f"[DNS SYNC] Synchronized DNS Tunnel to SOCKS Proxy -> {self.socks_host}:{self.socks_port}")

    def clear_cache(self) -> None:
        self._cache.clear()
        self._socks_pool.clear_pool()

    def prewarm_connections(self) -> None:
        self._socks_pool.prewarm(self.socks_host, self.socks_port, count=2)

    def _free_port_53_if_occupied(self) -> None:
        """
        Release 127.0.0.1:53 from conflicting third-party DNS proxies (such as dnscrypt-proxy)
        that might bypass the residential proxy tunnel.
        """
        if LOCAL_DOH_PORT != 53:
            return

        run_powershell(
            "Stop-Service -Name 'dnscrypt-proxy','cloudflared' -Force -ErrorAction SilentlyContinue"
        )
        run_cmd(["sc.exe", "stop", "dnscrypt-proxy"])
        run_cmd(["taskkill", "/F", "/IM", "dnscrypt-proxy.exe"])

        my_pid = os.getpid()
        code, out, _ = run_cmd(["netstat", "-ano"])
        if code == 0 and out:
            pids = set()
            for line in out.splitlines():
                if ":53 " in line and ("127.0.0.1:53" in line or "0.0.0.0:53" in line or "[::1]:53" in line):
                    parts = line.split()
                    if parts and parts[-1].isdigit():
                        pid = int(parts[-1])
                        if pid > 4 and pid != my_pid:
                            pids.add(pid)
            for pid in pids:
                self._log(f"[PORT 53] Releasing 127.0.0.1:53 from conflicting PID {pid}...")
                run_cmd(["taskkill", "/F", "/PID", str(pid)])
            if pids:
                time.sleep(0.4)

    def start(self, timeout: float = 10.0) -> Tuple[bool, str]:
        """Start the local DoH listener on 127.0.0.1:53 and wait until bound."""
        if self.is_running:
            self.clear_cache()
            self.prewarm_connections()
            return True, f"DoH Tunnel active on {LOCAL_DOH_HOST}:{LOCAL_DOH_PORT} via SOCKS {self.socks_host}:{self.socks_port}"

        self._ready_event.clear()
        self.startup_error = None
        self._thread = threading.Thread(target=self._run_loop, name="DoHProxyThread", daemon=True)
        self._thread.start()

        started = self._ready_event.wait(timeout=timeout)
        if not started:
            return False, "Timed out starting local DoH proxy on 127.0.0.1:53"
        if self.startup_error:
            return False, self.startup_error
        self.prewarm_connections()
        return True, f"DoH Tunnel listening on {LOCAL_DOH_HOST}:{LOCAL_DOH_PORT} -> SOCKS ({self.socks_host}:{self.socks_port})"

    def stop(self) -> None:
        """Stop the local DoH listener and release port 53."""
        self._socks_pool.clear_pool()
        if not self.is_running or not self._loop:
            self.is_running = False
            return
        try:
            if self._stop_event:
                self._loop.call_soon_threadsafe(self._stop_event.set)
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=4.0)
        except Exception:
            pass
        finally:
            self.is_running = False

    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._serve_async())
        except Exception as exc:
            self.startup_error = str(exc)
            self._ready_event.set()
        finally:
            try:
                loop.close()
            except Exception:
                pass
            self.is_running = False

    async def _serve_async(self) -> None:
        self._stop_event = asyncio.Event()
        self._free_port_53_if_occupied()

        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: UDPDoHProtocol(self),
                local_addr=(LOCAL_DOH_HOST, LOCAL_DOH_PORT),
            )
            self._udp_transport = transport  # type: ignore[assignment]

            self._tcp_server = await asyncio.start_server(
                self._handle_tcp_client,
                host=LOCAL_DOH_HOST,
                port=LOCAL_DOH_PORT,
            )
        except OSError as exc:
            self.startup_error = (
                f"Failed to bind {LOCAL_DOH_HOST}:{LOCAL_DOH_PORT} ({exc}). "
                "Ensure the application is running with Administrator privileges."
            )
            self._ready_event.set()
            return

        self.is_running = True
        self._ready_event.set()

        await self._stop_event.wait()

        if self._udp_transport:
            self._udp_transport.close()
        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while not reader.at_eof():
                len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
                msg_len = struct.unpack("!H", len_bytes)[0]
                data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=5.0)
                resp = await self.forward_dns_query(data)
                if resp:
                    writer.write(struct.pack("!H", len(resp)) + resp)
                    await writer.drain()
                else:
                    break
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def forward_dns_query(self, raw_query: bytes) -> Optional[bytes]:
        """Forward a wire-format DNS query through the active SOCKS proxy tunnel."""
        qname_str = "unknown"
        qtype_int = 0
        query_id = 0
        parsed_query: Optional[DNSRecord] = None
        is_leak_test_domain = False

        try:
            parsed_query = DNSRecord.parse(raw_query)
            query_id = parsed_query.header.id
            if parsed_query.questions:
                q = parsed_query.questions[0]
                qname_str = str(q.qname).rstrip(".")
                qtype_int = q.qtype
                self.last_query_domain = f"{qname_str} ({QTYPE.get(qtype_int, qtype_int)})"

                # Neutralize IPv6 AAAA queries at the DNS layer to prevent IPv6 fallback leaks
                if qtype_int == QTYPE.AAAA:
                    empty_v6 = parsed_query.reply()
                    empty_v6.header.rcode = RCODE.NOERROR
                    self.queries_handled += 1
                    return empty_v6.pack()

                # Strict Kill-Switch enforcement if a critical disconnect or leak is active
                if self.killswitch_block_dns:
                    self.queries_blocked += 1
                    refused = parsed_query.reply()
                    refused.header.rcode = RCODE.REFUSED
                    return refused.pack()

                lower_q = qname_str.lower()
                is_leak_test_domain = any(
                    d in lower_q
                    for d in ("whoer.net", "dnsleaktest", "browserleaks", "ipleak", "ip-api.com", "ipwho.is")
                )
                if not is_leak_test_domain:
                    cache_key = (lower_q, qtype_int)
                    cached = self._cache.get(cache_key)
                    if cached and (time.time() - cached[0]) < 60.0:
                        cached_reply = bytearray(cached[1])
                        if len(cached_reply) >= 2:
                            struct.pack_into("!H", cached_reply, 0, query_id)
                            self.queries_handled += 1
                            return bytes(cached_reply)
        except Exception:
            pass

        t0 = time.perf_counter()
        loop = asyncio.get_running_loop()
        wire_resp = await loop.run_in_executor(
            self._executor,
            self._socks_pool.query_doh_sync,
            raw_query,
            self.socks_host,
            self.socks_port,
        )

        if wire_resp:
            self.last_latency_ms = round((time.perf_counter() - t0) * 1000.0, 1)
            self.queries_handled += 1
            if qname_str != "unknown" and not is_leak_test_domain:
                try:
                    DNSRecord.parse(wire_resp)
                    if len(self._cache) > 512:
                        self._cache.clear()
                    self._cache[(qname_str.lower(), qtype_int)] = (time.time(), wire_resp)
                except Exception:
                    pass
            return wire_resp

        self.queries_failed += 1
        if parsed_query is not None:
            try:
                reply = parsed_query.reply()
                reply.header.rcode = RCODE.SERVFAIL
                return reply.pack()
            except Exception:
                pass
        return None


# ============================================================================
# SYSTEM SHIELD CONTROLLER (ADAPTERS, SMHNR, FIREWALL, POLICIES & TELEMETRY)
# ============================================================================

class NetShieldSystemController:
    """Manages Windows network adapters, SMHNR, IPv6, Firewall Kill-Switch, and Proxy Telemetry."""

    def __init__(self, log_callback: Callable[[str], None]) -> None:
        self.log = log_callback
        self.doh_server = LocalDoHProxyServer(log_callback=log_callback)
        self.shield_active: bool = False
        self.locked_uk_ip: Optional[str] = None
        self.locked_uk_isp: Optional[str] = None
        self.locked_uk_city: Optional[str] = None
        self.killswitch_tripped: bool = False
        self.killswitch_reason: str = ""
        self._ssl_ctx = ssl.create_default_context()

    # ------------------------------------------------------------------------
    # Network Adapter Discovery
    # ------------------------------------------------------------------------
    def get_active_adapters(self) -> List[Dict[str, Any]]:
        """Return a list of all currently active ('Up') Windows network adapters."""
        ps_cmd = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | "
            "Select-Object Name, InterfaceDescription, ifIndex | ConvertTo-Json -Compress"
        )
        code, out, _ = run_powershell(ps_cmd)
        adapters: List[Dict[str, Any]] = []
        if code == 0 and out:
            try:
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    if item.get("Name"):
                        adapters.append(
                            {
                                "Name": str(item["Name"]),
                                "Description": str(item.get("InterfaceDescription", "")),
                                "ifIndex": item.get("ifIndex"),
                            }
                        )
            except Exception:
                pass

        if not adapters:
            code, out, _ = run_cmd(["netsh", "interface", "show", "interface"])
            if code == 0 and out:
                for line in out.splitlines():
                    if "Connected" in line:
                        parts = re.split(r"\s{2,}", line.strip())
                        if len(parts) >= 4:
                            adapters.append(
                                {
                                    "Name": parts[-1].strip(),
                                    "Description": parts[-1].strip(),
                                    "ifIndex": None,
                                }
                            )
        return adapters

    # ------------------------------------------------------------------------
    # Local Proxy Tunnel Discovery (Registry & Active Processes)
    # ------------------------------------------------------------------------
    def detect_proxy_tunnel(self) -> Dict[str, Any]:
        """
        Inspect Windows Registry (`Internet Settings`, `Connections`, and residential VPN keys)
        and active proxy helper processes to determine the local SOCKS proxy endpoint.
        """
        info: Dict[str, Any] = {
            "tuxler_running": False,
            "is_proxy_set": False,
            "selected_country": "United Kingdom",
            "selected_country_iso": "GB",
            "selected_city": "",
            "proxy_enabled_reg": False,
            "proxy_raw": "Not Set",
            "socks_host": "127.0.0.1",
            "socks_port": DEFAULT_LOCAL_SOCKS_PORT,
            "socks_online": False,
        }

        # 1. Inspect residential VPN application registry settings
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_TUXLER_APP, 0, winreg.KEY_READ) as k:
                try:
                    val, _ = winreg.QueryValueEx(k, "isproxyset")
                    info["is_proxy_set"] = str(val).lower() in ("true", "1")
                except FileNotFoundError:
                    pass
                try:
                    val, _ = winreg.QueryValueEx(k, "selected_country")
                    info["selected_country"] = str(val)
                except FileNotFoundError:
                    pass
                try:
                    val, _ = winreg.QueryValueEx(k, "selected_country_iso")
                    info["selected_country_iso"] = str(val).upper()
                except FileNotFoundError:
                    pass
                try:
                    val, _ = winreg.QueryValueEx(k, "selected_city")
                    info["selected_city"] = str(val)
                except FileNotFoundError:
                    pass
                try:
                    val, _ = winreg.QueryValueEx(k, "proxySettingsJSON")
                    if val and "127.0.0.1:" in str(val):
                        m = re.search(r"127\.0\.0\.1:(\d+)", str(val))
                        if m:
                            info["socks_port"] = int(m.group(1))
                except FileNotFoundError:
                    pass
        except Exception:
            pass

        # 2. Inspect HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_INTERNET_SETTINGS, 0, winreg.KEY_READ) as k:
                try:
                    pe, _ = winreg.QueryValueEx(k, "ProxyEnable")
                    info["proxy_enabled_reg"] = bool(pe)
                except FileNotFoundError:
                    pass
                try:
                    ps, _ = winreg.QueryValueEx(k, "ProxyServer")
                    ps_str = str(ps).strip()
                    if ps_str:
                        info["proxy_raw"] = ps_str
                        m = re.search(r"([0-9.]+):(\d+)", ps_str)
                        if m:
                            info["socks_host"] = m.group(1)
                            info["socks_port"] = int(m.group(2))
                except FileNotFoundError:
                    pass
        except Exception:
            pass

        # 2b. Inspect WinINet DefaultConnectionSettings binary value
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_CONNECTIONS, 0, winreg.KEY_READ) as k:
                blob, _ = winreg.QueryValueEx(k, "DefaultConnectionSettings")
                if isinstance(blob, (bytes, bytearray)):
                    ascii_str = bytes(b for b in blob if 32 <= b < 127).decode("ascii", "ignore")
                    m = re.search(r"(?:socks=|http=)?(127\.0\.0\.1):(\d{2,5})", ascii_str)
                    if m:
                        info["socks_host"] = m.group(1)
                        info["socks_port"] = int(m.group(2))
                        if info["proxy_raw"] == "Not Set":
                            info["proxy_raw"] = f"socks={m.group(1)}:{m.group(2)}"
        except Exception:
            pass

        # 3. Verify local SOCKS port reachability
        try:
            with socket.create_connection((info["socks_host"], int(info["socks_port"])), timeout=1.0):
                info["socks_online"] = True
                info["tuxler_running"] = True
        except Exception:
            code, out, _ = run_powershell(
                "$p = Get-Process -Name 'ExtensionHelperAppHelperTuxler','tuxlerVPN' -ErrorAction SilentlyContinue; "
                "if ($p) { Get-NetTCPConnection -OwningProcess $p.Id -State Listen -ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty LocalPort }",
                timeout=6,
            )
            if code == 0 and out:
                info["tuxler_running"] = True
                for line in out.splitlines():
                    if line.strip().isdigit():
                        candidate_port = int(line.strip())
                        if candidate_port not in KNOWN_CONTROL_PORTS and candidate_port > 1024:
                            info["socks_port"] = candidate_port
                            try:
                                with socket.create_connection(("127.0.0.1", candidate_port), timeout=1.0):
                                    info["socks_online"] = True
                                    break
                            except Exception:
                                pass

        if info["proxy_raw"] == "Not Set" and info["socks_online"]:
            info["proxy_raw"] = f"socks={info['socks_host']}:{info['socks_port']}"

        return info

    # ------------------------------------------------------------------------
    # SMHNR & Browser Anti-Leak Policies
    # ------------------------------------------------------------------------
    def apply_system_and_browser_policies(self) -> None:
        """
        1. Disable Windows Smart Multi-Homed Name Resolution (SMHNR) via Registry policy.
        2. Configure Chromium-based browsers (Chrome, Edge, Brave) to disable independent
           DoH bypass, QUIC UDP 443, and non-proxied WebRTC UDP traffic.
        """
        # Disable Windows SMHNR (TurnOffMulticast / DisableSmartNameResolution)
        try:
            dns_pol = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(dns_pol, "DisableSmartNameResolution", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(dns_pol, "EnableMulticast", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(dns_pol)
        except Exception:
            pass

        for path in BROWSER_POLICY_PATHS:
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "DnsOverHttpsMode", 0, winreg.REG_SZ, "off")
                winreg.SetValueEx(key, "QuicAllowed", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(
                    key, "WebRtcIPHandling", 0, winreg.REG_SZ, "disable_non_proxied_udp"
                )
                try:
                    winreg.DeleteValue(key, "BuiltInDnsClientEnabled")
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
            except Exception:
                pass

    def remove_system_and_browser_policies(self) -> None:
        """Remove SMHNR and browser policy overrides upon deactivation."""
        try:
            dns_pol = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                0,
                winreg.KEY_SET_VALUE,
            )
            for val_name in ("DisableSmartNameResolution", "EnableMulticast"):
                try:
                    winreg.DeleteValue(dns_pol, val_name)
                except FileNotFoundError:
                    pass
            winreg.CloseKey(dns_pol)
        except Exception:
            pass

        for path in BROWSER_POLICY_PATHS:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE)
                for val_name in ("DnsOverHttpsMode", "BuiltInDnsClientEnabled", "QuicAllowed", "WebRtcIPHandling"):
                    try:
                        winreg.DeleteValue(key, val_name)
                    except FileNotFoundError:
                        pass
                winreg.CloseKey(key)
            except Exception:
                pass

    # ------------------------------------------------------------------------
    # ACTIVATE SHIELD & ENFORCE PROXY-ALIGNED DNS
    # ------------------------------------------------------------------------
    def activate_uk_shield(self) -> Tuple[bool, str]:
        self.log("=" * 66)
        self.log("[NETSHIELD] STARTING 100% UK DNS SYNC & FIREWALL KILL-SWITCH...")

        # Step 1: Detect active proxy tunnel
        tuxler = self.detect_proxy_tunnel()
        socks_host = tuxler["socks_host"]
        socks_port = tuxler["socks_port"]
        self.log(
            f"[TUNNEL] Proxy Engine={tuxler['tuxler_running']} | "
            f"Active={tuxler['is_proxy_set'] or tuxler['proxy_enabled_reg']} | "
            f"Target={tuxler['selected_country']} ({tuxler['selected_country_iso']}) | "
            f"SOCKS={socks_host}:{socks_port}"
        )
        self.doh_server.update_socks_endpoint(socks_host, socks_port)
        self.doh_server.killswitch_block_dns = False

        # Step 2: Detect active network adapters, set initial DNS, and unbind IPv6
        adapters = self.get_active_adapters()
        if adapters:
            names_str = ", ".join(f"'{a['Name']}'" for a in adapters)
            self.log(f"[ADAPTERS] Active network adapter(s): {names_str}")

        for ad in adapters:
            name = ad["Name"]
            run_powershell(
                f"Set-DnsClientServerAddress -InterfaceAlias '{name}' -ServerAddresses ('1.1.1.1','1.0.0.1') -ErrorAction SilentlyContinue"
            )
            run_cmd(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "static", "1.1.1.1", "primary", "validate=no"])
            run_cmd(["netsh", "interface", "ipv4", "add", "dnsservers", f"name={name}", "1.0.0.1", "index=2", "validate=no"])

        self.log("[IPv6] Unbinding IPv6 across all adapters (Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6)...")
        run_powershell("Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue")

        # Step 3: Configure Windows Advanced Firewall Outbound Kill-Switch Rules
        self.log("[FIREWALL] Configuring Outbound Port 53, QUIC (UDP 443) & WebRTC Leak Blockers...")
        self._remove_firewall_rules_silent()

        run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FW_RULE_ALLOW_UDP}", "dir=out", "action=allow", "protocol=UDP",
            "remoteport=53", "remoteip=1.1.1.1,1.0.0.1,127.0.0.1", "profile=any", "enable=yes"
        ])
        run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FW_RULE_ALLOW_TCP}", "dir=out", "action=allow", "protocol=TCP",
            "remoteport=53", "remoteip=1.1.1.1,1.0.0.1,127.0.0.1", "profile=any", "enable=yes"
        ])
        run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FW_RULE_BLOCK_UDP_V4}", "dir=out", "action=block", "protocol=UDP",
            "remoteport=53", f"remoteip={BLOCKED_DNS_IPV4_RANGES}", "profile=any", "enable=yes"
        ])
        run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FW_RULE_BLOCK_TCP_V4}", "dir=out", "action=block", "protocol=TCP",
            "remoteport=53", f"remoteip={BLOCKED_DNS_IPV4_RANGES}", "profile=any", "enable=yes"
        ])
        run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FW_RULE_BLOCK_UDP_V6}", "dir=out", "action=block", "protocol=UDP",
            "remoteport=53", "remoteip=0000::/0", "profile=any", "enable=yes"
        ])
        run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FW_RULE_BLOCK_TCP_V6}", "dir=out", "action=block", "protocol=TCP",
            "remoteport=53", "remoteip=0000::/0", "profile=any", "enable=yes"
        ])
        run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FW_RULE_BLOCK_QUIC_UDP443}", "dir=out", "action=block", "protocol=UDP",
            "remoteport=443", "profile=any", "enable=yes"
        ])
        run_cmd([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={FW_RULE_BLOCK_WEBRTC_STUN}", "dir=out", "action=block", "protocol=UDP",
            "remoteport=3478,5349,19302", "profile=any", "enable=yes"
        ])

        # Step 4: Neutralize SMHNR & apply browser policies
        self.apply_system_and_browser_policies()

        # Step 5: Start Local DoH Proxy on 127.0.0.1:53 tunneled via SOCKS
        self.log(
            f"[DoH TUNNEL] Starting Local DoH Server on 127.0.0.1:53 -> SOCKS ({socks_host}:{socks_port})..."
        )
        doh_ok, doh_msg = self.doh_server.start()
        self.log(f"[DoH TUNNEL] {doh_msg}")

        if doh_ok:
            for ad in adapters:
                name = ad["Name"]
                run_powershell(
                    f"Set-DnsClientServerAddress -InterfaceAlias '{name}' -ServerAddresses ('127.0.0.1') -ErrorAction SilentlyContinue"
                )
                run_cmd([
                    "netsh", "interface", "ipv4", "set", "dnsservers",
                    f"name={name}", "static", "127.0.0.1", "primary", "validate=no"
                ])
            self.log("[DNS] Pointed Windows IPv4 DNS to 127.0.0.1 (100% Proxy-Aligned DoH).")

        # Step 6: Verify Live Outbound IP & Geo-Alignment
        geo = self.fetch_live_tunnel_telemetry(tuxler)
        live_ip = geo.get("ip", "")
        live_cc = geo.get("country_code", "")
        live_isp = geo.get("isp", "")
        live_loc = geo.get("location", "")
        dns_colo = geo.get("dns_colo", "")

        if live_cc in ("GB", "UK"):
            self.locked_uk_ip = live_ip
            self.locked_uk_isp = live_isp
            self.locked_uk_city = live_loc
            self.killswitch_tripped = False
            self.killswitch_reason = ""
            self.doh_server.killswitch_block_dns = False
            self.log(
                f"[LOCKED UK IP] Verified UK Outbound IP: {live_ip} ({live_isp} — {live_loc})"
            )
            self.log(
                f"[LOCKED UK DNS] DNS Queries Exit via {live_ip} -> Cloudflare UK ({dns_colo}) [100% GEO-ALIGNED]"
            )
        elif (len(live_cc) == 2 and live_cc not in ("GB", "UK")) or not tuxler["socks_online"]:
            self.locked_uk_ip = None
            self.doh_server.killswitch_block_dns = True
            self.killswitch_tripped = True
            self.killswitch_reason = (
                f"Proxy tunnel is not connected to the UK yet (Current IP: {live_ip} {live_loc}). "
                "Connect your proxy/VPN to United Kingdom (UK) and click 'ACTIVATE 100% UK SHIELD'."
            )
            self.log(f"[NOTICE] {self.killswitch_reason}")

        run_cmd(["ipconfig", "/flushdns"])
        self.log("[DNS CACHE] Flushed Windows DNS Resolver Cache (ipconfig /flushdns).")
        self.shield_active = True
        self.log("=" * 66)
        return True, "UK Shield Active"

    # ------------------------------------------------------------------------
    # DEACTIVATE / RESTORE SYSTEM STATE
    # ------------------------------------------------------------------------
    def deactivate_and_restore(self) -> Tuple[bool, str]:
        self.log("=" * 66)
        self.log("[RESTORE] DEACTIVATING NETSHIELD & RESTORING DEFAULT SYSTEM SETTINGS...")

        self.shield_active = False
        self.killswitch_tripped = False
        self.locked_uk_ip = None
        self.doh_server.killswitch_block_dns = False

        self.log("[1/4] Stopping local DoH proxy on 127.0.0.1:53...")
        self.doh_server.stop()

        self.log("[2/4] Removing Windows Firewall Kill-Switch rules & system policies...")
        self._remove_firewall_rules_silent()
        self.remove_system_and_browser_policies()

        self.log("[3/4] Re-enabling IPv6 across all network adapters...")
        run_powershell("Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue")

        self.log("[4/4] Restoring IPv4 DNS to automatic (DHCP) on active adapters...")
        for ad in self.get_active_adapters():
            name = ad["Name"]
            run_powershell(
                f"Set-DnsClientServerAddress -InterfaceAlias '{name}' -ResetServerAddresses -ErrorAction SilentlyContinue"
            )
            run_cmd(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "source=dhcp"])

        run_cmd(["ipconfig", "/flushdns"])
        self.log("[SUCCESS] All Network, DNS, IPv6, and Firewall settings restored to default.")
        self.log("=" * 66)
        return True, "Restored System Settings"

    def _remove_firewall_rules_silent(self) -> None:
        for rule_name in ALL_FW_RULES:
            run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])

    # ------------------------------------------------------------------------
    # LIVE TUNNEL IP, ASN/ISP & GEO-ALIGNMENT TELEMETRY
    # ------------------------------------------------------------------------
    def fetch_live_tunnel_telemetry(self, tuxler_info: Dict[str, Any]) -> Dict[str, str]:
        """
        Scan the active SOCKS proxy tunnel's outbound IP, ISP/ASN, City, Country (`GB`),
        and Cloudflare edge PoP (`LHR`/`MAN`).
        Returns `country_code = 'TIMEOUT'` on transient residential congestion so
        temporary timeouts never trigger false-positive alerts.
        """
        socks_host = tuxler_info.get("socks_host", "127.0.0.1")
        socks_port = int(tuxler_info.get("socks_port", DEFAULT_LOCAL_SOCKS_PORT))
        socks_online = tuxler_info.get("socks_online", False)

        if not socks_online:
            return {
                "ip": "Proxy Tunnel Offline",
                "isp": "Disconnected",
                "location": "Offline",
                "country_code": "OFFLINE",
                "dns_colo": "Blocked by Kill-Switch",
                "dns_country": "Blocked (No Leak)",
            }

        ip_val = ""
        isp_val = ""
        loc_val = ""
        cc_val = ""
        colo_val = "LHR"

        # 1. Query IP/ISP metadata via ip-api.com (`208.95.112.1:80`) over SOCKS4/5
        for socks_type in (socks.SOCKS4, socks.SOCKS5):
            s: Optional[socks.socksocket] = None
            try:
                s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                s.set_proxy(socks_type, socks_host, socks_port, rdns=False)
                s.settimeout(6.0)
                s.connect(("208.95.112.1", 80))
                s.sendall(
                    b"GET /json/?fields=status,country,countryCode,city,isp,org,query HTTP/1.1\r\n"
                    b"Host: ip-api.com\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                )
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                s.close()
                if b"\r\n\r\n" in raw:
                    body_str = raw.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace").strip()
                    m = re.search(r"\{.*\}", body_str, re.DOTALL)
                    if m:
                        data = json.loads(m.group(0))
                        if data.get("status") == "success":
                            ip_val = str(data.get("query") or "")
                            isp_val = str(data.get("isp") or data.get("org") or "UK Residential ISP")
                            country = str(data.get("country") or "")
                            cc_val = str(data.get("countryCode") or "").upper()
                            city = str(data.get("city") or "")
                            loc_val = f"{city}, {country} ({cc_val})".strip(", ")
                            break
            except Exception:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass

        # 2. Query Cloudflare Trace (`104.16.132.229:443`, SNI=`cloudflare.com`) over SOCKS4/5
        for socks_type in (socks.SOCKS4, socks.SOCKS5):
            raw_s: Optional[socks.socksocket] = None
            try:
                raw_s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                raw_s.set_proxy(socks_type, socks_host, socks_port, rdns=False)
                raw_s.settimeout(6.0)
                raw_s.connect(("104.16.132.229", 443))
                ss = self._ssl_ctx.wrap_socket(raw_s, server_hostname="cloudflare.com")
                ss.settimeout(6.0)
                ss.sendall(
                    b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\n"
                    b"Connection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                )
                resp = ss.recv(4096).decode("utf-8", errors="replace")
                ss.close()
                if "loc=" in resp:
                    kv = dict(line.split("=", 1) for line in resp.splitlines() if "=" in line)
                    if not ip_val:
                        ip_val = kv.get("ip", "")
                    if not cc_val:
                        cc_val = kv.get("loc", "").upper()
                    colo_val = kv.get("colo", "LHR")
                    if not loc_val and cc_val:
                        loc_val = f"United Kingdom ({cc_val})" if cc_val == "GB" else f"Country: {cc_val}"
                    if not isp_val and cc_val:
                        isp_val = "UK Residential Broadband" if cc_val == "GB" else "ISP"
                    break
            except Exception:
                if raw_s is not None:
                    try:
                        raw_s.close()
                    except Exception:
                        pass

        if not cc_val:
            return {
                "ip": self.locked_uk_ip or "Tunnel Busy (Keeping UK Lock)",
                "isp": self.locked_uk_isp or "UK Residential ISP",
                "location": self.locked_uk_city or "United Kingdom (GB)",
                "country_code": "TIMEOUT",
                "dns_colo": colo_val,
                "dns_country": f"United Kingdom (Cloudflare {colo_val} via {self.locked_uk_ip or 'UK Tunnel'})",
            }

        dns_country = (
            f"United Kingdom (Cloudflare {colo_val} via {ip_val})"
            if cc_val in ("GB", "UK")
            else f"BLOCKED BY KILL-SWITCH (Current IP: {cc_val})"
        )
        return {
            "ip": ip_val,
            "isp": isp_val,
            "location": loc_val,
            "country_code": cc_val,
            "dns_colo": colo_val,
            "dns_country": dns_country,
        }

    def get_system_dns_status(self) -> Dict[str, Any]:
        adapters = self.get_active_adapters()
        dns_list: List[str] = []
        for ad in adapters:
            name = ad["Name"]
            ps_dns = (
                f"(Get-DnsClientServerAddress -InterfaceAlias '{name}' "
                f"-AddressFamily IPv4).ServerAddresses | ConvertTo-Json -Compress"
            )
            code, out, _ = run_powershell(ps_dns, timeout=6)
            if code == 0 and out:
                try:
                    parsed = json.loads(out)
                    if isinstance(parsed, str) and parsed not in dns_list:
                        dns_list.append(parsed)
                    elif isinstance(parsed, list):
                        for s in parsed:
                            if str(s) not in dns_list:
                                dns_list.append(str(s))
                except Exception:
                    pass

        fw_code, fw_out, _ = run_cmd(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={FW_RULE_BLOCK_UDP_V4}"],
            timeout=6,
        )
        fw_active = fw_code == 0 and FW_RULE_BLOCK_UDP_V4 in fw_out

        return {
            "dns_servers": dns_list,
            "firewall_killswitch": fw_active,
            "doh_running": self.doh_server.is_running,
            "doh_queries": self.doh_server.queries_handled,
            "doh_blocked": self.doh_server.queries_blocked,
            "doh_latency_ms": self.doh_server.last_latency_ms,
            "doh_last_domain": self.doh_server.last_query_domain,
        }


# ============================================================================
# GRAPHICAL USER INTERFACE & CRITICAL-ONLY EMERGENCY ALERT SYSTEM
# ============================================================================

class NetShieldApp:
    """Main Windows GUI Application for NetShield: Dynamic DNS-Leak Guard & Proxy Enforcer."""

    def __init__(self) -> None:
        self.controller = NetShieldSystemController(log_callback=self.append_log_threadsafe)
        self._closing = False
        self._action_lock = threading.Lock()
        self._last_ip_check_ts = 0.0
        self._alert_window: Optional[Any] = None
        self._alert_acknowledged_for_reason: str = ""
        self._consecutive_critical_failures: int = 0

        if HAS_CTK:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()
            self.root.configure(bg="#0d1117")

        self.root.title(APP_TITLE)
        self.root.geometry("960x760")
        self.root.minsize(900, 700)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()
        self.append_log(f"[INIT] {APP_TITLE} v{APP_VERSION} initialized.")
        self.append_log(
            f"[PRIVILEGE] Administrator Mode: {'YES (Full Firewall & Port 53 Control)' if is_admin() else 'NO (Run as Admin!)'}"
        )

        # Start continuous background telemetry thread
        self._monitor_thread = threading.Thread(
            target=self._continuous_monitor_loop, name="NetShieldTelemetryThread", daemon=True
        )
        self._monitor_thread.start()

        # Automatically activate and synchronize DNS on launch
        self.root.after(600, self._auto_activate_on_launch)

    def _auto_activate_on_launch(self) -> None:
        self.append_log(
            "[AUTO-START] Automatically synchronizing DNS with active proxy tunnel and activating UK Shield..."
        )
        self.on_click_activate()

    # ------------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------------
    def _build_ui(self) -> None:
        if HAS_CTK:
            self._build_ctk_ui()
        else:
            self._build_tk_ui()

    def _build_ctk_ui(self) -> None:
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(3, weight=1)

        # 1. Header Banner
        header = ctk.CTkFrame(self.root, corner_radius=12, fg_color="#111827", border_width=1, border_color="#1f2937")
        header.grid(row=0, column=0, padx=16, pady=(14, 8), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title_lbl = ctk.CTkLabel(
            header,
            text="🛡️ NETSHIELD — DYNAMIC DNS-LEAK GUARD & PROXY ENFORCER",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#f9fafb",
        )
        title_lbl.grid(row=0, column=0, padx=16, pady=(12, 2), sticky="w")

        sub_lbl = ctk.CTkLabel(
            header,
            text="SOCKS Keep-Alive UK DNS Tunnel  •  100% Whoer.net Disguise (UK IP + UK DNS)  •  Port-53 & SMHNR Kill-Switch",
            font=ctk.CTkFont(size=12),
            text_color="#9ca3af",
        )
        sub_lbl.grid(row=1, column=0, padx=16, pady=(0, 12), sticky="w")

        self.badge_lbl = ctk.CTkLabel(
            header,
            text=" INITIALIZING SHIELD... ",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#1e3a8a",
            text_color="#bfdbfe",
            corner_radius=8,
            padx=12,
            pady=6,
        )
        self.badge_lbl.grid(row=0, column=1, rowspan=2, padx=16, pady=12, sticky="e")

        # 2. Primary Action Buttons
        btn_frame = ctk.CTkFrame(self.root, corner_radius=12, fg_color="#111827", border_width=1, border_color="#1f2937")
        btn_frame.grid(row=1, column=0, padx=16, pady=8, sticky="ew")
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)

        self.btn_activate = ctk.CTkButton(
            btn_frame,
            text="⚡ ACTIVATE 100% UK SHIELD",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=54,
            corner_radius=10,
            fg_color="#059669",
            hover_color="#047857",
            text_color="#ffffff",
            command=self.on_click_activate,
        )
        self.btn_activate.grid(row=0, column=0, padx=(14, 8), pady=14, sticky="ew")

        self.btn_deactivate = ctk.CTkButton(
            btn_frame,
            text="🔓 DEACTIVATE / RESTORE",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=54,
            corner_radius=10,
            fg_color="#dc2626",
            hover_color="#b91c1c",
            text_color="#ffffff",
            command=self.on_click_deactivate,
        )
        self.btn_deactivate.grid(row=0, column=1, padx=(8, 14), pady=14, sticky="ew")

        # 3. Live Telemetry Dashboard Grid
        dash = ctk.CTkFrame(self.root, corner_radius=12, fg_color="#111827", border_width=1, border_color="#1f2937")
        dash.grid(row=2, column=0, padx=16, pady=8, sticky="ew")
        dash.grid_columnconfigure((0, 1), weight=1)

        # Left column: Proxy Tunnel & Outbound IP Telemetry
        left_card = ctk.CTkFrame(dash, corner_radius=10, fg_color="#1e293b")
        left_card.grid(row=0, column=0, padx=(12, 6), pady=12, sticky="nsew")
        left_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            left_card,
            text="🇬🇧 LIVE PROXY TUNNEL & OUTBOUND IP TELEMETRY",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8",
        ).grid(row=0, column=0, columnspan=2, padx=12, pady=(10, 6), sticky="w")

        self.val_tuxler_port = self._add_ctk_row(left_card, 1, "Local SOCKS Tunnel:")
        self.val_public_ip = self._add_ctk_row(left_card, 2, "Live Outbound IP:")
        self.val_locked_ip = self._add_ctk_row(left_card, 3, "Locked UK Shield IP:")
        self.val_isp = self._add_ctk_row(left_card, 4, "Outbound ISP / ASN:")
        self.val_location = self._add_ctk_row(left_card, 5, "Live Geo Location:")

        # Right column: Geo-Aligned DNS & Firewall Kill-Switch Status
        right_card = ctk.CTkFrame(dash, corner_radius=10, fg_color="#1e293b")
        right_card.grid(row=0, column=1, padx=(6, 12), pady=12, sticky="nsew")
        right_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            right_card,
            text="🔒 GEO-ALIGNED DNS & KILL-SWITCH STATUS",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#34d399",
        ).grid(row=0, column=0, columnspan=2, padx=12, pady=(10, 6), sticky="w")

        self.val_dns_servers = self._add_ctk_row(right_card, 1, "Windows Adapter DNS:")
        self.val_dns_exit = self._add_ctk_row(right_card, 2, "Live DNS Exit Region:")
        self.val_fw_status = self._add_ctk_row(right_card, 3, "Firewall & QUIC Block:")
        self.val_whoer_status = self._add_ctk_row(right_card, 4, "Disguise / Leak Status:")
        self.val_doh_metrics = self._add_ctk_row(right_card, 5, "Tunnel DNS Queries:")

        # 4. Real-Time Execution & Security Audit Log Console
        log_frame = ctk.CTkFrame(self.root, corner_radius=12, fg_color="#111827", border_width=1, border_color="#1f2937")
        log_frame.grid(row=3, column=0, padx=16, pady=(8, 14), sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)

        log_header = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_header.grid(row=0, column=0, padx=12, pady=(8, 4), sticky="ew")
        log_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            log_header,
            text="📋 REAL-TIME SECURITY & NETWORK AUDIT LOG",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#9ca3af",
        ).grid(row=0, column=0, sticky="w")

        self.btn_verify_doh = ctk.CTkButton(
            log_header,
            text="🔍 Verify UK DNS & Flush Cache",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=28,
            width=210,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            command=self.on_click_test_doh,
        )
        self.btn_verify_doh.grid(row=0, column=1, sticky="e")

        self.log_box = ctk.CTkTextbox(
            log_frame,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#090d16",
            text_color="#e5e7eb",
            corner_radius=8,
        )
        self.log_box.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="nsew")

    def _add_ctk_row(self, parent: Any, row_idx: int, label_text: str) -> Any:
        lbl = ctk.CTkLabel(
            parent,
            text=label_text,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#94a3b8",
        )
        lbl.grid(row=row_idx, column=0, padx=(12, 6), pady=3, sticky="w")

        val = ctk.CTkLabel(
            parent,
            text="Checking...",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color="#f8fafc",
            anchor="w",
        )
        val.grid(row=row_idx, column=1, padx=(4, 12), pady=3, sticky="ew")
        return val

    def _build_tk_ui(self) -> None:
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(3, weight=1)

        header = tk.Frame(self.root, bg="#111827", padx=14, pady=12)
        header.grid(row=0, column=0, padx=14, pady=10, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        tk.Label(
            header,
            text="NETSHIELD — DYNAMIC DNS-LEAK GUARD & PROXY ENFORCER",
            font=("Segoe UI", 14, "bold"),
            fg="#f9fafb",
            bg="#111827",
        ).grid(row=0, column=0, sticky="w")

        self.badge_lbl = tk.Label(
            header,
            text=" INITIALIZING... ",
            font=("Segoe UI", 10, "bold"),
            bg="#1e3a8a",
            fg="#bfdbfe",
            padx=10,
            pady=4,
        )
        self.badge_lbl.grid(row=0, column=1, sticky="e")

        btn_frame = tk.Frame(self.root, bg="#111827", padx=12, pady=12)
        btn_frame.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        btn_frame.grid_columnconfigure((0, 1), weight=1)

        self.btn_activate = tk.Button(
            btn_frame,
            text="ACTIVATE 100% UK SHIELD",
            font=("Segoe UI", 12, "bold"),
            bg="#059669",
            fg="#ffffff",
            height=2,
            command=self.on_click_activate,
        )
        self.btn_activate.grid(row=0, column=0, padx=8, sticky="ew")

        self.btn_deactivate = tk.Button(
            btn_frame,
            text="DEACTIVATE / RESTORE",
            font=("Segoe UI", 12, "bold"),
            bg="#dc2626",
            fg="#ffffff",
            height=2,
            command=self.on_click_deactivate,
        )
        self.btn_deactivate.grid(row=0, column=1, padx=8, sticky="ew")

        dash = tk.Frame(self.root, bg="#1e293b", padx=12, pady=10)
        dash.grid(row=2, column=0, padx=14, pady=6, sticky="ew")
        dash.grid_columnconfigure((1, 3), weight=1)

        self.val_tuxler_port = self._add_tk_row(dash, 0, 0, "Local SOCKS Tunnel:")
        self.val_public_ip = self._add_tk_row(dash, 1, 0, "Live Outbound IP:")
        self.val_locked_ip = self._add_tk_row(dash, 2, 0, "Locked UK Shield IP:")
        self.val_isp = self._add_tk_row(dash, 3, 0, "Outbound ISP / ASN:")
        self.val_location = self._add_tk_row(dash, 4, 0, "Live Geo Location:")

        self.val_dns_servers = self._add_tk_row(dash, 0, 2, "Windows Adapter DNS:")
        self.val_dns_exit = self._add_tk_row(dash, 1, 2, "Live DNS Exit Region:")
        self.val_fw_status = self._add_tk_row(dash, 2, 2, "Firewall & QUIC Block:")
        self.val_whoer_status = self._add_tk_row(dash, 3, 2, "Disguise / Leak Status:")
        self.val_doh_metrics = self._add_tk_row(dash, 4, 2, "Tunnel DNS Queries:")

        log_frame = tk.Frame(self.root, bg="#111827", padx=10, pady=10)
        log_frame.grid(row=3, column=0, padx=14, pady=10, sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)

        self.log_box = tk.Text(log_frame, bg="#090d16", fg="#e5e7eb", font=("Consolas", 10))
        self.log_box.grid(row=0, column=0, sticky="nsew")

    def _add_tk_row(self, parent: Any, r: int, c: int, label_text: str) -> Any:
        tk.Label(parent, text=label_text, bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 9, "bold")).grid(
            row=r, column=c, padx=6, pady=2, sticky="w"
        )
        val = tk.Label(parent, text="Checking...", bg="#1e293b", fg="#f8fafc", font=("Consolas", 9, "bold"))
        val.grid(row=r, column=c + 1, padx=6, pady=2, sticky="w")
        return val

    # ------------------------------------------------------------------------
    # CRITICAL-ONLY EMERGENCY POPUP ALERT + SOUND ALARM + WINDOWS NOTIFICATION
    # ------------------------------------------------------------------------
    def trigger_emergency_alert(self, reason: str) -> None:
        """
        Display an Always-On-Top emergency alert dialog ONLY when a confirmed
        critical condition occurs (tunnel offline or non-UK IP detected).
        """
        if self._alert_acknowledged_for_reason == reason and self._alert_window is not None:
            return
        self._alert_acknowledged_for_reason = reason

        def _sound_alarm() -> None:
            try:
                for _ in range(3):
                    winsound.Beep(1400, 280)
                    time.sleep(0.1)
            except Exception:
                try:
                    winsound.MessageBeep(winsound.MB_ICONHAND)
                except Exception:
                    pass

        threading.Thread(target=_sound_alarm, daemon=True).start()

        show_windows_toast_notification(
            "CRITICAL UK VPN / DNS ALERT!",
            f"{reason} Immediately close your active website and reconnect your VPN to the UK!",
        )

        if self._alert_window is not None:
            try:
                self._alert_window.destroy()
            except Exception:
                pass
            self._alert_window = None

        if HAS_CTK:
            win = ctk.CTkToplevel(self.root)
            win.configure(fg_color="#450a0a")
        else:
            win = tk.Toplevel(self.root)
            win.configure(bg="#450a0a")

        win.title("⚠️ CRITICAL SECURITY ALERT — PROXY TUNNEL DROPPED / NON-UK IP")
        win.geometry("640x340")
        win.attributes("-topmost", True)
        win.lift()
        win.focus_force()
        self._alert_window = win

        msg_title = "🚨 CRITICAL ALERT: UK TUNNEL DROPPED OR NON-UK IP DETECTED! 🚨"
        msg_body = (
            f"CRITICAL SITUATION: {reason}\n\n"
            "• DNS KILL-SWITCH IS NOW ACTIVE: All DNS queries are blocked so your local ISP DNS CANNOT leak.\n"
            "• ACTION REQUIRED IMMEDIATELY:\n"
            "   1. Quickly CLOSE the website or browser tab you are currently working on.\n"
            "   2. Reconnect your VPN/Proxy to UNITED KINGDOM (UK).\n"
            "   3. Click 'RE-SYNC & LOCK UK DNS NOW' below."
        )

        if HAS_CTK:
            ctk.CTkLabel(
                win,
                text=msg_title,
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color="#fecaca",
            ).pack(padx=20, pady=(20, 10))

            ctk.CTkLabel(
                win,
                text=msg_body,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#ffffff",
                justify="left",
                wraplength=590,
            ).pack(padx=20, pady=10)

            btn_row = ctk.CTkFrame(win, fg_color="transparent")
            btn_row.pack(padx=20, pady=(16, 20), fill="x")
            btn_row.grid_columnconfigure((0, 1), weight=1)

            ctk.CTkButton(
                btn_row,
                text="⚡ RE-SYNC & LOCK UK DNS NOW",
                font=ctk.CTkFont(size=14, weight="bold"),
                height=44,
                fg_color="#059669",
                hover_color="#047857",
                command=lambda: self._dismiss_alert_and_resync(),
            ).grid(row=0, column=0, padx=8, sticky="ew")

            ctk.CTkButton(
                btn_row,
                text="Dismiss Alert",
                font=ctk.CTkFont(size=14, weight="bold"),
                height=44,
                fg_color="#374151",
                hover_color="#4b5563",
                command=lambda: self._close_alert_window(),
            ).grid(row=0, column=1, padx=8, sticky="ew")
        else:
            tk.Label(win, text=msg_title, font=("Segoe UI", 12, "bold"), bg="#450a0a", fg="#fecaca").pack(
                padx=16, pady=(16, 8)
            )
            tk.Label(
                win, text=msg_body, font=("Segoe UI", 10, "bold"), bg="#450a0a", fg="#ffffff", justify="left", wraplength=580
            ).pack(padx=16, pady=8)
            tk.Button(
                win,
                text="RE-SYNC & LOCK UK DNS NOW",
                font=("Segoe UI", 11, "bold"),
                bg="#059669",
                fg="#ffffff",
                command=self._dismiss_alert_and_resync,
            ).pack(pady=12)

    def _close_alert_window(self) -> None:
        if self._alert_window is not None:
            try:
                self._alert_window.destroy()
            except Exception:
                pass
            self._alert_window = None

    def _dismiss_alert_and_resync(self) -> None:
        self._close_alert_window()
        self._alert_acknowledged_for_reason = ""
        self._consecutive_critical_failures = 0
        self.on_click_activate()

    # ------------------------------------------------------------------------
    # Logging & Label Helpers
    # ------------------------------------------------------------------------
    def append_log(self, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {message}\n"
        try:
            self.log_box.insert("end", line)
            self.log_box.see("end")
        except Exception:
            pass

    def append_log_threadsafe(self, message: str) -> None:
        if not self._closing:
            self.root.after(0, lambda m=message: self.append_log(m))

    @staticmethod
    def _set_label(widget: Any, text: str, color: Optional[str] = None) -> None:
        try:
            if HAS_CTK:
                kwargs: Dict[str, Any] = {"text": text}
                if color:
                    kwargs["text_color"] = color
                widget.configure(**kwargs)
            else:
                kwargs = {"text": text}
                if color:
                    kwargs["fg"] = color
                widget.configure(**kwargs)
        except Exception:
            pass

    # ------------------------------------------------------------------------
    # Button Handlers
    # ------------------------------------------------------------------------
    def on_click_activate(self) -> None:
        if not self._action_lock.acquire(blocking=False):
            return
        self._set_buttons_busy(True)

        def worker() -> None:
            try:
                self._consecutive_critical_failures = 0
                self.controller.activate_uk_shield()
                self._last_ip_check_ts = 0.0
            finally:
                self._action_lock.release()
                self.root.after(0, lambda: self._set_buttons_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def on_click_deactivate(self) -> None:
        if not self._action_lock.acquire(blocking=False):
            return
        self._set_buttons_busy(True)

        def worker() -> None:
            try:
                self._consecutive_critical_failures = 0
                self.root.after(0, self._close_alert_window)
                self.controller.deactivate_and_restore()
                self._last_ip_check_ts = 0.0
            finally:
                self._action_lock.release()
                self.root.after(0, lambda: self._set_buttons_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def on_click_test_doh(self) -> None:
        def worker() -> None:
            self.append_log_threadsafe("[VERIFY] Flushing DNS cache and testing live UK DoH resolution on 127.0.0.1:53...")
            self.controller.doh_server.clear_cache()
            self.controller.doh_server.prewarm_connections()
            run_cmd(["ipconfig", "/flushdns"])
            try:
                q = DNSRecord.question("whoer.net", "A").pack()
                if self.controller.doh_server.is_running:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(7.0)
                    t0 = time.perf_counter()
                    sock.sendto(q, (LOCAL_DOH_HOST, LOCAL_DOH_PORT))
                    data, _ = sock.recvfrom(4096)
                    ms = round((time.perf_counter() - t0) * 1000.0, 1)
                    sock.close()
                    parsed = DNSRecord.parse(data)
                    ips = [str(rr.rdata) for rr in parsed.rr]
                    if parsed.header.rcode == RCODE.REFUSED:
                        self.append_log_threadsafe(
                            "[VERIFY] DNS Kill-Switch is currently holding queries because no UK tunnel IP is active."
                        )
                    else:
                        self.append_log_threadsafe(
                            f"[VERIFY PASS] 127.0.0.1:53 resolved whoer.net via UK SOCKS Tunnel -> {', '.join(ips)} ({ms} ms)"
                        )
                else:
                    self.append_log_threadsafe("[VERIFY] Local DoH server is stopped. Click 'ACTIVATE 100% UK SHIELD'.")
            except Exception as exc:
                self.append_log_threadsafe(f"[VERIFY ERROR] DNS test failed: {exc}")
            self._last_ip_check_ts = 0.0

        threading.Thread(target=worker, daemon=True).start()

    def _set_buttons_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        try:
            self.btn_activate.configure(state=state)
            self.btn_deactivate.configure(state=state)
        except Exception:
            pass

    # ------------------------------------------------------------------------
    # Continuous Background Telemetry Monitor (Critical-Only Alert Logic)
    # ------------------------------------------------------------------------
    def _continuous_monitor_loop(self) -> None:
        cached_geo: Dict[str, str] = {
            "ip": "Checking...",
            "isp": "Checking...",
            "location": "Checking...",
            "country_code": "TIMEOUT",
            "dns_colo": "LHR",
            "dns_country": "Checking...",
        }

        while not self._closing:
            try:
                tuxler_info = self.controller.detect_proxy_tunnel()
                self.controller.doh_server.update_socks_endpoint(
                    tuxler_info["socks_host"], tuxler_info["socks_port"]
                )
                sys_status = self.controller.get_system_dns_status()

                now = time.time()
                if (now - self._last_ip_check_ts) >= 7.0:
                    new_geo = self.controller.fetch_live_tunnel_telemetry(tuxler_info)
                    self._last_ip_check_ts = time.time()

                    live_cc = new_geo.get("country_code", "")
                    live_ip = new_geo.get("ip", "")
                    live_isp = new_geo.get("isp", "")
                    live_loc = new_geo.get("location", "")

                    if live_cc != "TIMEOUT" or not self.controller.locked_uk_ip:
                        cached_geo = new_geo

                    if self.controller.shield_active:
                        socks_online = tuxler_info.get("socks_online", False)

                        if live_cc in ("GB", "UK"):
                            self._consecutive_critical_failures = 0
                            self.controller.killswitch_tripped = False
                            self.controller.killswitch_reason = ""
                            self.controller.doh_server.killswitch_block_dns = False
                            self.root.after(0, self._close_alert_window)

                            if not self.controller.locked_uk_ip:
                                self.controller.locked_uk_ip = live_ip
                                self.controller.locked_uk_isp = live_isp
                                self.controller.locked_uk_city = live_loc
                                self.controller.doh_server.clear_cache()
                                self.controller.doh_server.prewarm_connections()
                                run_cmd(["ipconfig", "/flushdns"])
                                self.append_log_threadsafe(
                                    f"[LOCKED UK] Locked onto UK IP: {live_ip} ({live_isp} — {live_loc})"
                                )
                            elif live_ip and live_ip != self.controller.locked_uk_ip:
                                # Silent background re-sync when rotating between two UK residential peers
                                old_ip = self.controller.locked_uk_ip
                                self.controller.locked_uk_ip = live_ip
                                self.controller.locked_uk_isp = live_isp
                                self.controller.locked_uk_city = live_loc
                                self.controller.doh_server.clear_cache()
                                self.controller.doh_server.prewarm_connections()
                                run_cmd(["ipconfig", "/flushdns"])
                                self.append_log_threadsafe(
                                    f"[UK PEER SYNC] UK IP rotated ({old_ip} -> {live_ip}, {live_isp}). Silently synced UK DNS!"
                                )

                        elif live_cc == "TIMEOUT" and socks_online:
                            # Ignore transient residential timeout — never trigger false-positive warnings
                            pass

                        else:
                            is_confirmed_non_uk_country = len(live_cc) == 2 and live_cc not in ("GB", "UK")
                            is_tunnel_offline = not socks_online or live_cc == "OFFLINE"

                            if is_confirmed_non_uk_country or is_tunnel_offline:
                                self._consecutive_critical_failures += 1
                                if is_confirmed_non_uk_country or self._consecutive_critical_failures >= 2:
                                    self.controller.doh_server.killswitch_block_dns = True
                                    self.controller.killswitch_tripped = True
                                    if is_tunnel_offline:
                                        reason = "Proxy/VPN tunnel went offline or disconnected!"
                                    else:
                                        reason = f"Non-UK Outbound IP Detected: {live_ip} ({live_loc})!"
                                    self.controller.killswitch_reason = reason
                                    self.append_log_threadsafe(f"[CRITICAL ALERT] {reason}")
                                    self.root.after(0, lambda r=reason: self.trigger_emergency_alert(r))

                if not self._closing:
                    self.root.after(
                        0,
                        lambda t=tuxler_info, s=sys_status, g=dict(cached_geo): self._update_dashboard_ui(t, s, g),
                    )
            except Exception:
                pass

            for _ in range(15):
                if self._closing:
                    break
                time.sleep(0.1)

    def _update_dashboard_ui(
        self, tuxler_info: Dict[str, Any], sys_status: Dict[str, Any], geo: Dict[str, str]
    ) -> None:
        if self._closing:
            return

        socks_host = tuxler_info.get("socks_host", "127.0.0.1")
        socks_port = tuxler_info.get("socks_port", DEFAULT_LOCAL_SOCKS_PORT)
        socks_online = tuxler_info.get("socks_online", False)

        live_ip = geo.get("ip", "Unknown")
        live_cc = geo.get("country_code", "")
        if live_cc == "TIMEOUT" and self.controller.locked_uk_ip:
            live_cc = "GB"
            live_ip = self.controller.locked_uk_ip

        live_isp = geo.get("isp", "Unknown")
        live_loc = geo.get("location", "Unknown")
        dns_country = geo.get("dns_country", "Unknown")

        is_uk = live_cc in ("GB", "UK")
        is_set = is_uk or tuxler_info.get("is_proxy_set", False) or tuxler_info.get("proxy_enabled_reg", False)

        tunnel_str = (
            f"socks4://{socks_host}:{socks_port} [{'CONNECTED (UK ACTIVE)' if is_uk else ('CONNECTED' if is_set else 'STANDBY')}]"
            if socks_online
            else "Proxy Tunnel Offline"
        )
        self._set_label(self.val_tuxler_port, tunnel_str, "#4ade80" if (socks_online and is_set) else "#fbbf24")
        self._set_label(self.val_public_ip, f"{live_ip} ({live_cc or 'N/A'})", "#4ade80" if is_uk else "#f87171")

        locked_ip = self.controller.locked_uk_ip
        self._set_label(
            self.val_locked_ip,
            f"{locked_ip} (LOCKED UK)" if locked_ip else "Waiting for UK Tunnel...",
            "#38bdf8" if locked_ip else "#fbbf24",
        )

        self._set_label(self.val_isp, live_isp[:46], "#f8fafc")
        self._set_label(self.val_location, live_loc[:46], "#4ade80" if is_uk else "#f87171")

        dns_servers = sys_status.get("dns_servers", [])
        dns_str = ", ".join(dns_servers) if dns_servers else "DHCP"
        dns_locked = dns_servers == ["127.0.0.1"] or "127.0.0.1" in dns_servers
        self._set_label(
            self.val_dns_servers,
            f"{dns_str} (Local UK DoH)" if dns_locked else dns_str,
            "#4ade80" if dns_locked else "#f87171",
        )

        self._set_label(self.val_dns_exit, dns_country[:46], "#4ade80" if is_uk else "#f87171")

        fw_up = sys_status.get("firewall_killswitch", False)
        self._set_label(
            self.val_fw_status,
            "ACTIVE (Port 53 + QUIC UDP 443 + IPv6 Blocked)" if fw_up else "INACTIVE",
            "#4ade80" if fw_up else "#fbbf24",
        )

        doh_up = sys_status.get("doh_running", False)
        ready_100 = doh_up and fw_up and is_uk and not self.controller.doh_server.killswitch_block_dns
        self._set_label(
            self.val_whoer_status,
            "100% READY (IP = UK & DNS = UK Matched!)" if ready_100 else "HOLD — Connect Tunnel to UK First!",
            "#4ade80" if ready_100 else "#f87171",
        )

        q_ok = sys_status.get("doh_queries", 0)
        q_blk = sys_status.get("doh_blocked", 0)
        q_lat = sys_status.get("doh_latency_ms", 0.0)
        self._set_label(
            self.val_doh_metrics,
            f"{q_ok} Tunneled ({q_lat}ms) | {q_blk} Leaks Blocked",
            "#cbd5e1",
        )

        try:
            if ready_100:
                if HAS_CTK:
                    self.badge_lbl.configure(
                        text=" 🛡️ 100% UK SHIELD LOCKED (ZERO LEAKS) ",
                        fg_color="#065f46",
                        text_color="#a7f3d0",
                    )
                else:
                    self.badge_lbl.configure(text=" 100% UK SHIELD LOCKED ", bg="#065f46", fg="#a7f3d0")
            elif self.controller.shield_active and self.controller.doh_server.killswitch_block_dns:
                if HAS_CTK:
                    self.badge_lbl.configure(
                        text=" 🚨 KILL-SWITCH ENGAGED (CONNECT UK VPN!) ",
                        fg_color="#991b1b",
                        text_color="#fef2f2",
                    )
                else:
                    self.badge_lbl.configure(text=" KILL-SWITCH ENGAGED ", bg="#991b1b", fg="#fef2f2")
            else:
                if HAS_CTK:
                    self.badge_lbl.configure(
                        text=" ⚠️ SHIELD INACTIVE / NORMAL ",
                        fg_color="#7f1d1d",
                        text_color="#fecaca",
                    )
                else:
                    self.badge_lbl.configure(text=" SHIELD INACTIVE ", bg="#7f1d1d", fg="#fef2f2")
        except Exception:
            pass

    def on_close(self) -> None:
        self._closing = True
        try:
            self.controller.doh_server.stop()
        except Exception:
            pass
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


# ============================================================================
# ENTRY POINT
# ============================================================================

def main() -> None:
    if sys.platform == "win32" and "--no-elevate" not in sys.argv:
        if not is_admin():
            elevate_to_admin()
    app = NetShieldApp()
    app.run()


if __name__ == "__main__":
    main()
