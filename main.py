#!/usr/bin/env python3
import os
import sys
import json
import base64
import argparse
from urllib.parse import urlparse, parse_qs, unquote, quote, urlencode

try:
    import yaml
except ImportError:
    sys.stderr.write("Missing dependency PyYAML. Install with: pip install pyyaml\n")
    sys.exit(1)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass
def b64d(s, urlsafe=None):
    """Internal helper."""
    s = s.strip().replace("\n", "").replace("\r", "")
    s += "=" * (-len(s) % 4)
    if urlsafe is None:
        # Try likely decoder order based on URL-safe characters.
        alts = [base64.urlsafe_b64decode, base64.b64decode] if ("-" in s or "_" in s) \
               else [base64.b64decode, base64.urlsafe_b64decode]
    else:
        alts = [base64.urlsafe_b64decode if urlsafe else base64.b64decode]
    last = None
    for fn in alts:
        try:
            return fn(s).decode("utf-8", "replace")
        except Exception as e:  # noqa
            last = e
    raise last


def b64e(s, urlsafe=False, pad=True):
    raw = s.encode("utf-8") if isinstance(s, str) else s
    out = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode()
    return out if pad else out.rstrip("=")


def try_b64_text(s):
    """Internal helper."""
    s = s.strip()
    # Already plain text (a link or Clash YAML), not base64 to decode.
    if not s or "://" in s or "proxies:" in s:
        return None
    try:
        dec = b64d(s)
    except Exception:
        return None
    # Treat decoded content as text only if it looks like links or Clash YAML.
    if "://" in dec or "proxies" in dec:
        return dec
    return None


def truthy(v):
    return str(v).lower() in ("1", "true", "yes", "on")


def get1(q, *keys, default=None):
    """Internal helper."""
    for k in keys:
        if k in q and q[k]:
            return q[k][0]
    return default


def encode_query(q):
    """Internal helper."""
    return urlencode(q, safe="", quote_via=quote)


KNOWN_LINK_QUERY_KEYS = {
    "encryption", "flow",
    "security", "sni", "peer", "fp", "alpn", "allowInsecure", "insecure",
    "pbk", "publicKey", "sid", "shortId",
    "type", "network", "host", "path", "mode", "extra",
    "serviceName", "servicename", "headerType",
}


def _preserve_unknown_xhttp_query(node, q):
    if node.get("network") != "xhttp":
        return
    extra = {}
    for k, vals in q.items():
        if k not in KNOWN_LINK_QUERY_KEYS and vals:
            extra[k] = vals[0]
    if extra:
        node["xhttp-query-extra"] = extra

def parse_ss(uri):
    body = uri[len("ss://"):]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = unquote(frag)
    plugin_q = ""
    if "?" in body:
        body, plugin_q = body.split("?", 1)
    if "@" in body:  # SIP002
        userinfo, hostport = body.rsplit("@", 1)
        try:
            userinfo = b64d(userinfo)
        except Exception:
            userinfo = unquote(userinfo)
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    else:
        dec = b64d(body)
        methpass, hostport = dec.rsplit("@", 1)
        method, password = methpass.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    node = {"type": "ss", "name": name, "server": host, "port": int(port),
            "cipher": method, "password": password}
    if plugin_q:
        q = parse_qs(plugin_q)
        plugin_raw = get1(q, "plugin", default="")
        if plugin_raw:
            parts = plugin_raw.split(";")
            pname = parts[0]
            popts = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
            if pname in ("obfs-local", "simple-obfs", "obfs"):
                node["plugin"] = "obfs"
                node["plugin-opts"] = {"mode": popts.get("obfs", "http"),
                                       "host": popts.get("obfs-host", "")}
            elif pname in ("v2ray-plugin",):
                node["plugin"] = "v2ray-plugin"
                node["plugin-opts"] = {"mode": popts.get("mode", "websocket"),
                                       "host": popts.get("host", ""),
                                       "path": popts.get("path", "/"),
                                       "tls": "tls" in popts}
    return node


def parse_vmess(uri):
    dec = b64d(uri[len("vmess://"):])
    j = json.loads(dec)
    node = {"type": "vmess", "name": j.get("ps", ""), "server": j.get("add", ""),
            "port": int(j.get("port", 0) or 0), "uuid": j.get("id", ""),
            "alterId": int(j.get("aid", 0) or 0),
            "cipher": j.get("scy", "auto") or "auto"}
    net = j.get("net", "tcp") or "tcp"
    node["network"] = net
    host = j.get("host", "")
    path = j.get("path", "")
    if str(j.get("tls", "")).lower() in ("tls", "1", "true", "reality"):
        node["tls"] = True
        if j.get("sni"):
            node["sni"] = j["sni"]
        elif host:
            node["sni"] = host
    if j.get("alpn"):
        node["alpn"] = [a for a in str(j["alpn"]).replace(",", " ").split() if a]
    if j.get("fp"):
        node["fp"] = j["fp"]
    if net == "ws":
        node["ws-path"] = path or "/"
        if host:
            node["ws-host"] = host
    elif net == "grpc":
        node["grpc-service"] = path
    elif net in ("h2", "http"):
        node["h2-path"] = path or "/"
        if host:
            node["h2-host"] = host
    elif net == "tcp" and (j.get("type") == "http"):
        node["header-type"] = "http"
        node["http-path"] = path or "/"
        if host:
            node["http-host"] = host
    return node


def _parse_transport_from_query(node, q):
    """Internal helper."""
    net = get1(q, "type", "network", default="tcp") or "tcp"
    node["network"] = net
    host = get1(q, "host", default="")
    path = get1(q, "path", default="")
    sname = get1(q, "serviceName", "servicename", default="")
    htype = get1(q, "headerType", default="")
    if net == "ws":
        node["ws-path"] = unquote(path) if path else "/"
        if host:
            node["ws-host"] = host
    elif net == "grpc":
        node["grpc-service"] = sname or path
    elif net in ("h2", "http"):
        node["h2-path"] = unquote(path) if path else "/"
        if host:
            node["h2-host"] = host
    elif net == "xhttp":
        node["xhttp-path"] = unquote(path) if path else "/"
        if host:
            node["xhttp-host"] = host
        mode = get1(q, "mode", default="")
        if mode:
            node["xhttp-mode"] = mode
        extra = get1(q, "extra", default="")
        if extra:
            try:  
                node["xhttp-extra"] = json.loads(extra)
            except Exception:
                pass
        _preserve_unknown_xhttp_query(node, q)
    elif net == "tcp" and htype == "http":
        node["header-type"] = "http"
        if path:
            node["http-path"] = unquote(path)
        if host:
            node["http-host"] = host


def _parse_tls_from_query(node, q):
    sec = get1(q, "security", default="")
    sni = get1(q, "sni", "peer", default="")
    fp = get1(q, "fp", default="")
    alpn = get1(q, "alpn", default="")
    if sec in ("tls", "reality", "xtls"):
        node["tls"] = True
    if sni:
        node["sni"] = sni
    if fp:
        node["fp"] = fp
    if alpn:
        node["alpn"] = [a for a in unquote(alpn).replace(",", " ").split() if a]
    if truthy(get1(q, "allowInsecure", "insecure", default="0")):
        node["skip-cert-verify"] = True
    if sec == "reality":
        node["reality"] = True
        pbk = get1(q, "pbk", "publicKey", default="")
        sid = get1(q, "sid", "shortId", default="")
        if pbk:
            node["reality-pbk"] = pbk
        if sid:
            node["reality-sid"] = sid


def parse_vless(uri):
    u = urlparse(uri)
    q = parse_qs(u.query, keep_blank_values=True)
    node = {"type": "vless", "name": unquote(u.fragment) if u.fragment else "",
            "server": u.hostname or "", "port": int(u.port or 0),
            "uuid": unquote(u.username or "")}
    flow = get1(q, "flow", default="")
    if flow:
        node["flow"] = flow
    _parse_tls_from_query(node, q)
    _parse_transport_from_query(node, q)
    return node


def parse_trojan(uri):
    u = urlparse(uri)
    q = parse_qs(u.query, keep_blank_values=True)
    node = {"type": "trojan", "name": unquote(u.fragment) if u.fragment else "",
            "server": u.hostname or "", "port": int(u.port or 0),
            "password": unquote(u.username or "")}
    node["tls"] = True  # trojan defaults to TLS
    _parse_tls_from_query(node, q)
    _parse_transport_from_query(node, q)
    return node


def parse_hysteria2(uri):
    u = urlparse(uri)
    q = parse_qs(u.query)
    node = {"type": "hysteria2", "name": unquote(u.fragment) if u.fragment else "",
            "server": u.hostname or "", "port": int(u.port or 0),
            "password": unquote(u.username or "")}
    sni = get1(q, "sni", "peer", default="")
    if sni:
        node["sni"] = sni
    if truthy(get1(q, "insecure", "allowInsecure", default="0")):
        node["skip-cert-verify"] = True
    obfs = get1(q, "obfs", default="")
    if obfs:
        node["obfs"] = obfs
        opw = get1(q, "obfs-password", "obfsParam", default="")
        if opw:
            node["obfs-password"] = opw
    for k_link, k_node in (("up", "up"), ("down", "down"),
                           ("upmbps", "up"), ("downmbps", "down")):
        v = get1(q, k_link, default="")
        if v:
            node[k_node] = v
    alpn = get1(q, "alpn", default="")
    if alpn:
        node["alpn"] = [a for a in unquote(alpn).replace(",", " ").split() if a]
    return node


def parse_hysteria(uri):
    u = urlparse(uri)
    q = parse_qs(u.query)
    node = {"type": "hysteria", "name": unquote(u.fragment) if u.fragment else "",
            "server": u.hostname or "", "port": int(u.port or 0)}
    auth = get1(q, "auth", "auth_str", default="")
    if auth:
        node["auth"] = auth
    peer = get1(q, "peer", "sni", default="")
    if peer:
        node["sni"] = peer
    if truthy(get1(q, "insecure", default="0")):
        node["skip-cert-verify"] = True
    for kl, kn in (("upmbps", "up"), ("downmbps", "down")):
        v = get1(q, kl, default="")
        if v:
            node[kn] = v
    proto = get1(q, "protocol", default="")
    if proto:
        node["hy-protocol"] = proto
    obfs = get1(q, "obfs", "obfsParam", default="")
    if obfs:
        node["obfs"] = obfs
    alpn = get1(q, "alpn", default="")
    if alpn:
        node["alpn"] = [a for a in unquote(alpn).replace(",", " ").split() if a]
    return node


def parse_socks(uri):
    scheme = uri.split("://", 1)[0]
    body = uri.split("://", 1)[1]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = unquote(frag)
    if body.startswith("?"):
        body = body[1:]
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    user = password = ""
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            dec = b64d(userinfo)
            if ":" in dec:
                user, password = dec.split(":", 1)
            else:
                user = dec
        except Exception:
            if ":" in userinfo:
                user, password = unquote(userinfo).split(":", 1)
    else:
        # Some socks links encode the body as base64 userinfo.
        try:
            dec = b64d(body)
            if "@" in dec:
                userinfo, hostport = dec.rsplit("@", 1)
                if ":" in userinfo:
                    user, password = userinfo.split(":", 1)
            else:
                hostport = dec
        except Exception:
            hostport = body
    host, port = hostport.rsplit(":", 1)
    node = {"type": "socks5", "name": name, "server": host, "port": int(port)}
    if user:
        node["username"] = user
    if password:
        node["password"] = password
    return node


LINK_PARSERS = {
    "ss": parse_ss, "vmess": parse_vmess, "vless": parse_vless,
    "trojan": parse_trojan, "hysteria2": parse_hysteria2, "hy2": parse_hysteria2,
    "hysteria": parse_hysteria, "hy": parse_hysteria,
    "socks": parse_socks, "socks5": parse_socks,
}


def parse_link(uri):
    uri = uri.strip()
    scheme = uri.split("://", 1)[0].lower()
    fn = LINK_PARSERS.get(scheme)
    if not fn:
        raise ValueError("unsupported link scheme: %s" % scheme)
    return fn(uri)


# ----------------------------- node -> link ------------------------------
def _frag(name):
    return "#" + quote(name, safe="") if name else ""


def emit_ss(n):
    userinfo = b64e("%s:%s" % (n.get("cipher", ""), n.get("password", "")),
                    urlsafe=True, pad=False)
    base = "ss://%s@%s:%s" % (userinfo, n["server"], n["port"])
    if n.get("plugin") == "obfs":
        o = n.get("plugin-opts", {})
        p = "obfs-local;obfs=%s" % o.get("mode", "http")
        if o.get("host"):
            p += ";obfs-host=%s" % o["host"]
        base += "?plugin=" + quote(p, safe="")
    elif n.get("plugin") == "v2ray-plugin":
        o = n.get("plugin-opts", {})
        p = "v2ray-plugin;mode=%s" % o.get("mode", "websocket")
        if o.get("tls"):
            p += ";tls"
        if o.get("host"):
            p += ";host=%s" % o["host"]
        if o.get("path"):
            p += ";path=%s" % o["path"]
        base += "?plugin=" + quote(p, safe="")
    return base + _frag(n.get("name", ""))


def emit_vmess(n):
    j = {"v": "2", "ps": n.get("name", ""), "add": n["server"], "port": str(n["port"]),
         "id": n["uuid"], "aid": str(n.get("alterId", 0)),
         "scy": n.get("cipher", "auto"), "net": n.get("network", "tcp"),
         "type": "none", "host": "", "path": "", "tls": "", "sni": "", "alpn": ""}
    net = n.get("network", "tcp")
    if net == "ws":
        j["path"] = n.get("ws-path", "/")
        j["host"] = n.get("ws-host", "")
    elif net == "grpc":
        j["path"] = n.get("grpc-service", "")
    elif net in ("h2", "http"):
        j["path"] = n.get("h2-path", "/")
        h2host = n.get("h2-host", "")
        j["host"] = h2host[0] if isinstance(h2host, list) else h2host
    elif net == "tcp" and n.get("header-type") == "http":
        j["type"] = "http"
        j["path"] = n.get("http-path", "/")
        j["host"] = n.get("http-host", "")
    if n.get("tls"):
        j["tls"] = "tls"
        j["sni"] = n.get("sni") or n.get("ws-host") or n["server"]
    if n.get("alpn"):
        j["alpn"] = ",".join(n["alpn"])
    if n.get("fp"):
        j["fp"] = n["fp"]
    return "vmess://" + b64e(json.dumps(j, ensure_ascii=False))


def _build_transport_query(n, q):
    net = n.get("network", "tcp")
    if net and net != "tcp":
        q["type"] = net
    else:
        q["type"] = "tcp"
    if net == "ws":
        if n.get("ws-path"):
            q["path"] = n["ws-path"]
        if n.get("ws-host"):
            q["host"] = n["ws-host"]
    elif net == "grpc":
        if n.get("grpc-service"):
            q["serviceName"] = n["grpc-service"]
    elif net in ("h2", "http"):
        if n.get("h2-path"):
            q["path"] = n["h2-path"]
        h2h = n.get("h2-host")
        if h2h:  # link host is a single value; take the first if a list
            q["host"] = h2h[0] if isinstance(h2h, list) else h2h
    elif net == "xhttp":
        q["path"] = n.get("xhttp-path", "/")
        if n.get("xhttp-host"):
            q["host"] = n["xhttp-host"]
        if n.get("xhttp-mode"):
            q["mode"] = n["xhttp-mode"]
        if n.get("xhttp-extra"):
            q["extra"] = json.dumps(n["xhttp-extra"], ensure_ascii=False,
                                    separators=(",", ":"))
        for k, v in n.get("xhttp-query-extra", {}).items():
            if k not in q:
                q[k] = v
    elif net == "tcp" and n.get("header-type") == "http":
        q["headerType"] = "http"
        if n.get("http-path"):
            q["path"] = n["http-path"]
        if n.get("http-host"):
            q["host"] = n["http-host"]


def _build_tls_query(n, q, default_security=""):
    if n.get("reality"):
        q["security"] = "reality"
        if n.get("reality-pbk"):
            q["pbk"] = n["reality-pbk"]
        if n.get("reality-sid"):
            q["sid"] = n["reality-sid"]
    elif n.get("tls"):
        q["security"] = "tls"
    elif default_security:
        q["security"] = default_security
    else:
        q["security"] = "none"
    if n.get("sni"):
        q["sni"] = n["sni"]
    if n.get("fp"):
        q["fp"] = n["fp"]
    if n.get("alpn"):
        q["alpn"] = ",".join(n["alpn"])
    if n.get("skip-cert-verify"):
        q["allowInsecure"] = "1"


def emit_vless(n):
    q = {"encryption": "none"}
    _build_tls_query(n, q)
    _build_transport_query(n, q)
    if n.get("flow"):
        q["flow"] = n["flow"]
    query = encode_query(q)
    return "vless://%s@%s:%s?%s%s" % (n["uuid"], n["server"], n["port"],
                                      query, _frag(n.get("name", "")))


def emit_trojan(n):
    q = {}
    _build_tls_query(n, q, default_security="tls")
    if q.get("security") == "none":  # trojan defaults to TLS
        q["security"] = "tls"
    if not q.get("sni"):  # align with mihomo: default SNI to server address
        q["sni"] = n["server"]
    _build_transport_query(n, q)
    query = encode_query(q)
    return "trojan://%s@%s:%s?%s%s" % (quote(n.get("password", ""), safe=""), n["server"],
                                       n["port"], query, _frag(n.get("name", "")))


def emit_hysteria2(n):
    q = {}
    q["sni"] = n["sni"] if n.get("sni") else n["server"]
    if n.get("skip-cert-verify"):
        q["insecure"] = "1"
    if n.get("obfs"):
        q["obfs"] = n["obfs"]
        if n.get("obfs-password"):
            q["obfs-password"] = n["obfs-password"]
    if n.get("up"):
        q["up"] = n["up"]
    if n.get("down"):
        q["down"] = n["down"]
    if n.get("alpn"):
        q["alpn"] = ",".join(n["alpn"])
    query = ("?" + encode_query(q)) if q else ""
    return "hysteria2://%s@%s:%s%s%s" % (quote(n.get("password", ""), safe=""),
                                         n["server"], n["port"], query,
                                         _frag(n.get("name", "")))


def emit_hysteria(n):
    q = {}
    if n.get("auth"):
        q["auth"] = n["auth"]
    if n.get("sni"):
        q["peer"] = n["sni"]
    if n.get("skip-cert-verify"):
        q["insecure"] = "1"
    if n.get("up"):
        q["upmbps"] = n["up"]
    if n.get("down"):
        q["downmbps"] = n["down"]
    if n.get("hy-protocol"):
        q["protocol"] = n["hy-protocol"]
    if n.get("obfs"):
        q["obfs"] = n["obfs"]
    if n.get("alpn"):
        q["alpn"] = ",".join(n["alpn"])
    query = ("?" + encode_query(q)) if q else ""
    return "hysteria://%s:%s%s%s" % (n["server"], n["port"], query,
                                     _frag(n.get("name", "")))


def emit_socks(n):
    if n.get("username") or n.get("password"):
        userinfo = b64e("%s:%s" % (n.get("username", ""), n.get("password", "")),
                        pad=False)
        return "socks://%s@%s:%s%s" % (userinfo, n["server"], n["port"],
                                       _frag(n.get("name", "")))
    return "socks://%s:%s%s" % (n["server"], n["port"], _frag(n.get("name", "")))


LINK_EMITTERS = {
    "ss": emit_ss, "vmess": emit_vmess, "vless": emit_vless, "trojan": emit_trojan,
    "hysteria2": emit_hysteria2, "hysteria": emit_hysteria, "socks5": emit_socks,
    "socks": emit_socks,
}


def emit_link(n):
    fn = LINK_EMITTERS.get(n["type"])
    if not fn:
        raise ValueError("unsupported link type: %s" % n["type"])
    return fn(n)


# ----------------------------- clash <-> node ------------------------------
def clash_to_node(p):
    t = p.get("type")
    node = {"type": "socks5" if t == "socks5" else t,
            "name": p.get("name", ""), "server": p.get("server", ""),
            "port": int(p.get("port", 0) or 0)}
    node["_clash"] = dict(p)
    if p.get("udp") is not None:
        node["udp"] = bool(p["udp"])
    if t == "ss":
        node["cipher"] = p.get("cipher", "")
        node["password"] = p.get("password", "")
        if p.get("plugin"):
            node["plugin"] = p["plugin"]
            node["plugin-opts"] = p.get("plugin-opts", {})
        return node
    if t == "vmess":
        node["uuid"] = p.get("uuid", "")
        node["alterId"] = int(p.get("alterId", 0) or 0)
        node["cipher"] = p.get("cipher", "auto")
    elif t == "vless":
        node["uuid"] = p.get("uuid", "")
        if p.get("flow"):
            node["flow"] = p["flow"]
    elif t == "trojan":
        node["password"] = p.get("password", "")
        node["tls"] = True
    elif t == "hysteria2":
        node["password"] = p.get("password", "") or p.get("auth", "")
        if p.get("obfs"):
            node["obfs"] = p["obfs"]
        if p.get("obfs-password"):
            node["obfs-password"] = p["obfs-password"]
        if p.get("up"):
            node["up"] = str(p["up"])
        if p.get("down"):
            node["down"] = str(p["down"])
    elif t == "hysteria":
        node["auth"] = p.get("auth-str", "") or p.get("auth_str", "") or p.get("auth", "")
        if p.get("protocol"):
            node["hy-protocol"] = p["protocol"]
        if p.get("obfs"):
            node["obfs"] = p["obfs"]
        if p.get("up"):
            node["up"] = str(p["up"])
        if p.get("down"):
            node["down"] = str(p["down"])
    elif t == "socks5":
        if p.get("username"):
            node["username"] = p["username"]
        if p.get("password"):
            node["password"] = p["password"]
        return node
    elif t == "http":
        if p.get("username"):
            node["username"] = p["username"]
        if p.get("password"):
            node["password"] = p["password"]
        if p.get("tls"):
            node["tls"] = True
        sni = p.get("sni") or p.get("servername")
        if sni:
            node["sni"] = sni
        if p.get("skip-cert-verify"):
            node["skip-cert-verify"] = True
        return node

    # Common TLS/SNI and transport options.
    if p.get("tls"):
        node["tls"] = True
    sni = p.get("servername") or p.get("sni")
    if sni:
        node["sni"] = sni
    if p.get("client-fingerprint") or p.get("fingerprint"):
        node["fp"] = p.get("client-fingerprint") or p.get("fingerprint")
    if p.get("skip-cert-verify"):
        node["skip-cert-verify"] = True
    if p.get("alpn"):
        node["alpn"] = p["alpn"] if isinstance(p["alpn"], list) else [p["alpn"]]
    if p.get("reality-opts"):
        node["tls"] = True
        node["reality"] = True
        ro = p["reality-opts"]
        if ro.get("public-key"):
            node["reality-pbk"] = ro["public-key"]
        if ro.get("short-id"):
            node["reality-sid"] = str(ro["short-id"])
    net = p.get("network")
    if net:
        node["network"] = net
        if net == "ws":
            wo = p.get("ws-opts", {})
            node["ws-path"] = wo.get("path", "/")
            h = (wo.get("headers") or {}).get("Host") or (wo.get("headers") or {}).get("host")
            if h:
                node["ws-host"] = h
        elif net == "grpc":
            go = p.get("grpc-opts", {})
            node["grpc-service"] = go.get("grpc-service-name", "")
        elif net in ("h2", "http"):
            ho = p.get("h2-opts", {}) or p.get("http-opts", {})
            node["h2-path"] = ho.get("path", "/") if not isinstance(ho.get("path"), list) \
                else (ho.get("path") or ["/"])[0]
            hosts = ho.get("host") or ho.get("Host")
            if hosts:
                # Keep the full list so Clash->Clash rebuild preserves every
                # host; the link layer picks the first one (URI host is single).
                node["h2-host"] = hosts
        elif net == "xhttp":
            xo = p.get("xhttp-opts", {})
            node["xhttp-path"] = xo.get("path", "/")
            if xo.get("host"):
                node["xhttp-host"] = xo["host"]
            if xo.get("mode"):
                node["xhttp-mode"] = xo["mode"]
            if xo.get("extra"):
                node["xhttp-extra"] = xo["extra"]
    return node


def node_to_clash(n):
    if isinstance(n.get("_clash"), dict):
        p = dict(n["_clash"])
        # Re-apply corrections that normalize() may have added to the node body
        # after it was cached (e.g. vless flow implies TLS), so Clash->Clash
        # output reflects them instead of the stale original proxy.
        if n.get("tls") and not p.get("tls"):
            p["tls"] = True
        return p
    t = n["type"]
    p = {"name": n.get("name", ""), "type": t,
         "server": n["server"], "port": n["port"]}
    if n.get("udp"):
        p["udp"] = True
    if t == "ss":
        p["cipher"] = n.get("cipher", "")
        p["password"] = n.get("password", "")
        if n.get("plugin"):
            p["plugin"] = n["plugin"]
            p["plugin-opts"] = n.get("plugin-opts", {})
        return p
    if t in ("socks5", "http"):
        if n.get("username"):
            p["username"] = n["username"]
        if n.get("password"):
            p["password"] = n["password"]
        if n.get("tls"):
            p["tls"] = True
        if n.get("sni"):
            p["sni"] = n["sni"]
        if n.get("skip-cert-verify"):
            p["skip-cert-verify"] = True
        return p
    if t == "vmess":
        p["uuid"] = n.get("uuid", "")
        p["alterId"] = n.get("alterId", 0)
        p["cipher"] = n.get("cipher", "auto")
    elif t == "vless":
        p["uuid"] = n.get("uuid", "")
        if n.get("flow"):
            p["flow"] = n["flow"]
    elif t == "trojan":
        p["password"] = n.get("password", "")
    elif t == "hysteria2":
        p["password"] = n.get("password", "")
        if n.get("obfs"):
            p["obfs"] = n["obfs"]
        if n.get("obfs-password"):
            p["obfs-password"] = n["obfs-password"]
        if n.get("up"):
            p["up"] = n["up"]
        if n.get("down"):
            p["down"] = n["down"]
    elif t == "hysteria":
        if n.get("auth"):
            p["auth-str"] = n["auth"]
        if n.get("hy-protocol"):
            p["protocol"] = n["hy-protocol"]
        if n.get("obfs"):
            p["obfs"] = n["obfs"]
        if n.get("up"):
            p["up"] = n["up"]
        if n.get("down"):
            p["down"] = n["down"]

    if n.get("tls") and t != "trojan":  # trojan implies TLS
        p["tls"] = True
    if n.get("sni"):
        # Clash uses servername for vmess/vless.
        if t in ("vmess", "vless"):
            p["servername"] = n["sni"]
        else:
            p["sni"] = n["sni"]
    if n.get("fp"):
        p["client-fingerprint"] = n["fp"]
    if n.get("skip-cert-verify"):
        p["skip-cert-verify"] = True
    if n.get("alpn"):
        p["alpn"] = n["alpn"]
    if n.get("reality"):
        ro = {}
        if n.get("reality-pbk"):
            ro["public-key"] = n["reality-pbk"]
        if n.get("reality-sid"):
            ro["short-id"] = n["reality-sid"]
        p["reality-opts"] = ro
    net = n.get("network")
    if net and net != "tcp":
        p["network"] = net
        if net == "ws":
            wo = {"path": n.get("ws-path", "/")}
            if n.get("ws-host"):
                wo["headers"] = {"Host": n["ws-host"]}
            p["ws-opts"] = wo
        elif net == "grpc":
            p["grpc-opts"] = {"grpc-service-name": n.get("grpc-service", "")}
        elif net in ("h2", "http"):
            ho = {"path": n.get("h2-path", "/")}
            if n.get("h2-host"):
                h = n["h2-host"]
                ho["host"] = h if isinstance(h, list) else [h]
            p["h2-opts"] = ho
        elif net == "xhttp":
            xo = {"path": n.get("xhttp-path", "/")}
            if n.get("xhttp-host"):
                xo["host"] = n["xhttp-host"]
            if n.get("xhttp-mode"):
                xo["mode"] = n["xhttp-mode"]
            if n.get("xhttp-extra"):
                xo["extra"] = n["xhttp-extra"]
            p["xhttp-opts"] = xo
    elif net == "tcp" and n.get("header-type") == "http":
        p["network"] = "tcp"
    return p

def normalize(node):
    """Internal helper."""
    if node.get("type") == "vless":
        flow = node.get("flow", "")
        # vless vision/xtls requires TLS semantics.
        if flow and not node.get("tls") and not node.get("reality"):
            node["tls"] = True
    return node


def load_nodes(content, _depth=0):
    content = content.strip()
    if not content or _depth > 3:
        return []

    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and data.get("proxies"):
            nodes = []
            for p in data["proxies"]:
                if not isinstance(p, dict):
                    continue
                try:
                    nodes.append(normalize(clash_to_node(p)))
                except Exception as e:
                    sys.stderr.write("[skip proxy] %s (%s)\n" %
                                     (p.get("name", ""), e))
            return nodes
    except Exception:
        pass

    if "://" not in content.split("\n", 1)[0]:
        dec = try_b64_text(content)
        if dec is not None:
            return load_nodes(dec, _depth + 1)

    nodes = []
    for line in content.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        try:
            nodes.append(normalize(parse_link(line)))
        except Exception as e:
            sys.stderr.write("[skip] %s ... (%s)\n" % (line[:40], e))
    return nodes


def dump_clash(nodes):
    proxies = [node_to_clash(n) for n in nodes]
    return yaml.safe_dump({"proxies": proxies}, allow_unicode=True,
                          default_flow_style=False, sort_keys=False, width=4096)


def dump_links(nodes):
    out = []
    for n in nodes:
        link_type = n.get("type", "")
        if link_type not in LINK_EMITTERS:
            sys.stderr.write("[skip export] %s (unsupported link type: %s)\n" %
                             (n.get("name", ""), link_type))
            continue
        try:
            out.append(emit_link(n))
        except Exception as e:
            sys.stderr.write("[skip export] %s (%s)\n" %
                             (n.get("name", ""), e))
    return "\n".join(out)


def render(nodes, target):
    """Internal helper."""
    if target == "clash":
        return dump_clash(nodes)
    if target == "links":
        return dump_links(nodes)
    # v2ray / base64
    return b64e(dump_links(nodes))


TARGET_EXT = {"clash": ".yaml", "v2ray": ".txt", "base64": ".txt", "links": ".txt"}

def cmd_convert(args):
    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    nodes = load_nodes(content)
    if not nodes:
        sys.stderr.write("No nodes were parsed.\n")
        sys.exit(2)
    sys.stderr.write("Parsed %d nodes: %s\n" %
                     (len(nodes), ", ".join(sorted({n["type"] for n in nodes}))))

    result = render(nodes, args.to)

    out_path = args.out
    if not out_path:
        in_dir = os.path.dirname(os.path.abspath(args.input))
        out_path = os.path.join(in_dir, "sub" + TARGET_EXT[args.to])

    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(result if result.endswith("\n") else result + "\n")
    sys.stderr.write("Wrote %s\n" % out_path)

def _make_server(host, port, default_src=""):
    import urllib.request
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    def fetch_one(src):
        src = src.strip()
        if src.lower().startswith(("http://", "https://")):
            req = urllib.request.Request(
                src, headers={"User-Agent": "convert-local/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode("utf-8", "replace")
        with open(src, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    def collect_nodes(url_param):
        nodes = []
        for src in url_param.split("|"):
            src = src.strip()
            if not src:
                continue
            nodes.extend(load_nodes(fetch_one(src)))
        return nodes

    def build_index(real_host, real_port):
        base = "http://%s:%d/sub" % (real_host, real_port)
        lines = ["Local subscription service is running.\n"]
        if default_src:
            lines.append("Default source: %s\n" % default_src)
            lines.append("Subscription URLs:")
            lines.append("  clash : %s?target=clash" % base)
            lines.append("  v2rayN: %s?target=v2ray" % base)
            lines.append("")
            lines.append("Advanced targets:")
            for t in ("base64", "links"):
                lines.append("  %s?target=%s" % (base, t))
            lines.append("")
            lines.append("Append &url=<source> to temporarily override the default source.")
        else:
            lines.append("Subscription URLs:")
            lines.append("  %s?target=clash&url=<source>" % base)
            lines.append("  %s?target=v2ray&url=<source>" % base)
            lines.append("")
            lines.append("Advanced targets: base64 | links")
            lines.append("source: local file path / remote URL / sources joined by |")
            lines.append("Tip: for local paths, prefer --src or main.bat generated URLs.")
        return "\n".join(lines) + "\n"

    class Handler(BaseHTTPRequestHandler):
        server_version = "convert-local/1.0"

        def _send(self, code, body, ctype="text/plain; charset=utf-8"):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                self._send(200, build_index(self.server.server_address[0],
                                            self.server.server_address[1]))
                return
            if u.path != "/sub":
                self._send(404, "Not found. Use /sub?target=...&url=...\n")
                return

            q = parse_qs(u.query)
            target = (q.get("target", ["clash"])[0] or "clash").lower()
            url_param = unquote(q.get("url", [""])[0]) or default_src

            if target not in ("clash", "v2ray", "base64", "links"):
                self._send(400, "Invalid target: %s (clash|v2ray|base64|links)\n" % target)
                return
            if not url_param:
                self._send(400, "Missing url parameter and no --src default source was set.\n")
                return

            try:
                nodes = collect_nodes(url_param)
            except FileNotFoundError as e:
                self._send(400, "Source file not found: %s\n" % e)
                return
            except Exception as e:
                self._send(400, "Failed to fetch or parse source: %s\n" % e)
                return

            if not nodes:
                self._send(400, "No nodes were found.\n")
                return

            ctype = "text/yaml; charset=utf-8" if target == "clash" \
                else "text/plain; charset=utf-8"
            body = render(nodes, target)
            kinds = ", ".join(sorted({n["type"] for n in nodes}))
            sys.stderr.write("[%s] target=%s  %d nodes (%s)\n" %
                             (self.address_string(), target, len(nodes), kinds))
            self._send(200, body, ctype)

        def log_message(self, *a):
            pass

    return ThreadingHTTPServer((host, port), Handler)


def cmd_serve(args):
    default_src = (args.src or "").strip()
    srv = _make_server(args.host, args.port, default_src)
    sys.stderr.write("Local subscription service started: http://%s:%d/\n" % (args.host, args.port))
    base = "http://%s:%d/sub" % (args.host, args.port)
    if default_src:
        sys.stderr.write("Default source: %s\n" % default_src)
        sys.stderr.write("Subscription URLs:\n")
        sys.stderr.write("  clash : %s?target=clash\n" % base)
        sys.stderr.write("  v2rayN: %s?target=v2ray\n" % base)
        sys.stderr.write("Advanced exports: %s?target=base64 / links\n" % base)
    else:
        sys.stderr.write("No default source; include url=. Example: %s?target=clash&url=a.txt\n" % base)
        sys.stderr.write("v2rayN example: %s?target=v2ray&url=a.txt\n" % base)
        sys.stderr.write("Tip: use --src \"C:\\path\\a.txt\" to avoid putting local paths in url=.\n")
    sys.stderr.write("Press Ctrl+C to stop.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nStopped.\n")
        srv.shutdown()


# ============================================================================
# Entrypoint: convert / serve
# ============================================================================
def main():
    ap = argparse.ArgumentParser(
        description="Subscription tool: Clash / v2rayN conversion + local subscription service; base64/links are advanced exports")
    sub = ap.add_subparsers(dest="mode", required=True)

    pc = sub.add_parser("convert", help="convert one input file")
    pc.add_argument("input", help="input file")
    pc.add_argument("--to", required=True,
                    choices=["clash", "v2ray", "base64", "links"],
                    help="target format; common: clash/v2ray, advanced: base64/links")
    pc.add_argument("-o", "--out",
                    help="output file; default is sub.* next to the input file")
    pc.set_defaults(func=cmd_convert)

    ps = sub.add_parser("serve", help="start local subscription service")
    ps.add_argument("--host", default="127.0.0.1",
                    help="listen host; default 127.0.0.1")
    ps.add_argument("--port", type=int, default=25500,
                    help="listen port; default 25500")
    ps.add_argument("--src", default="",
                    help="default source: local file, remote URL, or sources joined by |")
    ps.set_defaults(func=cmd_serve)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
