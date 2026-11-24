"""MIRA DNS shield: a small resolver that refuses scam domains and forwards everything else.

    python dns_shield.py --port 5353 --api http://localhost:8000 --upstream 1.1.1.1
    dig @127.0.0.1 -p 5353 emiratespost-redelivery.com      -> NXDOMAIN (blocked)

Point a test phone's DNS at this server (Android: Wi-Fi settings > static DNS, or a DoT front end
for Private DNS). The blocklist is pulled from the MIRA API every 30 seconds, so an officer's
"antibody" reaches every phone within half a minute.
"""
import argparse
import threading
import time

import requests
from dnslib import QTYPE, RCODE, RR, A
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer


class ShieldResolver(ProxyResolver):
    def __init__(self, upstream, api, sinkhole=None):
        super().__init__(upstream, 53, 5)
        self.api, self.sinkhole, self.blocked = api, sinkhole, set()
        threading.Thread(target=self._refresh, daemon=True).start()

    def _refresh(self):
        while True:
            try:
                txt = requests.get(f"{self.api}/api/blocklist.txt", timeout=5).text
                self.blocked = {l.strip().lower() for l in txt.splitlines() if l.strip()}
            except requests.RequestException:
                pass
            time.sleep(30)

    def _is_blocked(self, name):
        parts = name.rstrip(".").lower().split(".")
        return any(".".join(parts[i:]) in self.blocked for i in range(len(parts) - 1))

    def resolve(self, request, handler):
        name = str(request.q.qname)
        if self._is_blocked(name):
            reply = request.reply()
            if self.sinkhole and request.q.qtype == QTYPE.A:
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.sinkhole), ttl=30))
            else:
                reply.header.rcode = RCODE.NXDOMAIN
            print(f"[blocked] {name}", flush=True)
            return reply
        return super().resolve(request, handler)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5353)
    ap.add_argument("--upstream", default="1.1.1.1")
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--sinkhole", help="IP of the MIRA server, to show the warning page for plain-HTTP visits")
    a = ap.parse_args()
    srv = DNSServer(ShieldResolver(a.upstream, a.api, a.sinkhole), port=a.port, address="0.0.0.0")
    srv.start_thread()
    print(f"MIRA DNS shield on :{a.port}, upstream {a.upstream}")
    while True:
        time.sleep(3600)
