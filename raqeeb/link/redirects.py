"""Redirect-chain analysis for the SAWNN sandbox.

Input: the navigation responses the sandbox recorded (status + URL for every main-frame navigation, including
client-side JavaScript / meta-refresh redirects, which show up as further navigations with status 200).
Output: one entry per hop plus a summary that says whether every destination was analysed and, if not, why.
Nothing is truncated silently: if the chain hits the hop limit, `stopped_reason` says so.
"""
from ..urlparse import SHORTENERS, parse

MAX_HOPS = 20
HTTP_REDIRECT = {301: "permanent (301)", 302: "temporary (302)", 303: "see other (303)", 307: "temporary (307)", 308: "permanent (308)"}


def analyse(chain: list[dict], submitted: str, final_url: str | None, stop_error: str | None = None,
            blocked: list[str] | None = None) -> dict:
    hops, seen, loop = [], set(), False
    prev_reg = parse(submitted).registered_domain
    for i, h in enumerate(chain[:MAX_HOPS]):
        p = parse(h.get("url", ""))
        status = h.get("status")
        nxt = chain[i + 1] if i + 1 < len(chain) else None
        if status in HTTP_REDIRECT:
            kind = "HTTP redirect, " + HTTP_REDIRECT[status]
        elif nxt is not None:
            kind = "client-side redirect (JavaScript or meta refresh)"
        else:
            kind = "final page"
        key = p.url.rstrip("/")
        if key in seen:
            loop = True
        seen.add(key)
        changed = bool(p.registered_domain and prev_reg and p.registered_domain != prev_reg)
        hops.append({"hop": i + 1, "url": h.get("url"), "host": p.host, "registered_domain": p.registered_domain, "status": status,
                     "type": kind, "domain_changed": changed, "shortener": p.registered_domain in SHORTENERS or p.host in SHORTENERS,
                     "https": p.scheme == "https"})
        prev_reg = p.registered_domain or prev_reg
    domains = []
    for h in hops:
        if h["registered_domain"] and h["registered_domain"] not in domains:
            domains.append(h["registered_domain"])
    truncated = len(chain) > MAX_HOPS
    if stop_error:
        reason = f"navigation stopped: {stop_error}"
    elif truncated:
        reason = f"hop limit reached ({MAX_HOPS}); later hops were not followed"
    elif loop:
        reason = "redirect loop detected"
    elif blocked:
        reason = "a hop pointed to an internal or reserved address and was blocked by the SSRF guard"
    else:
        reason = "reached a page that did not redirect further"
    fp = parse(final_url or "")
    suspicious = []
    if len(domains) > 2:
        suspicious.append(f"passes through {len(domains)} different domains")
    if any(h["shortener"] for h in hops):
        suspicious.append("uses a link shortener")
    if any(h["https"] is False for h in hops[1:]) and hops and hops[0]["https"]:
        suspicious.append("drops from HTTPS to plain HTTP")
    if loop:
        suspicious.append("loops")
    return {
        "hops": hops, "redirect_count": max(0, len(hops) - 1), "domains": domains,
        "domain_changes": sum(h["domain_changed"] for h in hops), "loop": loop, "truncated": truncated,
        "shortener_in_chain": any(h["shortener"] for h in hops), "final_url": final_url,
        "final_registered_domain": fp.registered_domain or None,
        "all_destinations_analysed": not (truncated or stop_error or blocked or loop), "stopped_reason": reason,
        "suspicious_patterns": suspicious, "blocked_hops": blocked or [],
    }
