"""ScamCast: scams follow the calendar. Before each UAE event, pre-generate the fake domains scammers are
likely to register, so the hunter is already watching for them when they appear."""
import datetime as dt

from .brands import BRANDS

# Recurring UAE scam seasons from police advisories. Month ranges are inclusive; fixed dates where they exist.
SEASONS = [
    {"id": "salary", "name": "Salary payment period", "name_ar": "فترة صرف الرواتب", "when": "25th to 3rd, every month",
     "brands": ["adcb", "fab", "enbd", "adib", "mashreq", "cbuae"], "lures": ["salary", "bonus", "update", "kyc", "card"]},
    {"id": "national_day", "name": "Eid Al Etihad (2 December)", "name_ar": "عيد الاتحاد (2 ديسمبر)", "months": [11, 12],
     "brands": ["etisalat", "du", "uaegov", "tamm"], "lures": ["gift", "free", "data", "reward", "53gb"]},
    {"id": "global_village", "name": "Global Village season", "name_ar": "موسم القرية العالمية", "months": [10, 11, 12, 1, 2, 3, 4],
     "brands": ["globalvillage"], "lures": ["vip", "pack", "tickets", "offer", "discount"]},
    {"id": "winter_events", "name": "Winter events, concerts and New Year’s Eve", "name_ar": "فعاليات الشتاء ورأس السنة", "months": [11, 12, 1],
     "brands": ["dubaiopera", "yasisland", "louvreabudhabi"], "lures": ["tickets", "nye", "offer", "booking", "vip"]},
    {"id": "summer", "name": "Summer travel and waterparks", "name_ar": "السفر الصيفي والحدائق المائية", "months": [6, 7, 8],
     "brands": ["yasisland", "aquaventure", "wildwadi", "emiratesair", "etihad"], "lures": ["tickets", "offer", "booking", "deal", "family"]},
    {"id": "always", "name": "Year-round: fines, tolls, parcels, UAE PASS", "name_ar": "طوال العام: المخالفات والتعرفة والطرود والهوية الرقمية",
     "months": list(range(1, 13)),
     "brands": ["adpolice", "darb", "salik", "emiratespost", "aramex", "uaepass", "icp"], "lures": ["pay", "fine", "toll", "track", "verify", "renew"]},
]
TLDS = ["com", "net", "online", "site", "top", "xyz", "shop", "info", "live", "click", "ae.com", "com.co"]


def active(today: dt.date | None = None) -> list[dict]:
    today = today or dt.date.today()
    out = []
    for s in SEASONS:
        if s["id"] == "salary":
            on = today.day >= 25 or today.day <= 3
        else:
            on = today.month in s["months"]
        if on:
            out.append(s)
    return out


def predicted_domains(season: dict, per_brand: int = 40) -> list[str]:
    by_id = {b["id"]: b for b in BRANDS}
    doms = []
    for bid in season["brands"]:
        b = by_id.get(bid)
        if not b:
            continue
        base = [k.replace("-", "") for k in b["keywords"] if len(k.replace("-", "")) >= 4][:2]
        names = []
        for k in base:
            for lure in season["lures"]:
                names += [f"{k}-{lure}", f"{lure}-{k}", f"{k}{lure}"]
        for i, n in enumerate(names[:per_brand]):
            doms.append(f"{n}.{TLDS[i % len(TLDS)]}")
    return sorted(set(doms))


def forecast(today: dt.date | None = None) -> list[dict]:
    return [{**{k: v for k, v in s.items() if k != "months"},
             "watchlist_size": len(predicted_domains(s)), "sample": predicted_domains(s)[:8]} for s in active(today)]
