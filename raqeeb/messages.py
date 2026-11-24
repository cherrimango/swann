"""Check a whole SMS / WhatsApp message: every link in it plus the scam script around the link (EN/AR)."""
import re

from .brands import BRANDS
from .engine import scan_many

URL_RX = re.compile(
    r"(?:(?:https?://|www\.)[^\s<>\"']+)|(?:\b[a-z0-9][a-z0-9\-]{1,62}(?:\.[a-z0-9\-]{1,62})*\.(?:com|net|org|info|ae|top|xyz|shop|online|site|live|click|icu|cfd|sbs|vip|io|app|co|me|cc|link|support|help|ly|gl|gd|to|in|uk|be|fr|de)(?:/[^\s<>\"']*)?)",
    re.IGNORECASE)

# Scam scripts seen in UAE advisories: (code, weight, english regex, arabic regex, explanation en, explanation ar)
SCRIPTS = [
    ("urgency", 18, r"\b(urgent|immediately|today|within 24 hours|final notice|last chance|expires? today)\b",
     r"(عاجل|فوراً|فورا|اليوم|خلال 24 ساعة|إشعار نهائي|آخر فرصة)", "Pressure to act now", "ضغط للتصرف فوراً"),
    ("blocked", 22, r"\b(blocked|suspended|deactivated|locked|frozen|will be (closed|suspended))\b",
     r"(تم إيقاف|تم حظر|موقوف|سيتم إيقاف|مجمد|تم تجميد)", "Says your account or card is blocked", "يدّعي أن حسابك أو بطاقتك موقوفة"),
    ("small_fee", 22, r"\b(aed|dh|dhs|dirhams?)\s?\d{1,3}(\.\d{1,2})?\b|\b\d{1,3}(\.\d{1,2})?\s?(aed|dh|dhs|dirhams?)\b",
     r"\d{1,3}\s?(درهم)", "Asks for a small fee", "يطلب رسوماً صغيرة"),
    ("otp", 30, r"\b(otp|one[- ]time (password|code)|verification code|share (the|your) code)\b",
     r"(رمز التحقق|الرمز السري|كلمة المرور لمرة واحدة|أرسل الرمز)", "Asks for a code or OTP", "يطلب رمز تحقق"),
    ("update_details", 18, r"\b(update|verify|confirm) (your )?(details|information|account|card|kyc|emirates id)\b",
     r"(حدّث|حدث|تحديث) (بياناتك|البيانات)|تأكيد (بياناتك|الحساب)", "Asks you to update or verify details", "يطلب تحديث أو تأكيد بياناتك"),
    ("parcel", 15, r"\b(parcel|package|shipment|delivery (failed|attempt)|redeliver|customs fee)\b",
     r"(طرد|شحنة|توصيل|رسوم جمركية)", "Parcel or delivery lure", "طُعم طرد أو توصيل"),
    ("fine_toll", 18, r"\b(traffic (fine|violation)|unpaid (fine|toll)|toll fee|overdue toll|black points)\b",
     r"(مخالفة مرورية|غرامة|رسوم التعرفة|نقاط سوداء|مخالفات)", "Traffic fine or toll lure", "طُعم مخالفة أو تعرفة مرورية"),
    ("prize", 15, r"\b(congratulations|you have won|winner|prize|lucky draw|reward points|points (will )?expire|redeem)\b",
     r"(مبروك|ربحت|فائز|جائزة|سحب|نقاط المكافآت|استبدل)", "Prize or points lure", "طُعم جائزة أو نقاط"),
    ("reply_y", 15, r"\breply\s+y\b|\breply with y\b", r"(أرسل|رد) ب?نعم", "‘Reply Y to open the link’ trick", "حيلة ‘رد بنعم لفتح الرابط’"),
    ("too_cheap", 12, r"\b(\d{2})\s?% off\b|\bdiscount\b|\bonly \d+ (left|tickets)\b",
     r"(خصم|تخفيض|عرض لفترة محدودة)", "Too-good discount or scarcity", "خصم مغرٍ أو ندرة مصطنعة"),
]


# Urdu (Arabic script) and Roman Urdu wording for the same scam scripts.
URDU = {
    "urgency": r"(فوری|ابھی|آج ہی|24 گھنٹے|آخری موقع)|\b(foran|abhi|aaj hi)\b",
    "blocked": r"(بلاک|معطل|بند کر دیا|بند ہو جائے گا)|\b(band ho jayega|block ho gaya)\b",
    "small_fee": r"\d{1,3}\s?(درہم|فیس)",
    "otp": r"(او ٹی پی|تصدیقی کوڈ|کوڈ بھیجیں|کوڈ بتائیں)|\b(otp bhej|code bata|code bhej)",
    "update_details": r"(تفصیلات اپ ڈیٹ|معلومات کی تصدیق|ایمریٹس آئی ڈی)|\b(details update kar)",
    "parcel": r"(پارسل|ڈیلیوری|کسٹم)",
    "fine_toll": r"(جرمانہ|چالان|ٹول)|\b(jurmana|challan)\b",
    "prize": r"(مبارک ہو|انعام|جیت لیا)|\b(inaam|mubarak ho)\b",
    "too_cheap": r"(رعایت|ڈسکاؤنٹ|آفر)",
}


def _brands_named(text: str) -> list[str]:
    low = text.lower()
    out = []
    for b in BRANDS:
        terms = [t for t in b["content_terms"] if len(t) >= 4] + [b["name"].split(" (")[0]]
        if any((t.lower() in low) if t.isascii() else (t in text) for t in terms):
            out.append(b["name"])
    return out[:4]


def check_message(text: str) -> dict:
    text = (text or "")[:4000]
    urls = []
    for m in URL_RX.finditer(text):
        u = m.group(0).rstrip(").,;!؟،")
        if u not in urls:
            urls.append(u)
    link_results = scan_many(urls[:10]) if urls else []
    hits, script_score = [], 0
    for code, w, en_rx, ar_rx, en, ar in SCRIPTS:
        if re.search(en_rx, text, re.IGNORECASE) or re.search(ar_rx, text) or (code in URDU and re.search(URDU[code], text, re.IGNORECASE)):
            hits.append({"code": code, "en": en, "ar": ar, "weight": w})
            script_score += w
    named = _brands_named(text)
    link_risk = max((r["risk_score"] for r in link_results), default=0.0)
    # A message that names a brand, uses a scam script and carries a link is the classic smishing shape.
    risk = max(link_risk, min(95.0, script_score * (1.4 if urls else 0.9) + (10 if named and urls else 0)))
    if link_risk >= 50:
        risk = max(risk, min(100.0, link_risk + script_score * 0.15))
    verdict = "scam" if risk >= 50 else ("suspicious" if risk >= 35 else
                                         "inconclusive" if any(r["verdict"] == "inconclusive" for r in link_results) else "looks safe")
    return {"verdict": verdict, "risk_score": round(risk, 1), "links": link_results, "script_signals": hits,
            "brands_named": named, "advice_en": _advice(verdict, hits, "en"), "advice_ar": _advice(verdict, hits, "ar")}


def _advice(verdict, hits, lang):
    codes = {h["code"] for h in hits}
    if verdict == "looks safe":
        return "No scam signs found. Still open services from the official app, not from links." if lang == "en" \
            else "لا توجد علامات احتيال. افتح الخدمات من التطبيق الرسمي دائماً وليس من الروابط."
    if verdict == "inconclusive":
        return ("No scam wording found, but the link goes to a site SAWNN can't vouch for yet. Run a deep check or open the "
                "service from its official app.") if lang == "en" else \
            "لا توجد عبارات احتيال، لكن الرابط يؤدي إلى موقع لا تستطيع صون التحقق منه بعد. افحصه فحصاً عميقاً أو افتح الخدمة من تطبيقها الرسمي."
    if "otp" in codes:
        return "Never share a code. No bank or government entity will ask for it." if lang == "en" \
            else "لا تشارك أي رمز. لا يطلبه أي بنك أو جهة حكومية."
    return "Don’t open the link or pay. Report it to Aman (8002626 or SMS 2828)." if lang == "en" \
        else "لا تفتح الرابط ولا تدفع. أبلغ خدمة أمان (8002626 أو رسالة إلى 2828)."
