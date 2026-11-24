"""Public content: knowledge centre, scam simulations, brand verification registry, public safety report and
impact figures. Every number here is computed from the database at request time; nothing is invented."""
import json
import time

from .brands import BRANDS, SCAM_TYPES
from .db import db, rows

SECTOR_CONTACT = {  # general guidance only; we never publish phone numbers we have not verified
    "digital_identity": ("Never shares your UAE PASS PIN or OTP by phone, SMS or WhatsApp. Approve logins only that you started yourself.",
                         "لا تشارك رمز UAE PASS أو رمز التحقق عبر الهاتف أو الرسائل. وافق فقط على تسجيل دخول بدأته بنفسك."),
    "government_services": ("Government services are paid only on official .gov.ae / .ae portals or official apps.",
                            "تُدفع رسوم الخدمات الحكومية فقط عبر البوابات الرسمية أو التطبيقات الرسمية."),
    "police_traffic": ("Traffic fines are paid in the official police or MOI app or website, never through a link in an SMS.",
                       "تُدفع المخالفات المرورية عبر تطبيق أو موقع الشرطة الرسمي فقط، وليس عبر رابط في رسالة."),
    "transport_tolls": ("Top up tolls and transport cards in the official app or website only.",
                        "اشحن رصيد التعرفة والبطاقات عبر التطبيق أو الموقع الرسمي فقط."),
    "identity_visa": ("Visa and Emirates ID services are only on the official ICP / GDRFA channels.",
                      "خدمات التأشيرة والهوية فقط عبر القنوات الرسمية للهيئة الاتحادية أو إقامة دبي."),
    "customs": ("Customs never asks you to pay a release fee through a link in a message.",
                "الجمارك لا تطلب رسوم إفراج عبر رابط في رسالة."),
    "employment": ("Legitimate employers never charge job, visa or registration fees.",
                   "أصحاب العمل الحقيقيون لا يطلبون رسوم توظيف أو تأشيرة."),
    "delivery": ("Delivery companies rarely ask for small fees by SMS link; check in the official app.",
                 "شركات التوصيل نادراً ما تطلب رسوماً صغيرة عبر رابط؛ تحقق من التطبيق الرسمي."),
    "banking": ("Your bank will never ask for your card number, PIN, CVV or OTP.",
                "البنك لن يطلب أبداً رقم البطاقة أو الرقم السري أو رمز التحقق."),
    "telecom": ("Points, free data and prizes are claimed only in the official telecom app.",
                "النقاط والباقات المجانية تُستلم فقط عبر تطبيق شركة الاتصالات الرسمي."),
    "attractions": ("Buy tickets only on the attraction's own website or app; huge discounts on social media are a red flag.",
                    "اشترِ التذاكر من الموقع أو التطبيق الرسمي فقط؛ الخصومات الكبيرة على مواقع التواصل علامة تحذير."),
    "travel": ("Book on the airline's own domain; fake 'free ticket' giveaways are common.",
               "احجز عبر موقع شركة الطيران الرسمي؛ مسابقات التذاكر المجانية المزيفة شائعة."),
}


def brand_registry() -> list[dict]:
    out = []
    for b in BRANDS:
        en, ar = SECTOR_CONTACT.get(b["sector"], ("Use official channels only.", "استخدم القنوات الرسمية فقط."))
        out.append({"id": b["id"], "name": b["name"], "name_ar": b["name_ar"], "sector": b["sector"],
                    "official_domains": [{"domain": d["domain"], "verified": d["confidence"] == "high"} for d in b["official_domains"]],
                    "contact_rule_en": en, "contact_rule_ar": ar,
                    "known_scams": [{"en": SCAM_TYPES[s]["en"], "ar": SCAM_TYPES[s]["ar"]} for s in b.get("scams", []) if s in SCAM_TYPES]})
    return out


KNOWLEDGE = [
    {"id": "otp", "title_en": "Never share an OTP", "title_ar": "لا تشارك رمز التحقق أبداً",
     "body_en": "A one-time password lets someone act as you. No bank, police force or government entity will ask for it. If someone asks, it is a scam.",
     "body_ar": "رمز التحقق يسمح لشخص آخر بالتصرف باسمك. لن يطلبه أي بنك أو جهة شرطية أو حكومية. إن طلبه أحد فهي عملية احتيال.",
     "title_ur": "کبھی او ٹی پی شیئر نہ کریں", "body_ur": "ایک بار استعمال ہونے والا کوڈ کسی کو آپ بن کر کام کرنے دیتا ہے۔ کوئی بینک، پولیس یا سرکاری ادارہ یہ نہیں مانگے گا۔ اگر کوئی مانگے تو یہ فراڈ ہے۔"},
    {"id": "domains", "title_en": "Read the domain, not the logo", "title_ar": "اقرأ اسم النطاق وليس الشعار",
     "body_en": "Scam pages copy logos perfectly. The part that cannot be copied is the domain. uaepass.ae is real; uaepass-verify.com is not.",
     "body_ar": "صفحات الاحتيال تنسخ الشعارات بإتقان. ما لا يمكن نسخه هو اسم النطاق. uaepass.ae حقيقي، أما uaepass-verify.com فليس كذلك.",
     "title_ur": "لوگو نہیں، ڈومین پڑھیں", "body_ur": "جعلی صفحات لوگو ہوبہو نقل کر لیتے ہیں، لیکن ڈومین نقل نہیں ہو سکتا۔ uaepass.ae اصلی ہے؛ uaepass-verify.com نہیں۔"},
    {"id": "fines", "title_en": "Traffic fines and 'discounts'", "title_ar": "المخالفات المرورية و'الخصومات'",
     "body_en": "Fake fine messages offer 50% discounts that expire today. Check fines only in the official police or MOI app.",
     "body_ar": "رسائل المخالفات المزيفة تعرض خصماً 50٪ ينتهي اليوم. تحقق من مخالفاتك فقط عبر تطبيق الشرطة أو وزارة الداخلية.",
     "title_ur": "ٹریفک جرمانے اور 'رعایت'", "body_ur": "جعلی جرمانے کے پیغامات آج ختم ہونے والی 50٪ رعایت دیتے ہیں۔ جرمانے صرف پولیس یا وزارت داخلہ کی آفیشل ایپ میں چیک کریں۔"},
    {"id": "parcels", "title_en": "The tiny parcel fee", "title_ar": "رسوم الطرد الصغيرة",
     "body_en": "A small 'redelivery' or 'customs' fee of a few dirhams is the hook. The real goal is your card details.",
     "body_ar": "رسوم 'إعادة التوصيل' أو 'الجمارك' الصغيرة هي الطُّعم. الهدف الحقيقي هو بيانات بطاقتك.",
     "title_ur": "پارسل کی چھوٹی فیس", "body_ur": "چند درہم کی 'دوبارہ ڈیلیوری' یا 'کسٹم' فیس صرف چارہ ہے۔ اصل مقصد آپ کے کارڈ کی تفصیلات ہیں۔"},
    {"id": "jobs", "title_en": "Jobs that charge you", "title_ar": "وظائف تطلب منك المال",
     "body_en": "A genuine employer pays you. Any job that asks for a registration, training or visa fee is a scam.",
     "body_ar": "صاحب العمل الحقيقي يدفع لك. أي وظيفة تطلب رسوم تسجيل أو تدريب أو تأشيرة هي احتيال.",
     "title_ur": "پیسے مانگنے والی نوکریاں", "body_ur": "اصلی آجر آپ کو تنخواہ دیتا ہے۔ جو نوکری رجسٹریشن، تربیت یا ویزا فیس مانگے وہ فراڈ ہے۔"},
    {"id": "investment", "title_en": "Guaranteed returns do not exist", "title_ar": "لا توجد أرباح مضمونة",
     "body_en": "Ads using famous faces and promising fixed monthly profit are investment scams. Check that a firm is licensed by a UAE regulator.",
     "body_ar": "الإعلانات التي تستخدم وجوه المشاهير وتعد بربح شهري ثابت هي احتيال استثماري. تأكد من ترخيص الشركة لدى جهة رقابية إماراتية.",
     "title_ur": "یقینی منافع کچھ نہیں ہوتا", "body_ur": "مشہور چہروں والے اور مقررہ ماہانہ منافع کا وعدہ کرنے والے اشتہار سرمایہ کاری فراڈ ہیں۔ دیکھیں کہ کمپنی کسی اماراتی ریگولیٹر سے لائسنس یافتہ ہو۔"},
    {"id": "calls", "title_en": "Calls from 'the police' or 'the bank'", "title_ar": "اتصالات من 'الشرطة' أو 'البنك'",
     "body_en": "Hang up and call the official number yourself. Scammers can fake caller ID and will pressure you to act now.",
     "body_ar": "أغلق الخط واتصل أنت بالرقم الرسمي. المحتالون يزوّرون رقم المتصل ويضغطون عليك للتصرف فوراً.",
     "title_ur": "'پولیس' یا 'بینک' کی کالیں", "body_ur": "کال بند کریں اور خود آفیشل نمبر پر کال کریں۔ دھوکے باز کالر آئی ڈی جعلی بنا سکتے ہیں اور فوراً کچھ کرنے کا دباؤ ڈالتے ہیں۔"},
    {"id": "qr", "title_en": "QR codes can lie", "title_ar": "رموز QR قد تخدع",
     "body_en": "A sticker over a parking or menu QR code can lead to a fake payment page. Scan it with RAQEEB first.",
     "body_ar": "ملصق فوق رمز QR للمواقف أو قائمة الطعام قد يقود إلى صفحة دفع مزيفة. امسحه برقيب أولاً.",
     "title_ur": "کیو آر کوڈ دھوکہ دے سکتے ہیں", "body_ur": "پارکنگ یا مینو کے کیو آر کوڈ پر لگا اسٹیکر جعلی ادائیگی کے صفحے پر لے جا سکتا ہے۔ پہلے رقیب سے اسکین کریں۔"},
    {"id": "victim", "title_en": "If you already paid", "title_ar": "إذا كنت قد دفعت بالفعل",
     "body_en": "Call your bank immediately to block the card, then report to the police through their official channels. Speed matters.",
     "body_ar": "اتصل ببنكك فوراً لإيقاف البطاقة، ثم أبلغ الشرطة عبر قنواتها الرسمية. السرعة مهمة.",
     "title_ur": "اگر آپ ادائیگی کر چکے ہیں", "body_ur": "فوراً اپنے بینک کو کال کر کے کارڈ بلاک کروائیں، پھر پولیس کو ان کے آفیشل ذرائع سے رپورٹ کریں۔ رفتار اہم ہے۔"},
]

# Training scenarios. Clearly labelled as simulations; links use the reserved .example TLD so they can never resolve.
SIMULATIONS = [
    {"id": "sim-fine", "channel": "SMS", "scam": True,
     "text_en": "MOI: You have an unpaid traffic fine of AED 400. Pay today with 50% discount: http://moi-fines-pay.example/ae",
     "text_ar": "وزارة الداخلية: لديك مخالفة مرورية غير مدفوعة بقيمة 400 درهم. ادفع اليوم بخصم 50٪: http://moi-fines-pay.example/ae",
     "why_en": "The domain is not moi.gov.ae, and the 'today only' discount is pressure.", "why_ar": "النطاق ليس moi.gov.ae، وخصم 'اليوم فقط' أسلوب ضغط."},
    {"id": "sim-uaepass", "channel": "SMS", "scam": True,
     "text_en": "UAE PASS: your account will be suspended in 24 hours. Re-activate: https://uaepass-reactivate.example",
     "text_ar": "يو إيه إي باس: سيتم إيقاف حسابك خلال 24 ساعة. أعد التفعيل: https://uaepass-reactivate.example",
     "why_en": "UAE PASS does not suspend accounts by SMS link. The domain is fake.", "why_ar": "UAE PASS لا يوقف الحسابات عبر رابط في رسالة. النطاق مزيف."},
    {"id": "sim-otp", "channel": "Phone call", "scam": True,
     "text_en": "Caller: 'This is your bank's fraud team. To stop a suspicious payment, read me the code we just sent you.'",
     "text_ar": "المتصل: 'نحن فريق الاحتيال في بنكك. لإيقاف عملية مشبوهة، اقرأ لي الرمز الذي أرسلناه لك الآن.'",
     "why_en": "No bank asks you to read out an OTP. That code is what authorises the payment.", "why_ar": "لا يطلب أي بنك قراءة رمز التحقق. هذا الرمز هو ما يعتمد الدفع."},
    {"id": "sim-parcel", "channel": "WhatsApp", "scam": True,
     "text_en": "Your parcel is held at customs. Pay AED 9.50 handling fee within 12 hours: http://parcel-release.example",
     "text_ar": "طردك محتجز في الجمارك. ادفع 9.50 درهم رسوم مناولة خلال 12 ساعة: http://parcel-release.example",
     "why_en": "A tiny fee plus a deadline plus an unknown link is the classic card-theft pattern.", "why_ar": "رسوم صغيرة مع مهلة ورابط مجهول هو النمط المعتاد لسرقة البطاقات."},
    {"id": "sim-real-otp", "channel": "SMS", "scam": False,
     "text_en": "Your verification code is 482193. Do not share this code with anyone.",
     "text_ar": "رمز التحقق الخاص بك هو 482193. لا تشارك هذا الرمز مع أي أحد.",
     "why_en": "A code you requested, with a warning not to share it and no link, is normal. Just don't share it.",
     "why_ar": "رمز طلبته بنفسك مع تحذير بعدم مشاركته ودون رابط أمر طبيعي. فقط لا تشاركه."},
    {"id": "sim-ticket", "channel": "Instagram ad", "scam": True,
     "text_en": "Water park family pass 80% OFF! Only 20 left. Pay by bank transfer to reserve.",
     "text_ar": "تذكرة عائلية للحديقة المائية بخصم 80٪! متبقي 20 فقط. ادفع بتحويل بنكي للحجز.",
     "why_en": "Huge discount, scarcity, and payment by transfer instead of the park's own site.", "why_ar": "خصم ضخم وندرة مصطنعة ودفع بالتحويل بدلاً من موقع الحديقة الرسمي."},
    {"id": "sim-job", "channel": "WhatsApp", "scam": True,
     "text_en": "Part-time job: earn AED 800/day liking videos. Registration fee AED 150 to start.",
     "text_ar": "وظيفة بدوام جزئي: اربح 800 درهم يومياً بالإعجاب بالفيديوهات. رسوم تسجيل 150 درهم للبدء.",
     "why_en": "Real jobs never charge you to start, and the pay is unrealistic.", "why_ar": "الوظائف الحقيقية لا تطلب رسوماً للبدء، والأجر غير واقعي."},
    {"id": "sim-real-bank", "channel": "Bank app notification", "scam": False,
     "text_en": "In-app: A purchase of AED 230 was made with your card. If this wasn't you, tap 'Report' in this app.",
     "text_ar": "داخل التطبيق: تمت عملية شراء بقيمة 230 درهم ببطاقتك. إن لم تكن أنت، اضغط 'إبلاغ' داخل هذا التطبيق.",
     "why_en": "It is inside the official app, asks for nothing, and sends you to the app itself.",
     "why_ar": "داخل التطبيق الرسمي، لا يطلب أي بيانات، ويوجهك إلى التطبيق نفسه."},
]


EMERGENCY = {
    "en": ["Stop talking to the suspected scammer. Don't reply, click or call back.",
           "Don't share any more codes, passwords or card details.",
           "If money or an account is affected, call your bank now on the number printed on your card or in its official app.",
           "Keep the evidence: screenshots, numbers, links, receipts and the chat itself.",
           "Report it through the police's official channels (in Abu Dhabi: Aman 8002626), then report it in RAQEEB."],
    "ar": ["أوقف التواصل مع المحتال المشتبه به. لا ترد ولا تضغط ولا تعاود الاتصال.",
           "لا تشارك أي رموز أو كلمات مرور أو بيانات بطاقة إضافية.",
           "إذا تأثر مالك أو حسابك، اتصل ببنكك الآن على الرقم المطبوع على بطاقتك أو في تطبيقه الرسمي.",
           "احتفظ بالأدلة: لقطات الشاشة والأرقام والروابط والإيصالات والمحادثة نفسها.",
           "أبلغ عبر القنوات الرسمية للشرطة (في أبوظبي: خدمة أمان 8002626)، ثم أبلغ في رقيب."],
    "ur": ["مشتبہ دھوکے باز سے بات بند کر دیں۔ جواب نہ دیں، کلک نہ کریں، واپس کال نہ کریں۔",
           "مزید کوئی کوڈ، پاس ورڈ یا کارڈ کی تفصیلات شیئر نہ کریں۔",
           "اگر رقم یا اکاؤنٹ متاثر ہوا ہے تو ابھی اپنے بینک کو کارڈ پر لکھے نمبر یا آفیشل ایپ سے کال کریں۔",
           "ثبوت محفوظ رکھیں: اسکرین شاٹس، نمبر، لنکس، رسیدیں اور خود چیٹ۔",
           "پولیس کے آفیشل ذرائع سے رپورٹ کریں (ابوظہبی میں: امان 8002626)، پھر رقیب میں رپورٹ کریں۔"],
}


def simulations_public() -> list[dict]:
    return [{k: v for k, v in s.items() if k not in ("scam", "why_en", "why_ar")} for s in SIMULATIONS]


def answer_simulation(sim_id: str, said_scam: bool) -> dict:
    s = next((x for x in SIMULATIONS if x["id"] == sim_id), None)
    if not s:
        raise KeyError(sim_id)
    return {"correct": said_scam == s["scam"], "scam": s["scam"], "why_en": s["why_en"], "why_ar": s["why_ar"]}


def bump(key: str, n: int = 1):
    db().execute("INSERT INTO metrics (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = value + ?", (key, n, n))


def metric(key: str) -> int:
    r = db().execute("SELECT value FROM metrics WHERE key=?", (key,)).fetchone()
    return r[0] if r else 0


def public_alerts(limit=30) -> list[dict]:
    """Only analyst-confirmed threats are shown to the public."""
    out = []
    for t in rows(db().execute("""SELECT id, category, indicator_type, normalized, brand, first_seen, last_seen, report_count, severity
                                  FROM threats WHERE status='confirmed_malicious' ORDER BY last_seen DESC LIMIT ?""", (limit,))):
        out.append(t)
    return out


def safety_report(days: int = 30) -> dict:
    since = time.time() - days * 86400
    q = lambda sql, *a: db().execute(sql, a).fetchone()[0]  # noqa: E731
    return {
        "period_days": days, "generated": time.time(),
        "confirmed_threats": q("SELECT COUNT(*) FROM threats WHERE status='confirmed_malicious' AND last_seen >= ?", since),
        "citizen_reports": q("SELECT COUNT(*) FROM citizen_reports WHERE created >= ?", since),
        "verified_from_citizens": q("SELECT COUNT(*) FROM citizen_reports WHERE status IN ('analyst_verified','confirmed_malicious') AND created >= ?", since),
        "most_impersonated": rows(db().execute("""SELECT brand, COUNT(*) n FROM threats WHERE status='confirmed_malicious'
                                                  AND brand != '' AND last_seen >= ? GROUP BY brand ORDER BY n DESC LIMIT 5""", (since,))),
        "by_category": rows(db().execute("""SELECT category, COUNT(*) n FROM threats WHERE status='confirmed_malicious'
                                            AND last_seen >= ? GROUP BY category ORDER BY n DESC""", (since,))),
        "note": "Counts include only threats confirmed by analysts. They reflect RAQEEB's own records, not all scams in the UAE.",
    }


def impact() -> dict:
    q = lambda sql: db().execute(sql).fetchone()[0]  # noqa: E731
    reports = rows(db().execute("SELECT impact FROM citizen_reports WHERE impact IS NOT NULL"))
    losses = sum(1 for r in reports if json.loads(r["impact"]).get("lost_money"))
    return {
        "threats_total": q("SELECT COUNT(*) FROM threats"),
        "confirmed": q("SELECT COUNT(*) FROM threats WHERE status='confirmed_malicious'"),
        "blocked_now": q("SELECT COUNT(*) FROM threats WHERE block_status='global'"),
        "citizen_reports": q("SELECT COUNT(*) FROM citizen_reports"),
        "reports_with_money_lost": losses,
        "checks_run": metric("checks"),
        "checks_matched_block": metric("checks_blocked"),
        "personal_blocks": q("SELECT COUNT(*) FROM personal_blocks"),
        "guardians": q("SELECT COUNT(*) FROM users WHERE role='citizen'"),
        "points_awarded": q("SELECT COALESCE(SUM(delta),0) FROM points"),
        "protection_version": q("SELECT COALESCE(MAX(version),0) FROM protection_versions"),
        "note": "Live counts from this RAQEEB instance. 'Checks matched block' counts lookups that hit a published rule; it does not prove a loss was prevented.",
    }


def geography() -> list[dict]:
    """Per-emirate counts for the map. Emirate level only: no precise citizen locations are ever stored."""
    from .auth import EMIRATES
    counts = {e: {"emirate": e, "reports": 0, "threats": 0, "confirmed": 0, "categories": {}, "campaigns": set()} for e in EMIRATES}
    for e, n in db().execute("SELECT emirate, COUNT(*) FROM citizen_reports WHERE emirate IS NOT NULL GROUP BY emirate"):
        if e in counts:
            counts[e]["reports"] = n
    for t in rows(db().execute("SELECT emirates, status, category, campaign_id FROM threats WHERE emirates IS NOT NULL")):
        for e in (json.loads(t["emirates"]) or {}):
            if e in counts:
                c = counts[e]
                c["threats"] += 1
                c["confirmed"] += t["status"] == "confirmed_malicious"
                c["categories"][t["category"]] = c["categories"].get(t["category"], 0) + 1
                if t["campaign_id"]:
                    c["campaigns"].add(t["campaign_id"])
    for c in counts.values():
        c["campaigns"] = sorted(c["campaigns"])
    return list(counts.values())
