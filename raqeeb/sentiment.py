"""Sentiment and social-engineering analysis for SAWNN (English and Arabic).

Finds the pressure tactics scam messages use (urgency, fear, threats, authority, money pressure, emotional
manipulation, fake rewards, deadlines, secrecy, account-suspension warnings, payment pressure, false reassurance),
returns the exact phrases matched, an overall sentiment, a manipulation score and a bilingual explanation.

This is supporting evidence only. Negative or urgent wording alone never makes a message fraudulent: genuine
banks and government services also send urgent notices. messages.check_message caps the contribution of this
module when there is no link, brand, payment request or known scam script in the message.
"""
import re

# (category, weight, English patterns, Arabic patterns, English label, Arabic label)
TACTICS = [
    ("urgency", 0.8, r"\b(urgent(ly)?|immediately|right now|asap|act now|as soon as possible|hurry|quickly|without delay)\b",
     r"(عاجل|فوراً|فورا|حالاً|حالا|بسرعة|على الفور|بشكل عاجل|الآن)", "Urgency", "استعجال"),
    ("deadline", 0.9, r"\b(within \d+ ?(hours?|hrs?|minutes?|mins?|days?)|today only|before midnight|last chance|expires? (today|soon|in)|final (notice|reminder|warning))\b",
     r"(خلال \d+ ?(ساعة|ساعات|دقيقة|دقائق|يوم|أيام)|اليوم فقط|قبل منتصف الليل|آخر فرصة|إشعار نهائي|تنبيه أخير|تنتهي اليوم)", "Artificial deadline", "مهلة مصطنعة"),
    ("fear", 0.7, r"\b(danger|risk|compromised|hacked|unauthori[sz]ed|suspicious activity|fraud(ulent)? (activity|transaction)|security alert)\b",
     r"(خطر|اختراق|تم اختراق|نشاط مشبوه|عملية غير مصرح|تنبيه أمني|معاملة احتيالية)", "Fear", "تخويف"),
    ("threat", 1.0, r"\b(legal action|arrest(ed)?|police case|court|penalt(y|ies)|fine[sd]? will|blacklist(ed)?|travel ban|deport(ed|ation)?|prosecut)",
     r"(إجراء قانوني|القبض|بلاغ للشرطة|المحكمة|غرامة|غرامات|القائمة السوداء|منع من السفر|ترحيل|ملاحقة قانونية)", "Threat of punishment", "تهديد بعقوبة"),
    ("authority", 0.8, r"\b(police|ministry|government|federal|customs|immigration|icp|uae ?pass|tamm|central bank|court|official notice)\b",
     r"(الشرطة|وزارة|الحكومة|اتحادية|الجمارك|الهوية والجنسية|الإقامة|المصرف المركزي|البنك المركزي|إشعار رسمي|الهوية الرقمية)", "Authority impersonation", "انتحال صفة جهة رسمية"),
    ("suspension", 1.0, r"\b(account (is |has been |will be )?(suspended|blocked|locked|frozen|deactivated|closed)|(suspend|block|freeze|deactivate)(ed)? your)\b",
     r"(تم إيقاف حسابك|سيتم إيقاف|تم تجميد|سيتم تجميد|تم حظر حسابك|إيقاف الحساب|تعليق الحساب|سيتم تعطيل)", "Account suspension warning", "تحذير بإيقاف الحساب"),
    ("payment", 1.0, r"\b(pay (now|the|a|your)|payment (required|pending|due|failed)|outstanding (amount|balance|fine)|settle|small fee|delivery fee|customs fee|transfer (the )?money)\b",
     r"(ادفع|الدفع الآن|دفع رسوم|رسوم التوصيل|رسوم جمركية|مبلغ مستحق|سداد|تحويل المبلغ|رسوم بسيطة)", "Payment pressure", "ضغط للدفع"),
    ("financial", 0.7, r"\b(refund|tax|vat|salary|loan|investment|profit|bitcoin|crypto|wallet|bank account|card (details|number))\b",
     r"(استرداد|ضريبة|راتب|قرض|استثمار|أرباح|بيتكوين|عملة رقمية|محفظة|حساب بنكي|بيانات البطاقة|رقم البطاقة)", "Financial pressure", "ضغط مالي"),
    ("reward", 0.9, r"\b(congratulations|you (have )?won|winner|prize|reward|gift|free (gift|iphone|ticket)|cash ?back|bonus|selected)\b",
     r"(مبروك|تهانينا|لقد فزت|ربحت|جائزة|مكافأة|هدية|مجاناً|مجانا|استرداد نقدي|تم اختيارك)", "False reward", "مكافأة زائفة"),
    ("emotional", 0.7, r"\b(help me|i('m| am) in trouble|emergency|accident|hospital|please don'?t tell|dear (customer|friend)|my love|i trust you)\b",
     r"(ساعدني|أنا في ورطة|حالة طارئة|حادث|المستشفى|عزيزي العميل|حبيبي|أثق بك)", "Emotional manipulation", "تلاعب عاطفي"),
    ("secrecy", 1.0, r"\b((don'?t|do not) (tell|share (this )?with) (anyone|anybody)|keep (this|it) (secret|confidential|private)|do not inform|between us)\b",
     r"(لا تخبر أحداً|لا تخبر أحدا|سري للغاية|احتفظ بالأمر سراً|بيننا فقط|لا تبلغ)", "Request for secrecy", "طلب السرية"),
    ("credentials", 1.0, r"\b(otp|one[- ]time (password|code)|verification code|pin|cvv|password|share (the )?code)\b",
     r"(رمز التحقق|كلمة المرور|الرقم السري|رمز لمرة واحدة|رمز CVV|شارك الرمز)", "Request for codes or passwords", "طلب رموز أو كلمات مرور"),
    ("reassurance", 0.6, r"\b(100% (safe|secure)|totally (safe|legit)|no risk|guaranteed|this is (not a scam|legit(imate)?)|trusted (by|site))\b",
     r"(آمن 100%|مضمون|بدون مخاطرة|هذه ليست عملية احتيال|موثوق تماماً|موقع رسمي وآمن)", "Manipulative reassurance", "طمأنة مضللة"),
]
NEG = r"\b(suspend|block|fine|penalt|arrest|danger|risk|fail|problem|warning|unauthori|hack|compromis|overdue|late|lose|lost)\w*"
POS = r"\b(congratulat|won|win|prize|gift|free|bonus|reward|refund|lucky|selected)\w*"
NEG_AR = r"(إيقاف|حظر|غرامة|عقوبة|خطر|مشكلة|تحذير|اختراق|متأخر|فقدان|تجميد)"
POS_AR = r"(مبروك|تهانينا|فزت|جائزة|هدية|مجان|مكافأة|استرداد|محظوظ)"


def detect_language(text: str) -> str:
    ar = len(re.findall(r"[؀-ۿ]", text or ""))
    lat = len(re.findall(r"[A-Za-z]", text or ""))
    if ar and lat:
        return "mixed" if min(ar, lat) / max(ar, lat) > 0.25 else ("ar" if ar > lat else "en")
    return "ar" if ar else "en" if lat else "unknown"


def analyse(text: str) -> dict:
    text = (text or "")[:6000]
    found = []
    for code, w, en, ar, label_en, label_ar in TACTICS:
        phrases = sorted({m.group(0).strip() for m in re.finditer(en, text, re.I)} | {m.group(0).strip() for m in re.finditer(ar, text)})
        if phrases:
            found.append({"category": code, "label_en": label_en, "label_ar": label_ar, "weight": w, "phrases": phrases[:5]})
    neg = len(re.findall(NEG, text, re.I)) + len(re.findall(NEG_AR, text))
    pos = len(re.findall(POS, text, re.I)) + len(re.findall(POS_AR, text))
    if neg == pos == 0:
        sentiment = {"label": "neutral", "score": 0.0}
    else:
        score = round((pos - neg) / (pos + neg), 2)
        sentiment = {"label": "negative" if score < -0.2 else "positive" if score > 0.2 else "mixed", "score": score}
    raw = sum(f["weight"] for f in found)
    manipulation = round(min(1.0, raw / 4.0), 2)
    # combinations that scam scripts rely on: pressure + an action the reader must take
    combo = {f["category"] for f in found}
    pressure = combo & {"urgency", "deadline", "threat", "suspension", "fear"}
    action = combo & {"payment", "credentials", "secrecy"}
    if pressure and action:
        manipulation = min(1.0, round(manipulation + 0.15, 2))
    confidence = "HIGH" if len(found) >= 4 else "MEDIUM" if len(found) >= 2 else "LOW" if found else "NONE"
    if found:
        en = "Uses " + ", ".join(f["label_en"].lower() for f in found[:5]) + "."
        ar = "يستخدم: " + "، ".join(f["label_ar"] for f in found[:5]) + "."
        if pressure and action:
            en += " It combines pressure with a demand to pay or share details, the pattern most scam messages follow."
            ar += " يجمع بين الضغط وطلب الدفع أو مشاركة البيانات، وهو النمط الذي تتبعه معظم رسائل الاحتيال."
        en += " Pressure wording alone does not prove a scam."
        ar += " عبارات الضغط وحدها لا تثبت الاحتيال."
    else:
        en, ar = "No manipulation tactics found.", "لم يتم العثور على أساليب تلاعب."
    return {"language": detect_language(text), "sentiment": sentiment, "indicators": found, "manipulation_score": manipulation,
            "pressure_with_action": bool(pressure and action), "confidence": confidence, "explanation_en": en, "explanation_ar": ar,
            "note": "Supporting evidence only; never sufficient on its own to classify a message as fraud."}
