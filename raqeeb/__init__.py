"""MIRA (ميرا) core package. The Python package keeps its original module name `raqeeb` for import stability;
every user-visible name is MIRA.

Environment: settings use the MIRA_ prefix. Older RAQEEB_* variables are still accepted and copied to their MIRA_
names, and the provider names from the MIRA API guide are mapped onto the names the code reads."""
import os

for _k, _v in list(os.environ.items()):
    if _k.startswith("RAQEEB_"):
        os.environ.setdefault("MIRA_" + _k[7:], _v)
for _new, _old in {"MIRA_VIRUSTOTAL_API_KEY": "VIRUSTOTAL_API_KEY", "MIRA_GOOGLE_THREAT_API_KEY": "GOOGLE_WEB_RISK_API_KEY",
                   "MIRA_URLHAUS_AUTH_KEY": "URLHAUS_AUTH_KEY", "URLHAUS_AUTH_KEY": "MIRA_URLHAUS_AUTH_KEY", "MIRA_DATABASE_URL": "MIRA_DB"}.items():
    if os.environ.get(_new) and not os.environ.get(_old):
        os.environ[_old] = os.environ[_new].removeprefix("sqlite:///")
if os.environ.get("MIRA_CHROMIUM") is None and os.environ.get("MIRA_SANDBOX_BROWSER"):
    os.environ["MIRA_CHROMIUM"] = os.environ["MIRA_SANDBOX_BROWSER"]
