"""SAWNN (صون) core package. The Python package keeps its original module name `raqeeb` for import stability;
every user-visible name is SAWNN.

Environment: settings use the SAWNN_ prefix. Older RAQEEB_* variables are still accepted and copied to their SAWNN_
names, and the provider names from the SAWNN API guide are mapped onto the names the code reads."""
import os

for _k, _v in list(os.environ.items()):
    if _k.startswith("RAQEEB_"):
        os.environ.setdefault("SAWNN_" + _k[7:], _v)
for _new, _old in {"SAWNN_VIRUSTOTAL_API_KEY": "VIRUSTOTAL_API_KEY", "SAWNN_GOOGLE_THREAT_API_KEY": "GOOGLE_WEB_RISK_API_KEY",
                   "SAWNN_URLHAUS_AUTH_KEY": "URLHAUS_AUTH_KEY", "URLHAUS_AUTH_KEY": "SAWNN_URLHAUS_AUTH_KEY", "SAWNN_DATABASE_URL": "SAWNN_DB"}.items():
    if os.environ.get(_new) and not os.environ.get(_old):
        os.environ[_old] = os.environ[_new].removeprefix("sqlite:///")
if os.environ.get("SAWNN_CHROMIUM") is None and os.environ.get("SAWNN_SANDBOX_BROWSER"):
    os.environ["SAWNN_CHROMIUM"] = os.environ["SAWNN_SANDBOX_BROWSER"]
