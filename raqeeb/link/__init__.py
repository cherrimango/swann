"""SAWNN Link Intelligence Engine: a standalone, multi-stage link analysis pipeline.

Stages (each reports its own availability; a stage that cannot run never counts as evidence of safety):
    url_validator   -> validation and normalisation (Public Suffix List aware)
    static_analyzer -> URL features, plus domain (RDAP, DNS) and certificate features in deep mode
    official_domains-> UAE official brand registry comparison
    signatures      -> SAWNN published rules, public feed snapshots, optional Google Web Risk / VirusTotal / URLhaus
    sandbox         -> isolated headless-browser visit (deep mode)
    visual          -> perceptual-hash comparison against verified reference screenshots (deep mode)
    ml              -> trained URL model with per-feature contributions
    risk            -> evidence-weighted aggregation into verdict, risk score, confidence and completeness
"""
from .pipeline import analyse  # noqa: F401
