"""Machine-learning stage: the trained URL model (character n-gram logistic regression stacked into LightGBM).

Feature contributions are LightGBM's TreeSHAP values (pred_contrib), in log-odds. The probability is the model's raw
score: it is not calibrated, so the API labels it as a model score, not a probability of fraud.
"""
import numpy as np

from ..engine import model
from ..features import READABLE


def predict(url: str) -> dict:
    try:
        m = model()
    except Exception as e:  # noqa: BLE001 - model files missing or unreadable
        return {"available": False, "prediction": None, "probability": None, "model_version": None, "error": str(e)[:160]}
    probs, contrib, _ = m.predict([url])
    p, c = float(probs[0]), contrib[0]
    top = [{"feature": m.names[j], "description": READABLE.get(m.names[j], m.names[j]), "contribution": round(float(c[j]), 3)}
           for j in np.argsort(-np.abs(c))[:6] if abs(c[j]) > 0.05]
    meta = m.meta
    return {"available": True, "prediction": "phishing" if p >= m.threshold else "legitimate", "probability": round(p, 4),
            "probability_calibrated": False, "decision_threshold": m.threshold,
            "model_version": f"lr+lightgbm {meta.get('mode', 'host')} {meta.get('trained_at', '')}".strip(),
            "explanation_method": "TreeSHAP feature contributions (log-odds)", "feature_contributions": top,
            "test_metrics": meta.get("test_metrics")}


def status() -> dict:
    try:
        m = model()
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": str(e)[:160]}
    return {"available": True, "model": "char n-gram logistic regression stacked into LightGBM", "mode": m.meta.get("mode"),
            "trained_at": m.meta.get("trained_at"), "threshold": m.threshold, "rows": m.meta.get("rows"),
            "test_metrics": m.meta.get("test_metrics"), "data_sources": m.meta.get("data_sources")}
