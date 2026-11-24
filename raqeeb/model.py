"""Two-stage ML model: char n-gram logistic regression -> LightGBM over handcrafted features."""
import json
import os
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from .features import FEATURE_NAMES, canonical, extract, text_for_ngrams
from .urlparse import parse

MODEL_DIR = Path(os.environ.get("SAWNN_MODEL_PATH") or Path(__file__).resolve().parent.parent / "models")


def make_lr():
    return make_pipeline(
        HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2 ** 19, alternate_sign=False, lowercase=True),
        TfidfTransformer(sublinear_tf=True),
        LogisticRegression(C=4.0, max_iter=300, solver="liblinear"),
    )


def featurise(urls, include_path):
    parsed = [parse(u) for u in urls]
    X = np.array([extract(p, include_path) for p in parsed], dtype=np.float32)
    texts = [text_for_ngrams(p, include_path) for p in parsed]
    return X, texts


LGB_PARAMS = dict(objective="binary", learning_rate=0.05, num_leaves=63, min_data_in_leaf=40,
                  feature_fraction=0.9, bagging_fraction=0.9, bagging_freq=1, lambda_l2=1.0, verbose=-1)


class Model:
    def __init__(self, lr, booster, meta):
        self.lr, self.booster, self.meta = lr, booster, meta
        self.include_path = meta["mode"] == "url"
        self.threshold = meta["threshold"]
        self.names = FEATURE_NAMES + ["lr_prob"]

    @classmethod
    def load(cls, directory: Path = MODEL_DIR):
        meta = json.loads((directory / "meta.json").read_text())
        return cls(joblib.load(directory / "lr.joblib"), lgb.Booster(model_file=str(directory / "lgbm.txt")), meta)

    def save(self, directory: Path = MODEL_DIR):
        directory.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.lr, directory / "lr.joblib", compress=3)
        self.booster.save_model(str(directory / "lgbm.txt"))
        (directory / "meta.json").write_text(json.dumps(self.meta, indent=2))

    def predict(self, urls):
        """Return probabilities and per-feature contributions (log-odds) for explanations."""
        if self.meta.get("canonical"):
            urls = [canonical(u) for u in urls]
        X, texts = featurise(urls, self.include_path)
        lr_p = self.lr.predict_proba(texts)[:, 1].astype(np.float32)
        Xf = np.column_stack([X, lr_p])
        prob = self.booster.predict(Xf)
        if self.meta.get("calibration"):
            c = self.meta["calibration"]
            prob = np.interp(prob, c["x"], c["y"])
        contrib = self.booster.predict(Xf, pred_contrib=True)[:, :-1]
        return prob, contrib, Xf
