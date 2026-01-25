import numpy as np
import pytest

from log_analyzer.models import IsolationForestModel, get_model, MODEL_REGISTRY
from log_analyzer.models.registry import ModelArtifact, load_model, save_model


def test_isolation_forest_score_range(tmp_path):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(500, 12))
    model = IsolationForestModel(contamination=0.05).fit(X)
    scores = model.score(X)
    assert scores.shape == (500,)
    assert scores.min() >= 0.0 and scores.max() <= 1.0


def test_registry_roundtrip(tmp_path):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(200, 12))
    model = get_model("isolation_forest", contamination=0.05).fit(X)
    artifact = ModelArtifact(model=model, feature_names=["f"] * 12)
    p = save_model(artifact, tmp_path / "m.joblib")
    loaded = load_model(p)
    assert loaded.model.name == "isolation_forest"


def test_registry_unknown_model():
    with pytest.raises(KeyError):
        get_model("does_not_exist")


@pytest.mark.parametrize("name", ["isolation_forest", "one_class_svm"])
def test_models_smoke(name: str):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(200, 12))
    model = get_model(name).fit(X)
    s = model.score(X)
    assert s.shape == (200,)
