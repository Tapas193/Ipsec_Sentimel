"""Phase 4 ML API and persistence tests.

Covers the full surface an operator and the frontend touch:

- health / schema / models endpoints, including the "no model" state
- training refusal without labels, and the training-disabled guard
- prediction runs, persistence, and **idempotency** (re-running must not grow
  the table)
- the MODEL_PREDICTED semantics, including abstention
- the guarantee that Phase 3 findings are untouched by ML

Deterministic fixtures are used to exercise the mechanics. Nothing here asserts
model accuracy, and the tests that create a real model do so only via a real
label file so the legitimate code path is the one under test.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.ml.schema import MLFeatureSchema
from app.models import Analysis, SecurityFinding, TrafficPrediction
from app.security.enums import ObservationStatus
from app.services import ml_service
from tests.ml_fixtures import (
    build_deterministic_dataset,
    make_analysis,
    make_capture,
    make_flow_with_features,
    synthetic_features,
    write_label_file,
)


@pytest.fixture()
def label_path(tmp_path: Path) -> Path:
    """A path for a label file, inside the test's temp dir.

    Reused by the Phase 3 isolation and abstention tests so they do not each
    rebuild the same labeled corpus.
    """
    return tmp_path / "ground_truth_labels.json"


@pytest.fixture()
def populated(db_session: Session, ml_schema: MLFeatureSchema) -> None:
    """Build the deterministic labeled corpus without training anything."""
    build_deterministic_dataset(
        db_session, schema=ml_schema, flows_per_class=10, captures_per_class=6
    )


@pytest.fixture()
def labeled_analysis(
    db_session: Session, ml_schema: MLFeatureSchema, tmp_path: Path
) -> tuple[str, Path]:
    """A fully-labeled dataset plus the label file that describes it."""
    labels, shas = build_deterministic_dataset(
        db_session, schema=ml_schema, flows_per_class=10, captures_per_class=6
    )
    label_path = write_label_file(tmp_path / "gt.json", labels, shas=shas, schema=ml_schema)
    return "ANL-T000", label_path


def train_from_labels(client: TestClient, label_path: Path, version: str = "api-1.0.0") -> bool:
    """Train through the public endpoint using a real label file."""
    response = client.post(
        "/api/v1/ml/train", json={"model_version": version, "label_file": str(label_path)}
    )
    return bool(response.json()["data"]["trained"])


class TestMLHealthAndSchema:
    def test_health_reports_disabled_by_default(
        self, client: TestClient, ml_schema: MLFeatureSchema
    ) -> None:
        response = client.get("/api/v1/ml/health")
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        data = body["data"]
        # ML is off unless a test opts in, and the shipped default is off.
        assert data["ml_enabled"] is False
        assert data["training_enabled"] is False
        assert data["any_model_available"] is False
        assert data["active_model_version"] is None
        assert data["detail"] is not None

    def test_health_is_200_not_an_error_when_unavailable(
        self, client: TestClient, ml_schema: MLFeatureSchema
    ) -> None:
        # "No model yet" is a normal state, so it must not be an HTTP failure.
        assert client.get("/api/v1/ml/health").status_code == 200

    def test_health_reports_enabled(self, client: TestClient, ml_settings: None) -> None:
        data = client.get("/api/v1/ml/health").json()["data"]
        assert data["ml_enabled"] is True
        assert data["feature_schema_version"] == "1.0"
        assert data["min_confidence"] == 0.60

    def test_schema_lists_27_features(self, client: TestClient, ml_schema: MLFeatureSchema) -> None:
        data = client.get("/api/v1/ml/schema").json()["data"]
        assert len(data["features"]) == 27
        assert data["feature_schema_version"] == "1.0"

    def test_schema_exposes_exclusions(
        self, client: TestClient, ml_schema: MLFeatureSchema
    ) -> None:
        data = client.get("/api/v1/ml/schema").json()["data"]
        excluded = set(data["excluded_features"])
        # Leakage controls must be visible to a reviewer of the API contract.
        assert {"source_port", "source_ip", "severity", "start_time"} <= excluded

    def test_schema_split_is_capture_level(
        self, client: TestClient, ml_schema: MLFeatureSchema
    ) -> None:
        split = client.get("/api/v1/ml/schema").json()["data"]["split"]
        assert split["unit"] == "capture"
        assert split["random_seed"] == 42

    def test_schema_declares_no_active_classes(
        self, client: TestClient, ml_schema: MLFeatureSchema
    ) -> None:
        data = client.get("/api/v1/ml/schema").json()["data"]
        assert "UNKNOWN" in data["classes"]

    def test_features_endpoint_includes_threshold(
        self, client: TestClient, ml_schema: MLFeatureSchema
    ) -> None:
        data = client.get("/api/v1/ml/features").json()["data"]
        assert data["feature_count"] == 27
        assert data["min_confidence"] == 0.60

    def test_dataset_endpoint_reports_insufficient_labeled_data(
        self, client: TestClient, db_session: Session, ml_schema: MLFeatureSchema
    ) -> None:
        build_deterministic_dataset(
            db_session, schema=ml_schema, flows_per_class=3, captures_per_class=2
        )
        data = client.get("/api/v1/ml/dataset").json()["data"]
        assert data["status"] == "INSUFFICIENT_LABELED_DATA"
        assert data["labeled_rows"] == 0
        assert data["label_registry_source"] == "none"

    def test_dataset_endpoint_audits_an_explicit_label_file(
        self,
        client: TestClient,
        db_session: Session,
        ml_schema: MLFeatureSchema,
        tmp_path: Path,
    ) -> None:
        """`/dataset` must resolve labels the same way `POST /train` does.

        Otherwise an operator who trains against an explicit `label_file` is
        told here that nothing is labeled, while training had just succeeded.
        """
        labels, shas = build_deterministic_dataset(
            db_session, schema=ml_schema, flows_per_class=3, captures_per_class=2
        )
        label_file = write_label_file(
            tmp_path / "ground_truth.json", labels, shas=shas, schema=ml_schema
        )
        data = client.get("/api/v1/ml/dataset", params={"label_file": str(label_file)}).json()[
            "data"
        ]
        assert data["labeled_rows"] > 0
        assert data["label_registry_source"] != "none"
        assert data["class_distribution"]


class TestTrainingEndpoint:
    def test_training_blocked_when_disabled(
        self, client: TestClient, ml_schema: MLFeatureSchema
    ) -> None:
        response = client.post("/api/v1/ml/train", json={})
        assert response.status_code == 500
        assert response.json()["success"] is False

    def test_training_refuses_without_labels(
        self, client: TestClient, db_session: Session, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        build_deterministic_dataset(
            db_session, schema=ml_schema, flows_per_class=3, captures_per_class=2
        )
        response = client.post("/api/v1/ml/train", json={})
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "INSUFFICIENT_LABELED_DATA"
        assert data["trained"] is False
        assert data["model_version"] is None
        assert data["metrics"] is None

    def test_refused_training_registers_no_model(
        self, client: TestClient, db_session: Session, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        build_deterministic_dataset(
            db_session, schema=ml_schema, flows_per_class=3, captures_per_class=2
        )
        client.post("/api/v1/ml/train", json={})
        assert client.get("/api/v1/ml/models").json()["data"]["total"] == 0

    def test_refusal_message_is_actionable(
        self, client: TestClient, db_session: Session, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        build_deterministic_dataset(
            db_session, schema=ml_schema, flows_per_class=3, captures_per_class=2
        )
        message = client.post("/api/v1/ml/train", json={}).json()["data"]["message"]
        assert "ML_LABEL_FILE" in message

    def test_training_with_label_file_succeeds(
        self,
        client: TestClient,
        labeled_analysis: tuple[str, Path],
        ml_settings: None,
        ml_schema: MLFeatureSchema,
    ) -> None:
        _, label_path = labeled_analysis
        response = client.post(
            "/api/v1/ml/train", json={"model_version": "api-1.0.0", "label_file": str(label_path)}
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "OK"
        assert data["trained"] is True
        assert data["model_version"] == "api-1.0.0"
        assert data["metrics"] is not None
        assert data["metrics"]["accuracy"] is not None

    def test_trained_model_appears_in_registry(
        self,
        client: TestClient,
        labeled_analysis: tuple[str, Path],
        ml_settings: None,
        ml_schema: MLFeatureSchema,
    ) -> None:
        _, label_path = labeled_analysis
        client.post(
            "/api/v1/ml/train", json={"model_version": "api-1.0.0", "label_file": str(label_path)}
        )
        data = client.get("/api/v1/ml/models").json()["data"]
        assert data["total"] == 1
        assert data["active_model_version"] == "api-1.0.0"
        assert data["models"][0]["model_version"] == "api-1.0.0"

    def test_model_detail_endpoint(
        self,
        client: TestClient,
        labeled_analysis: tuple[str, Path],
        ml_settings: None,
        ml_schema: MLFeatureSchema,
    ) -> None:
        _, label_path = labeled_analysis
        client.post(
            "/api/v1/ml/train", json={"model_version": "api-1.0.0", "label_file": str(label_path)}
        )
        data = client.get("/api/v1/ml/models/api-1.0.0").json()["data"]
        assert data["feature_schema_version"] == "1.0"
        assert data["feature_count"] == 27
        assert data["library_versions"]["scikit_learn"]

    def test_unknown_model_is_404(
        self, client: TestClient, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        response = client.get("/api/v1/ml/models/does-not-exist")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"

    def test_model_metrics_endpoint(
        self,
        client: TestClient,
        labeled_analysis: tuple[str, Path],
        ml_settings: None,
        ml_schema: MLFeatureSchema,
    ) -> None:
        _, label_path = labeled_analysis
        client.post(
            "/api/v1/ml/train", json={"model_version": "api-1.0.0", "label_file": str(label_path)}
        )
        data = client.get("/api/v1/ml/models/api-1.0.0/metrics").json()["data"]
        assert data["evaluated"] is True
        assert data["metrics"]["accuracy"] is not None
        assert data["note"] is None

    def test_invalid_model_version_is_rejected(
        self, client: TestClient, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        # Path traversal must not be reachable through the version parameter.
        response = client.get("/api/v1/ml/models/..%2F..%2Fetc")
        assert response.status_code in (400, 404)

    def test_malformed_model_version_on_train_is_rejected(
        self, client: TestClient, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        response = client.post("/api/v1/ml/train", json={"model_version": "../evil"})
        assert response.status_code == 422

    def test_unreadable_label_file_is_a_400(
        self, client: TestClient, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        response = client.post("/api/v1/ml/train", json={"label_file": "/nonexistent/labels.json"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "BAD_REQUEST"


class TestPredictionEndpoint:
    @pytest.fixture()
    def trained_client(
        self,
        client: TestClient,
        labeled_analysis: tuple[str, Path],
        ml_settings: None,
        ml_schema: MLFeatureSchema,
    ) -> TestClient:
        _, label_path = labeled_analysis
        assert train_from_labels(client, label_path)
        return client

    def test_predict_when_disabled_is_not_an_error(
        self, client: TestClient, db_session: Session, ml_schema: MLFeatureSchema
    ) -> None:
        capture = make_capture(db_session, "CAP-DIS")
        analysis = make_analysis(db_session, capture, "ANL-DIS")
        make_flow_with_features(db_session, analysis, synthetic_features("WEB", 0, ml_schema))
        db_session.commit()

        response = client.post("/api/v1/ml/analyses/ANL-DIS/predict")
        assert response.status_code == 200
        assert response.json()["data"]["status"] == "DISABLED"

    def test_predict_without_model_reports_unavailable(
        self, client: TestClient, db_session: Session, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        capture = make_capture(db_session, "CAP-NM")
        analysis = make_analysis(db_session, capture, "ANL-NM")
        make_flow_with_features(db_session, analysis, synthetic_features("WEB", 0, ml_schema))
        db_session.commit()

        response = client.post("/api/v1/ml/analyses/ANL-NM/predict")
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "MODEL_NOT_AVAILABLE"
        assert data["created"] == 0
        assert data["detail"]["reason"]
        # `total` counts candidate flows, not predictions. It is non-zero here
        # because the analysis does have flows, so anything rendering it as
        # "predictions" would be wrong; `summary.count` is the honest zero.
        assert data["total"] == 1
        assert data["summary"]["count"] == 0
        assert data["observation_status"] == ObservationStatus.MODEL_PREDICTED.value

        stored = db_session.scalars(select(TrafficPrediction)).all()
        assert stored == [], "an unavailable run must not persist predictions"

    def test_predict_unknown_analysis_is_404(
        self, client: TestClient, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        response = client.post("/api/v1/ml/analyses/ANL-NOPE/predict")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "ANALYSIS_NOT_FOUND"

    def test_predict_persists_rows(self, trained_client: TestClient, db_session: Session) -> None:
        response = trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "OK"
        assert data["created"] == 10
        assert data["total"] == 10
        count = db_session.scalar(select(func.count()).select_from(TrafficPrediction))
        assert count == 10

    def test_predictions_are_persisted_with_model_predicted_status(
        self, trained_client: TestClient, db_session: Session
    ) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        rows = db_session.scalars(select(TrafficPrediction)).all()
        assert rows
        for row in rows:
            assert row.observation_status == "model_predicted"
            assert row.model_version == "api-1.0.0"
            assert row.feature_schema_version == "1.0"
            assert 0.0 <= row.confidence <= 1.0
            assert row.capture_id == "CAP-T000"

    def test_prediction_ids_are_assigned(
        self, trained_client: TestClient, db_session: Session
    ) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        ids = [row.prediction_id for row in db_session.scalars(select(TrafficPrediction)).all()]
        # The `is not None` check is load-bearing: it asserts the human
        # identifier is always populated, not just well-formed when present.
        assert all(value is not None and value.startswith("PRED-") for value in ids)
        assert len(set(ids)) == len(ids)

    def test_rerun_is_idempotent_and_does_not_grow(
        self, trained_client: TestClient, db_session: Session
    ) -> None:
        first = trained_client.post("/api/v1/ml/analyses/ANL-T000/predict").json()["data"]
        assert first["created"] == 10

        second = trained_client.post("/api/v1/ml/analyses/ANL-T000/predict").json()["data"]
        assert second["created"] == 0
        assert second["updated"] == 10

        count = db_session.scalar(select(func.count()).select_from(TrafficPrediction))
        assert count == 10, "re-running inference must not append duplicate rows"

    def test_third_run_also_stable(self, trained_client: TestClient, db_session: Session) -> None:
        for _ in range(3):
            trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        count = db_session.scalar(select(func.count()).select_from(TrafficPrediction))
        assert count == 10

    def test_list_predictions_returns_stored_rows(self, trained_client: TestClient) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        data = trained_client.get("/api/v1/ml/analyses/ANL-T000/predictions").json()["data"]
        assert data["status"] == "OK"
        assert len(data["predictions"]) == 10
        assert data["summary"]["count"] == 10
        assert data["summary"]["model_version"] == "api-1.0.0"

    def test_list_predictions_empty_state_is_not_an_error(
        self, client: TestClient, db_session: Session, ml_settings: None, ml_schema: MLFeatureSchema
    ) -> None:
        capture = make_capture(db_session, "CAP-EMPTY")
        make_analysis(db_session, capture, "ANL-EMPTY")
        db_session.commit()

        response = client.get("/api/v1/ml/analyses/ANL-EMPTY/predictions")
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["predictions"] == []
        assert data["summary"]["count"] == 0

    def test_prediction_filter_by_class(self, trained_client: TestClient) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        all_rows = trained_client.get("/api/v1/ml/analyses/ANL-T000/predictions").json()["data"]
        classes = {row["prediction"] for row in all_rows["predictions"]}
        target = sorted(classes)[0]
        filtered = trained_client.get(
            f"/api/v1/ml/analyses/ANL-T000/predictions?prediction={target}"
        ).json()["data"]
        assert all(row["prediction"] == target for row in filtered["predictions"])

    def test_delete_predictions_clears_rows(
        self, trained_client: TestClient, db_session: Session
    ) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        deleted = trained_client.delete("/api/v1/ml/analyses/ANL-T000/predictions").json()["data"]
        assert deleted["deleted"] == 10
        count = db_session.scalar(select(func.count()).select_from(TrafficPrediction))
        assert count == 0

    def test_history_endpoint(self, trained_client: TestClient) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        data = trained_client.get("/api/v1/ml/predictions").json()["data"]
        assert data["total"] == 10

    def test_history_filters_by_capture(self, trained_client: TestClient) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        data = trained_client.get("/api/v1/ml/predictions?capture_id=CAP-T000").json()["data"]
        assert data["total"] == 10
        other = trained_client.get("/api/v1/ml/predictions?capture_id=CAP-NOPE").json()["data"]
        assert other["total"] == 0

    def test_flow_prediction_lookup(self, trained_client: TestClient, db_session: Session) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        row = db_session.scalar(select(TrafficPrediction))
        assert row is not None
        data = trained_client.get(f"/api/v1/ml/flows/{row.flow_id}/prediction").json()["data"]
        assert data["flow_id"] == row.flow_id
        assert data["observation_status"] == "model_predicted"

    def test_flow_prediction_unknown_flow_is_404(self, trained_client: TestClient) -> None:
        response = trained_client.get("/api/v1/ml/flows/does-not-exist/prediction")
        assert response.status_code == 404

    def test_probabilities_are_persisted(
        self, trained_client: TestClient, db_session: Session
    ) -> None:
        trained_client.post("/api/v1/ml/analyses/ANL-T000/predict")
        row = db_session.scalar(select(TrafficPrediction))
        assert row is not None
        assert row.probabilities
        assert sum(row.probabilities.values()) == pytest.approx(1.0, abs=1e-3)


class TestAbstentionSemantics:
    def test_high_threshold_yields_unknown_but_model_predicted(
        self,
        client: TestClient,
        db_session: Session,
        monkeypatch: pytest.MonkeyPatch,
        ml_settings: None,
        ml_schema: MLFeatureSchema,
    ) -> None:

        labels, shas = build_deterministic_dataset(
            db_session, schema=ml_schema, flows_per_class=10, captures_per_class=6
        )
        label_path = write_label_file(
            Path(str(get_settings().ML_MODEL_DIR)).parent / "gt.json",
            labels,
            shas=shas,
            schema=ml_schema,
        )
        assert client.post(
            "/api/v1/ml/train", json={"model_version": "abst-1.0.0", "label_file": str(label_path)}
        ).json()["data"]["trained"]

        # A threshold above 1.0 forces every flow to abstain.
        monkeypatch.setattr(get_settings(), "ML_MIN_CONFIDENCE", 1.01)
        response = client.post("/api/v1/ml/analyses/ANL-T000/predict")
        data = response.json()["data"]
        assert data["status"] == "OK"
        assert data["summary"]["abstained_count"] == 10
        assert data["summary"]["unknown_count"] == 10

        rows = client.get("/api/v1/ml/analyses/ANL-T000/predictions").json()["data"]["predictions"]
        for row in rows:
            assert row["prediction"] == "UNKNOWN"
            # The model ran, so the observation status is still MODEL_PREDICTED.
            # The wire value is the ObservationStatus enum member (lowercase),
            # matching Phase 3 evidence and the other enums in this project.
            assert row["observation_status"] == ObservationStatus.MODEL_PREDICTED.value
            assert row["abstained"] is True
            # The runner-up is preserved so the abstention stays auditable.
            assert row["top_candidate"]


class TestPhase3Isolation:
    """ML output must never become a security claim."""

    @pytest.fixture()
    def iso_client(
        self,
        client: TestClient,
        db_session: Session,
        ml_settings: None,
        ml_schema: MLFeatureSchema,
        label_path: Path,
    ) -> TestClient:
        labels, shas = build_deterministic_dataset(
            db_session, schema=ml_schema, flows_per_class=10, captures_per_class=6
        )
        write_label_file(label_path, labels, shas=shas, schema=ml_schema)
        assert train_from_labels(client, label_path, "iso-1.0.0")
        client.post("/api/v1/ml/analyses/ANL-T000/predict")
        return client

    def test_ml_does_not_create_findings(self, iso_client: TestClient, db_session: Session) -> None:
        findings = db_session.scalar(select(func.count()).select_from(SecurityFinding))
        assert findings == 0, "ML must never write a security finding"

    def test_findings_endpoint_still_works(self, iso_client: TestClient) -> None:
        # The Phase 3 API is untouched by a populated ML subsystem.
        assert iso_client.get("/api/v1/findings").status_code == 200

    def test_prediction_payload_has_no_security_fields(self, iso_client: TestClient) -> None:
        rows = iso_client.get("/api/v1/ml/analyses/ANL-T000/predictions").json()["data"][
            "predictions"
        ]
        assert rows
        for row in rows:
            for forbidden in (
                "severity",
                "risk_level",
                "security_score",
                "risk_score",
                "finding_id",
            ):
                assert forbidden not in row

    def test_analysis_delete_cascades_predictions(
        self, iso_client: TestClient, db_session: Session, enforce_foreign_keys: None
    ) -> None:
        before = db_session.scalar(select(func.count()).select_from(TrafficPrediction))
        assert before == 10

        analysis = db_session.scalar(select(Analysis).where(Analysis.analysis_id == "ANL-T000"))
        assert analysis is not None
        db_session.delete(analysis)
        db_session.commit()

        after = db_session.scalar(select(func.count()).select_from(TrafficPrediction))
        assert after == 0


class TestServiceLayer:
    def test_health_detail_present_when_disabled(self) -> None:
        health = ml_service.get_health()
        assert health["ml_enabled"] is False
        assert health["detail"] is not None
        assert "ML_ENABLED" in health["detail"]["reason"]

    def test_schema_payload_shape(self) -> None:
        payload = ml_service.ml_schema_payload()
        assert len(payload["features"]) == 27
        assert payload["split"]["unit"] == "capture"

    def test_predict_analysis_disabled_short_circuits(
        self, db_session: Session, ml_schema: MLFeatureSchema
    ) -> None:
        capture = make_capture(db_session, "CAP-SVC")
        analysis = make_analysis(db_session, capture, "ANL-SVC")
        db_session.commit()
        result = ml_service.predict_analysis(db_session, analysis)
        assert result.status == "DISABLED"
        # The API carries the ObservationStatus enum value, matching Phase 3's
        # evidence payload and the other enums in this project (severity is
        # stored "critical", not "CRITICAL"). The UI uppercases for display.
        assert result.observation_status == ObservationStatus.MODEL_PREDICTED.value
