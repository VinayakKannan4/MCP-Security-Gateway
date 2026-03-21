"""Unit tests for gateway/observability/otel.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI

from gateway.config import Settings
from gateway.observability.otel import configure_otel


@pytest.mark.unit
def test_configure_otel_noop_when_disabled() -> None:
    """configure_otel is a complete no-op when otel_enabled=False."""
    app = FastAPI()
    settings = Settings(otel_enabled=False)

    # Should not raise and should not touch TracerProvider
    with patch("gateway.observability.otel.TracerProvider") as mock_tp:
        configure_otel(app, settings)
        mock_tp.assert_not_called()


@pytest.mark.unit
def test_configure_otel_enabled_no_raise() -> None:
    """configure_otel does not raise when otel_enabled=True (SDK mocked)."""
    app = FastAPI()
    settings = Settings(otel_enabled=True, otel_endpoint="http://localhost:4317")

    mock_provider = MagicMock()
    mock_exporter = MagicMock()
    mock_processor = MagicMock()

    with (
        patch("gateway.observability.otel._OTEL_AVAILABLE", True),
        patch("gateway.observability.otel.TracerProvider", return_value=mock_provider),
        patch("gateway.observability.otel.OTLPSpanExporter", return_value=mock_exporter),
        patch("gateway.observability.otel.BatchSpanProcessor", return_value=mock_processor),
        patch("gateway.observability.otel.FastAPIInstrumentor") as mock_fai,
        patch("gateway.observability.otel.trace"),
        patch("gateway.observability.otel.Resource"),
    ):
        configure_otel(app, settings)

    mock_provider.add_span_processor.assert_called_once_with(mock_processor)
    mock_fai.instrument_app.assert_called_once_with(app)


@pytest.mark.unit
def test_configure_otel_disabled_does_not_call_sdk() -> None:
    """When disabled, OTel SDK methods are never called."""
    app = FastAPI()
    settings = Settings(otel_enabled=False)

    with patch("gateway.observability.otel.TracerProvider") as mock_tp:
        configure_otel(app, settings)
        mock_tp.assert_not_called()
