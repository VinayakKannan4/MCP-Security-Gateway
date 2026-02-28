"""Safe scenario tests — expected ALLOW or APPROVAL_REQUIRED.

These tests call PolicyEngine.evaluate() directly — no HTTP, no DB, no LLM.
Fully deterministic and fast (<1s total).
"""
import pytest

from gateway.models.identity import TrustLevel
from gateway.models.policy import DecisionEnum
from gateway.policy.engine import PolicyEngine
from tests.scenarios.conftest import make_request


@pytest.mark.scenario
@pytest.mark.safe
def test_safe_sql_select_analyst(scenario_engine: PolicyEngine) -> None:
    """Scenario 7 — Safe SQL SELECT query by an analyst in prod.

    Matches allow-sql-readonly-analysts: SELECT is an allowed statement
    and no denied keywords are present.
    """
    request, identity = make_request(
        tool="sql.query",
        server="db-mcp",
        args={"query": "SELECT COUNT(*) FROM sales WHERE date > '2025-01-01'"},
        role="analyst",
        trust_level=TrustLevel.MEDIUM,
        environment="prod",
    )
    decision = scenario_engine.evaluate(request, identity)
    assert decision.decision == DecisionEnum.ALLOW
    assert decision.matched_rule == "allow-sql-readonly-analysts"


@pytest.mark.scenario
@pytest.mark.safe
def test_safe_fs_read_allowed_prefix(scenario_engine: PolicyEngine) -> None:
    """Scenario 8 — Safe fs.read within /data/ allowed prefix by an analyst in prod.

    Matches allow-fs-read-authorized: path starts with /data/ and contains
    no denied patterns.
    """
    request, identity = make_request(
        tool="fs.read",
        server="filesystem-mcp",
        args={"path": "/data/report.csv"},
        role="analyst",
        trust_level=TrustLevel.MEDIUM,
        environment="prod",
    )
    decision = scenario_engine.evaluate(request, identity)
    assert decision.decision == DecisionEnum.ALLOW
    assert decision.matched_rule == "allow-fs-read-authorized"


@pytest.mark.scenario
@pytest.mark.safe
def test_fs_write_prod_requires_approval(scenario_engine: PolicyEngine) -> None:
    """Scenario 9 — fs.write in production requires human approval for a developer.

    Matches require-approval-fs-write-prod: developer role + prod environment +
    path within /data/output/ prefix.
    """
    request, identity = make_request(
        tool="fs.write",
        server="filesystem-mcp",
        args={"path": "/data/output/results.json", "content": '{"status": "ok"}'},
        role="developer",
        trust_level=TrustLevel.HIGH,
        environment="prod",
    )
    decision = scenario_engine.evaluate(request, identity)
    assert decision.decision == DecisionEnum.APPROVAL_REQUIRED
    assert decision.matched_rule == "require-approval-fs-write-prod"


@pytest.mark.scenario
@pytest.mark.safe
def test_safe_fs_read_reports_prefix(scenario_engine: PolicyEngine) -> None:
    """Scenario 10 — Scoped fs.read within /reports/ allowed prefix by a developer in prod.

    Matches allow-fs-read-authorized: path starts with /reports/ and contains
    no denied patterns.
    """
    request, identity = make_request(
        tool="fs.read",
        server="filesystem-mcp",
        args={"path": "/reports/quarterly/2025-Q1.pdf"},
        role="developer",
        trust_level=TrustLevel.HIGH,
        environment="prod",
    )
    decision = scenario_engine.evaluate(request, identity)
    assert decision.decision == DecisionEnum.ALLOW
    assert decision.matched_rule == "allow-fs-read-authorized"
