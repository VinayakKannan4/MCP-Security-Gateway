"""Unit tests for gateway/cache/redis_client.py.

Uses fakeredis so no real Redis server is needed.
"""

import pytest
import fakeredis.aioredis

from gateway.cache.redis_client import delete, get_json, set_json


@pytest.fixture
async def redis():
    """Provide a fresh in-memory FakeRedis client for each test."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.aclose()


# ---------------------------------------------------------------------------
# set_json / get_json roundtrip
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_set_and_get_json_roundtrip(redis):
    value = {"token": "abc123", "status": "PENDING", "nested": {"score": 0.9}}
    await set_json(redis, "test:key", value, ttl=60)
    result = await get_json(redis, "test:key")
    assert result == value


@pytest.mark.unit
async def test_get_json_returns_none_for_missing_key(redis):
    result = await get_json(redis, "does:not:exist")
    assert result is None


@pytest.mark.unit
async def test_set_json_overwrites_existing_key(redis):
    await set_json(redis, "test:key", {"v": 1}, ttl=60)
    await set_json(redis, "test:key", {"v": 2}, ttl=60)
    result = await get_json(redis, "test:key")
    assert result == {"v": 2}


@pytest.mark.unit
async def test_set_json_stores_ttl(redis):
    await set_json(redis, "test:key", {"x": 1}, ttl=300)
    ttl = await redis.ttl("test:key")
    # TTL should be positive and at most 300s
    assert 0 < ttl <= 300


# ---------------------------------------------------------------------------
# TTL enforcement — security invariant
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_set_json_rejects_zero_ttl(redis):
    with pytest.raises(ValueError, match="ttl must be positive"):
        await set_json(redis, "test:key", {"x": 1}, ttl=0)


@pytest.mark.unit
async def test_set_json_rejects_negative_ttl(redis):
    with pytest.raises(ValueError, match="ttl must be positive"):
        await set_json(redis, "test:key", {"x": 1}, ttl=-1)


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_delete_removes_key(redis):
    await set_json(redis, "test:key", {"x": 1}, ttl=60)
    await delete(redis, "test:key")
    result = await get_json(redis, "test:key")
    assert result is None


@pytest.mark.unit
async def test_delete_nonexistent_key_does_not_raise(redis):
    # Deleting a key that doesn't exist should be a no-op
    await delete(redis, "does:not:exist")


# ---------------------------------------------------------------------------
# Data integrity
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_set_json_preserves_types(redis):
    value = {
        "int_field": 42,
        "float_field": 3.14,
        "bool_field": True,
        "null_field": None,
        "list_field": [1, "two", 3.0],
    }
    await set_json(redis, "test:types", value, ttl=60)
    result = await get_json(redis, "test:types")
    assert result == value


@pytest.mark.unit
async def test_different_keys_are_independent(redis):
    await set_json(redis, "key:a", {"v": "alpha"}, ttl=60)
    await set_json(redis, "key:b", {"v": "beta"}, ttl=60)
    assert await get_json(redis, "key:a") == {"v": "alpha"}
    assert await get_json(redis, "key:b") == {"v": "beta"}
