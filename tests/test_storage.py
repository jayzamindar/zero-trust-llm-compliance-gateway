import pytest
from app.engine import ComplianceEngine, ComplianceEngineCrashError
from app.schemas import GatewayRequest
from app.storage import InMemoryTokenStorage, RedisTokenStorage
from tests.conftest import MockAsyncRedisClient


class TestInMemoryTokenStorage:
    """Unit tests for InMemoryTokenStorage."""

    @pytest.mark.asyncio
    async def test_async_token_creation_and_idempotency(self):
        storage = InMemoryTokenStorage()
        token1 = await storage.get_or_create_token("sess_1", "alice@example.com", "EMAIL")
        token2 = await storage.get_or_create_token("sess_1", "alice@example.com", "EMAIL")
        token3 = await storage.get_or_create_token("sess_1", "bob@example.com", "EMAIL")

        assert token1 == "<EMAIL_TOKEN_1>"
        assert token2 == "<EMAIL_TOKEN_1>"  # Idempotent within same session
        assert token3 == "<EMAIL_TOKEN_2>"

    @pytest.mark.asyncio
    async def test_async_session_retrieval_and_clear(self):
        storage = InMemoryTokenStorage()
        await storage.get_or_create_token("sess_1", "123-45-6789", "SSN")
        tokens = await storage.get_tokens_for_session("sess_1")
        assert tokens == {"<SSN_TOKEN_1>": "123-45-6789"}

        await storage.clear_session("sess_1")
        empty_tokens = await storage.get_tokens_for_session("sess_1")
        assert empty_tokens == {}

    @pytest.mark.asyncio
    async def test_ping(self):
        storage = InMemoryTokenStorage()
        assert await storage.ping() is True


class TestRedisTokenStorage:
    """Unit tests for RedisTokenStorage with simulated Redis backend."""

    @pytest.mark.asyncio
    async def test_redis_token_lifecycle_and_ttl(
        self, redis_storage: RedisTokenStorage, mock_redis_client: MockAsyncRedisClient
    ):
        # 1. Create first token
        token1 = await redis_storage.get_or_create_token(
            "sess_red_1", "support@fintech.io", "EMAIL"
        )
        assert token1 == "<EMAIL_TOKEN_1>"

        # Verify TTL was set in Redis
        tokens_key = redis_storage._tokens_key("sess_red_1")
        values_key = redis_storage._values_key("sess_red_1")
        counters_key = redis_storage._counters_key("sess_red_1")
        assert mock_redis_client._ttls[tokens_key] == redis_storage.ttl_seconds
        assert mock_redis_client._ttls[values_key] == redis_storage.ttl_seconds
        assert mock_redis_client._ttls[counters_key] == redis_storage.ttl_seconds

        # 2. Re-requesting same email reuses token and refreshes TTL
        token2 = await redis_storage.get_or_create_token(
            "sess_red_1", "support@fintech.io", "EMAIL"
        )
        assert token2 == "<EMAIL_TOKEN_1>"

        # 3. Create second distinct token
        token3 = await redis_storage.get_or_create_token(
            "sess_red_1", "456-78-1234", "SSN"
        )
        assert token3 == "<SSN_TOKEN_1>"

        # 4. Retrieve session mappings
        tokens = await redis_storage.get_tokens_for_session("sess_red_1")
        assert tokens["<EMAIL_TOKEN_1>"] == "support@fintech.io"
        assert tokens["<SSN_TOKEN_1>"] == "456-78-1234"

        # 5. Clear session deletes keys
        await redis_storage.clear_session("sess_red_1")
        tokens_after = await redis_storage.get_tokens_for_session("sess_red_1")
        assert tokens_after == {}

    @pytest.mark.asyncio
    async def test_redis_ping_health(
        self, redis_storage: RedisTokenStorage, mock_redis_client: MockAsyncRedisClient
    ):
        assert await redis_storage.ping() is True
        mock_redis_client._is_alive = False
        assert await redis_storage.ping() is False


class TestComplianceEngineWithRedis:
    """Integration tests for ComplianceEngine backed by RedisTokenStorage."""

    @pytest.mark.asyncio
    async def test_engine_async_mask_and_unmask(self, redis_storage: RedisTokenStorage):
        engine = ComplianceEngine(storage=redis_storage)

        req = GatewayRequest(
            prompt="User sec_lead@corp.net verified with SSN 321-45-6789.",
            session_id="sess_redis_roundtrip",
            user_id="usr_audit",
        )

        # Asynchronous mask
        masked_req = await engine.mask_async(req)
        assert isinstance(masked_req, GatewayRequest)
        assert "sec_lead@corp.net" not in masked_req.prompt
        assert "321-45-6789" not in masked_req.prompt
        assert "<EMAIL_TOKEN_1>" in masked_req.prompt
        assert "<SSN_TOKEN_1>" in masked_req.prompt

        # Asynchronous unmask
        unmasked_req = await engine.unmask_async(masked_req)
        assert isinstance(unmasked_req, GatewayRequest)
        assert unmasked_req.prompt == req.prompt

    @pytest.mark.asyncio
    async def test_engine_fail_closed_when_storage_unreachable(
        self, redis_storage: RedisTokenStorage, mock_redis_client: MockAsyncRedisClient
    ):
        """Zero-Trust Fail-Closed: If Redis crashes, health check fails closed immediately."""
        engine = ComplianceEngine(storage=redis_storage)

        # Healthy initially
        health = await engine.health_check_async()
        assert health["status"] == "healthy"

        # Simulate Redis outage
        mock_redis_client._is_alive = False
        with pytest.raises(ComplianceEngineCrashError) as exc_info:
            await engine.health_check_async(raise_on_crash=True)
        assert "unreachable" in str(exc_info.value).lower()

