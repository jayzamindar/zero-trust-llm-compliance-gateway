from typing import Any, Dict, Generator, Optional
import pytest
from fastapi.testclient import TestClient

from app.engine import ComplianceEngine
from app.main import app, get_compliance_engine
from app.storage import InMemoryTokenStorage, RedisTokenStorage


class MockRedisPipeline:
    """Mock for redis.asyncio pipeline supporting hset and expire."""

    def __init__(self, client: "MockAsyncRedisClient") -> None:
        self.client = client
        self.commands = []

    def hset(self, name: str, key: str, value: str) -> "MockRedisPipeline":
        self.commands.append(("hset", name, key, value))
        return self

    def hincrby(self, name: str, key: str, amount: int = 1) -> "MockRedisPipeline":
        self.commands.append(("hincrby", name, key, amount))
        return self

    def expire(self, name: str, time: int) -> "MockRedisPipeline":
        self.commands.append(("expire", name, time))
        return self

    async def execute(self) -> list:
        results = []
        for cmd in self.commands:
            if cmd[0] == "hset":
                _, name, key, value = cmd
                self.client._hashes.setdefault(name, {})[key] = value
                results.append(1)
            elif cmd[0] == "hincrby":
                _, name, key, amount = cmd
                hash_map = self.client._hashes.setdefault(name, {})
                new_val = int(hash_map.get(key, 0)) + amount
                hash_map[key] = new_val
                results.append(new_val)
            elif cmd[0] == "expire":
                _, name, time = cmd
                self.client._ttls[name] = time
                results.append(True)
        self.commands.clear()
        return results


class MockAsyncRedisClient:
    """In-memory mock for redis.asyncio.Redis to test RedisTokenStorage."""

    def __init__(self) -> None:
        self._hashes: Dict[str, Dict[str, Any]] = {}
        self._ttls: Dict[str, int] = {}
        self._is_alive: bool = True

    async def hget(self, name: str, key: str) -> Optional[str]:
        if not self._is_alive:
            raise ConnectionError("Redis connection lost")
        return self._hashes.get(name, {}).get(key)

    async def hincrby(self, name: str, key: str, amount: int = 1) -> int:
        if not self._is_alive:
            raise ConnectionError("Redis connection lost")
        hash_map = self._hashes.setdefault(name, {})
        val = int(hash_map.get(key, 0)) + amount
        hash_map[key] = val
        return val

    def pipeline(self) -> MockRedisPipeline:
        return MockRedisPipeline(self)

    async def hgetall(self, name: str) -> Dict[str, str]:
        if not self._is_alive:
            raise ConnectionError("Redis connection lost")
        return dict(self._hashes.get(name, {}))

    async def expire(self, name: str, time: int) -> bool:
        if not self._is_alive:
            raise ConnectionError("Redis connection lost")
        self._ttls[name] = time
        return True

    async def delete(self, *names: str) -> int:
        count = 0
        for name in names:
            if name in self._hashes:
                del self._hashes[name]
                count += 1
            self._ttls.pop(name, None)
        return count

    async def ping(self) -> bool:
        if not self._is_alive:
            raise ConnectionError("Redis connection lost")
        return True


@pytest.fixture
def clean_engine() -> ComplianceEngine:
    """Fixture providing a fresh ComplianceEngine instance isolated for each test."""
    return ComplianceEngine(storage=InMemoryTokenStorage())


@pytest.fixture
def mock_redis_client() -> MockAsyncRedisClient:
    """Fixture providing a simulated Redis client with pipeline and TTL tracking."""
    return MockAsyncRedisClient()


@pytest.fixture
def redis_storage(mock_redis_client: MockAsyncRedisClient) -> RedisTokenStorage:
    """Fixture providing RedisTokenStorage backed by the in-memory mock Redis client."""
    return RedisTokenStorage(redis_client=mock_redis_client, ttl_seconds=1800)


@pytest.fixture
def client(clean_engine: ComplianceEngine) -> Generator[TestClient, None, None]:
    """
    Fixture providing a FastAPI TestClient with the compliance engine dependency
    overridden with the fresh test engine instance.
    """
    app.dependency_overrides[get_compliance_engine] = lambda: clean_engine
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def valid_request_payload() -> dict:
    """Standard valid payload for testing."""
    return {
        "prompt": "Hello compliance team. Review account for alice@example.com with SSN 123-45-6789.",
        "session_id": "sess_unit_test_001",
        "user_id": "usr_analyst_901",
    }
