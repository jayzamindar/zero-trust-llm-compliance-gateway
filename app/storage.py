import asyncio
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class QuotaExceededError(RuntimeError):
    """Raised when a project or user group exceeds their allocated request or token budget."""

    pass


class BaseTokenStorage(ABC):
    """
    Abstract asynchronous interface for session-scoped PII token storage
    and project-based quota/rate limit enforcement.
    """

    @abstractmethod
    async def get_or_create_token(
        self, session_id: str, original_value: str, token_type: str
    ) -> str:
        """Idempotently fetch or create an ephemeral token for original_value."""
        pass

    @abstractmethod
    async def get_tokens_for_session(self, session_id: str) -> Dict[str, str]:
        """Retrieve token-to-value map for detokenization/unmasking."""
        pass

    @abstractmethod
    async def clear_session(self, session_id: str) -> None:
        """Evict all ephemeral tokens for the specified session."""
        pass

    @abstractmethod
    async def ping(self) -> bool:
        """Check backend storage health/connectivity."""
        pass

    @abstractmethod
    async def check_and_consume_quota(
        self,
        project_id: str,
        estimated_tokens: int,
        max_daily_requests: Optional[int] = None,
        max_daily_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Atomically check and consume request & token quota for project_id."""
        pass


class InMemoryTokenStorage(BaseTokenStorage):
    """
    Thread-safe and async-safe in-memory token storage with quota enforcement.
    Ideal for local development, edge deployments, and test suites.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._vaults: Dict[str, Dict[str, Any]] = {}
        self._quotas: Dict[str, Dict[str, Any]] = {}

    def _get_or_create_vault(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            if session_id not in self._vaults:
                self._vaults[session_id] = {
                    "token_to_value": {},
                    "value_to_token": {},
                    "counters": {"EMAIL": 0, "SSN": 0},
                }
            return self._vaults[session_id]

    # --- Synchronous Token Operations ---

    def get_or_create_token_sync(
        self, session_id: str, original_value: str, token_type: str
    ) -> str:
        with self._lock:
            vault = self._get_or_create_vault(session_id)
            if original_value in vault["value_to_token"]:
                return vault["value_to_token"][original_value]

            vault["counters"].setdefault(token_type, 0)
            vault["counters"][token_type] += 1
            counter = vault["counters"][token_type]
            token = f"<{token_type}_TOKEN_{counter}>"

            vault["value_to_token"][original_value] = token
            vault["token_to_value"][token] = original_value
            return token

    def get_tokens_for_session_sync(self, session_id: str) -> Dict[str, str]:
        with self._lock:
            vault = self._vaults.get(session_id)
            if not vault:
                return {}
            return dict(vault["token_to_value"])

    def clear_session_sync(self, session_id: str) -> None:
        with self._lock:
            self._vaults.pop(session_id, None)

    def ping_sync(self) -> bool:
        return True

    # --- Synchronous Quota Operations ---

    def check_and_consume_quota_sync(
        self,
        project_id: str,
        estimated_tokens: int,
        max_daily_requests: Optional[int] = None,
        max_daily_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            record = self._quotas.get(project_id)
            if not record or record.get("date") != today:
                record = {"date": today, "requests": 0, "tokens": 0}
                self._quotas[project_id] = record

            current_reqs = record["requests"]
            current_tokens = record["tokens"]

            if max_daily_requests is not None and current_reqs + 1 > max_daily_requests:
                raise QuotaExceededError(
                    f"Daily request quota exceeded for project '{project_id}': "
                    f"limit={max_daily_requests}, used={current_reqs}"
                )

            if (
                max_daily_tokens is not None
                and current_tokens + estimated_tokens > max_daily_tokens
            ):
                raise QuotaExceededError(
                    f"Daily token quota exceeded for project '{project_id}': "
                    f"limit={max_daily_tokens}, used={current_tokens}, requested={estimated_tokens}"
                )

            record["requests"] += 1
            record["tokens"] += estimated_tokens
            return {
                "project_id": project_id,
                "requests": record["requests"],
                "tokens": record["tokens"],
                "date": today,
            }

    # --- Asynchronous Interface Implementations ---

    async def get_or_create_token(
        self, session_id: str, original_value: str, token_type: str
    ) -> str:
        return self.get_or_create_token_sync(session_id, original_value, token_type)

    async def get_tokens_for_session(self, session_id: str) -> Dict[str, str]:
        return self.get_tokens_for_session_sync(session_id)

    async def clear_session(self, session_id: str) -> None:
        self.clear_session_sync(session_id)

    async def ping(self) -> bool:
        return self.ping_sync()

    async def check_and_consume_quota(
        self,
        project_id: str,
        estimated_tokens: int,
        max_daily_requests: Optional[int] = None,
        max_daily_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        return self.check_and_consume_quota_sync(
            project_id, estimated_tokens, max_daily_requests, max_daily_tokens
        )


class RedisTokenStorage(BaseTokenStorage):
    """
    Distributed Redis storage backend for ComplianceEngine.
    Enforces per-session TTL, namespace isolation, atomic token generation,
    and daily sliding/window quota tracking across project tiers.
    """

    def __init__(
        self,
        redis_client: Any = None,
        redis_url: Optional[str] = None,
        ttl_seconds: int = 3600,
        key_prefix: str = "compliance:vault",
    ) -> None:
        self.client = redis_client
        self.redis_url = redis_url or "redis://localhost:6379/0"
        self.ttl_seconds = ttl_seconds
        self.key_prefix = key_prefix

    def _get_client(self) -> Any:
        if self.client is not None:
            return self.client
        try:
            import redis.asyncio as aioredis

            self.client = aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
            return self.client
        except ImportError as e:
            raise ImportError(
                "Redis client requested but 'redis' package is not installed. "
                "Install it with 'pip install redis'."
            ) from e

    def _tokens_key(self, session_id: str) -> str:
        return f"{self.key_prefix}:{session_id}:tokens"

    def _values_key(self, session_id: str) -> str:
        return f"{self.key_prefix}:{session_id}:values"

    def _counters_key(self, session_id: str) -> str:
        return f"{self.key_prefix}:{session_id}:counters"

    def _quota_key(self, project_id: str, date_str: str) -> str:
        return f"{self.key_prefix}:quota:{project_id}:{date_str}"

    async def get_or_create_token(
        self, session_id: str, original_value: str, token_type: str
    ) -> str:
        client = self._get_client()
        tokens_key = self._tokens_key(session_id)
        values_key = self._values_key(session_id)
        counters_key = self._counters_key(session_id)

        # 1. Check if token already exists for this value in session
        existing_token = await client.hget(values_key, original_value)
        if existing_token:
            # Refresh TTL on access
            await client.expire(tokens_key, self.ttl_seconds)
            await client.expire(values_key, self.ttl_seconds)
            await client.expire(counters_key, self.ttl_seconds)
            return existing_token

        # 2. Atomic counter increment
        counter = await client.hincrby(counters_key, token_type, 1)
        token = f"<{token_type}_TOKEN_{counter}>"

        # 3. Store mappings atomically with TTL
        pipe = client.pipeline()
        pipe.hset(values_key, original_value, token)
        pipe.hset(tokens_key, token, original_value)
        pipe.expire(tokens_key, self.ttl_seconds)
        pipe.expire(values_key, self.ttl_seconds)
        pipe.expire(counters_key, self.ttl_seconds)
        await pipe.execute()

        return token

    async def get_tokens_for_session(self, session_id: str) -> Dict[str, str]:
        client = self._get_client()
        tokens_key = self._tokens_key(session_id)
        tokens = await client.hgetall(tokens_key)
        if tokens:
            await client.expire(tokens_key, self.ttl_seconds)
        return tokens or {}

    async def clear_session(self, session_id: str) -> None:
        client = self._get_client()
        tokens_key = self._tokens_key(session_id)
        values_key = self._values_key(session_id)
        counters_key = self._counters_key(session_id)
        await client.delete(tokens_key, values_key, counters_key)

    async def ping(self) -> bool:
        try:
            client = self._get_client()
            return bool(await client.ping())
        except Exception:
            return False

    async def check_and_consume_quota(
        self,
        project_id: str,
        estimated_tokens: int,
        max_daily_requests: Optional[int] = None,
        max_daily_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        client = self._get_client()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        quota_key = self._quota_key(project_id, today)

        # Inspect current usage
        current_data = await client.hgetall(quota_key)
        current_reqs = int(current_data.get("requests", 0))
        current_tokens = int(current_data.get("tokens", 0))

        if max_daily_requests is not None and current_reqs + 1 > max_daily_requests:
            raise QuotaExceededError(
                f"Daily request quota exceeded for project '{project_id}': "
                f"limit={max_daily_requests}, used={current_reqs}"
            )

        if (
            max_daily_tokens is not None
            and current_tokens + estimated_tokens > max_daily_tokens
        ):
            raise QuotaExceededError(
                f"Daily token quota exceeded for project '{project_id}': "
                f"limit={max_daily_tokens}, used={current_tokens}, requested={estimated_tokens}"
            )

        # Increment counters and set 24h TTL (86400s)
        pipe = client.pipeline()
        pipe.hincrby(quota_key, "requests", 1)
        pipe.hincrby(quota_key, "tokens", estimated_tokens)
        pipe.expire(quota_key, 86400)
        await pipe.execute()

        return {
            "project_id": project_id,
            "requests": current_reqs + 1,
            "tokens": current_tokens + estimated_tokens,
            "date": today,
        }
