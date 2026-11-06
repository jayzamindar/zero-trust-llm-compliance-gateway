import asyncio
import re
import threading
import unicodedata
from typing import Any, Dict, Optional, Union

from app.schemas import GatewayRequest
from app.storage import BaseTokenStorage, InMemoryTokenStorage, QuotaExceededError


class ComplianceEngineCrashError(RuntimeError):
    """Raised when ComplianceEngine experiences or simulates a service crash."""

    pass


class TokenSmugglingError(ValueError):
    """Raised when an incoming prompt attempts to spoof or smuggle compliance tokens."""

    pass


class ComplianceEngine:
    """
    Zero-Trust Compliance Engine for PII detection, ephemeral tokenization,
    and reversible masking scoped per session_id.
    Decoupled via an asynchronous storage abstraction (BaseTokenStorage).
    """

    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    # Supports hyphens, dots, and whitespace delimiters (e.g. 123-45-6789, 123.45.6789, 123 45 6789)
    SSN_PATTERN = re.compile(
        r"\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b"
    )

    ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF]")

    SMUGGLED_TOKEN_PATTERN = re.compile(
        r"(?:<|\[)(?:EMAIL|SSN|PII)_TOKEN_", re.IGNORECASE
    )

    def __init__(self, storage: Optional[BaseTokenStorage] = None) -> None:
        self.storage: BaseTokenStorage = storage or InMemoryTokenStorage()
        self._simulate_crash: bool = False
        self._lock = threading.Lock()
        self._project_budgets: Dict[str, Dict[str, Optional[int]]] = {}

    def set_project_budget(
        self,
        project_id: str,
        max_daily_requests: Optional[int] = None,
        max_daily_tokens: Optional[int] = None,
    ) -> None:
        """Configure request and token quota limits for a given project or tier."""
        self._project_budgets[project_id] = {
            "max_daily_requests": max_daily_requests,
            "max_daily_tokens": max_daily_tokens,
        }

    def get_project_budget(self, project_id: str) -> Dict[str, Optional[int]]:
        """Retrieve configured budget limits for a project."""
        return self._project_budgets.get(project_id, {})

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """
        Fast-path LLM prompt token estimation heuristic: max(1, ceil(char_count / 4)).
        Enforces predictable, sub-millisecond calculation for quota enforcement.
        """
        if not text:
            return 0
        return max(1, (len(text) + 3) // 4)

    def sanitize_inbound_text(self, text: str) -> str:
        """
        Fast-path inbound text sanitization:
        1. Normalize Unicode characters via NFKC (normalizes fullwidth digits & compatibility glyphs).
        2. Strip invisible zero-width characters (\\u200B to \\u200D, \\uFEFF).
        3. Detect and block token smuggling attempts (<EMAIL_TOKEN_..., [SSN_TOKEN_...).
        """
        normalized = unicodedata.normalize("NFKC", text)
        scrubbed = self.ZERO_WIDTH_PATTERN.sub("", normalized)
        if self.SMUGGLED_TOKEN_PATTERN.search(scrubbed):
            raise TokenSmugglingError(
                "Security Violation: Inbound text cannot contain pre-existing compliance token patterns."
            )
        return scrubbed

    # =========================================================================
    # Synchronous Execution Engine (100% Backwards Compatible)
    # =========================================================================

    def mask_text(self, text: str, session_id: str) -> str:
        """
        Detect emails and SSNs via regex and replace them with session-mapped ephemeral tokens.
        Preserves token consistency if the same PII appears multiple times within a session.
        """
        text = self.sanitize_inbound_text(text)
        if isinstance(self.storage, InMemoryTokenStorage):
            def _replace_email(match: re.Match) -> str:
                original = match.group(0)
                return self.storage.get_or_create_token_sync(
                    session_id, original, "EMAIL"
                )

            def _replace_ssn(match: re.Match) -> str:
                original = match.group(0)
                return self.storage.get_or_create_token_sync(
                    session_id, original, "SSN"
                )

            masked_text = self.EMAIL_PATTERN.sub(_replace_email, text)
            masked_text = self.SSN_PATTERN.sub(_replace_ssn, masked_text)
            return masked_text

        # Fallback runner for async storage in sync caller
        return asyncio.run(self.mask_text_async(text, session_id))

    def unmask_text(self, text: str, session_id: str) -> str:
        """
        Reverse ephemeral tokens back into original PII using the mapping for session_id.
        """
        if isinstance(self.storage, InMemoryTokenStorage):
            token_to_value = self.storage.get_tokens_for_session_sync(session_id)
            if not token_to_value:
                return text

            sorted_tokens = sorted(token_to_value.keys(), key=len, reverse=True)
            unmasked = text
            for token in sorted_tokens:
                unmasked = unmasked.replace(token, token_to_value[token])
            return unmasked

        return asyncio.run(self.unmask_text_async(text, session_id))

    def mask_request(self, request: GatewayRequest) -> GatewayRequest:
        """
        Mask PII in a GatewayRequest's prompt while enforcing project quota and data contract.
        """
        estimated_tokens = self.estimate_tokens(request.prompt)
        budget = self.get_project_budget(request.project_id)

        if isinstance(self.storage, InMemoryTokenStorage):
            self.storage.check_and_consume_quota_sync(
                request.project_id,
                estimated_tokens,
                max_daily_requests=budget.get("max_daily_requests"),
                max_daily_tokens=budget.get("max_daily_tokens"),
            )
        else:
            asyncio.run(
                self.storage.check_and_consume_quota(
                    request.project_id,
                    estimated_tokens,
                    max_daily_requests=budget.get("max_daily_requests"),
                    max_daily_tokens=budget.get("max_daily_tokens"),
                )
            )

        masked_prompt = self.mask_text(request.prompt, request.session_id)
        return GatewayRequest(
            prompt=masked_prompt,
            session_id=request.session_id,
            user_id=request.user_id,
            project_id=request.project_id,
        )

    def unmask_request(self, request: GatewayRequest) -> GatewayRequest:
        """Restore PII in a GatewayRequest's prompt for the given session_id."""
        unmasked_prompt = self.unmask_text(request.prompt, request.session_id)
        return GatewayRequest(
            prompt=unmasked_prompt,
            session_id=request.session_id,
            user_id=request.user_id,
            project_id=request.project_id,
        )

    def mask(
        self,
        target: Union[GatewayRequest, str],
        session_id: Optional[str] = None,
    ) -> Union[GatewayRequest, str]:
        """Polymorphic masking method accepting either a GatewayRequest or (text, session_id)."""
        if isinstance(target, GatewayRequest):
            return self.mask_request(target)
        elif isinstance(target, str):
            if not session_id:
                raise ValueError("session_id is required when masking raw string data.")
            return self.mask_text(target, session_id)
        else:
            raise TypeError(f"Unsupported target type for masking: {type(target)!r}")

    def unmask(
        self,
        target: Union[GatewayRequest, str],
        session_id: Optional[str] = None,
    ) -> Union[GatewayRequest, str]:
        """Polymorphic unmasking method accepting either a GatewayRequest or (text, session_id)."""
        if isinstance(target, GatewayRequest):
            return self.unmask_request(target)
        elif isinstance(target, str):
            if not session_id:
                raise ValueError("session_id is required when unmasking raw string data.")
            return self.unmask_text(target, session_id)
        else:
            raise TypeError(f"Unsupported target type for unmasking: {type(target)!r}")

    # =========================================================================
    # Asynchronous Execution Engine (Native Non-Blocking for FastAPI / Redis)
    # =========================================================================

    async def mask_text_async(self, text: str, session_id: str) -> str:
        """Asynchronously mask emails and SSNs using the abstract storage backend."""
        text = self.sanitize_inbound_text(text)
        email_matches = list(set(self.EMAIL_PATTERN.findall(text)))
        for email in email_matches:
            token = await self.storage.get_or_create_token(
                session_id, email, "EMAIL"
            )
            text = text.replace(email, token)

        ssn_matches = list(set(self.SSN_PATTERN.findall(text)))
        for ssn in ssn_matches:
            token = await self.storage.get_or_create_token(
                session_id, ssn, "SSN"
            )
            text = text.replace(ssn, token)

        return text

    async def unmask_text_async(self, text: str, session_id: str) -> str:
        """Asynchronously reverse ephemeral tokens using the abstract storage backend."""
        token_to_value = await self.storage.get_tokens_for_session(session_id)
        if not token_to_value:
            return text

        sorted_tokens = sorted(token_to_value.keys(), key=len, reverse=True)
        unmasked = text
        for token in sorted_tokens:
            unmasked = unmasked.replace(token, token_to_value[token])
        return unmasked

    async def mask_request_async(self, request: GatewayRequest) -> GatewayRequest:
        """Asynchronously mask a GatewayRequest with token quota enforcement."""
        estimated_tokens = self.estimate_tokens(request.prompt)
        budget = self.get_project_budget(request.project_id)

        await self.storage.check_and_consume_quota(
            request.project_id,
            estimated_tokens,
            max_daily_requests=budget.get("max_daily_requests"),
            max_daily_tokens=budget.get("max_daily_tokens"),
        )

        masked_prompt = await self.mask_text_async(
            request.prompt, request.session_id
        )
        return GatewayRequest(
            prompt=masked_prompt,
            session_id=request.session_id,
            user_id=request.user_id,
            project_id=request.project_id,
        )

    async def unmask_request_async(self, request: GatewayRequest) -> GatewayRequest:
        """Asynchronously unmask a GatewayRequest."""
        unmasked_prompt = await self.unmask_text_async(
            request.prompt, request.session_id
        )
        return GatewayRequest(
            prompt=unmasked_prompt,
            session_id=request.session_id,
            user_id=request.user_id,
            project_id=request.project_id,
        )

    async def mask_async(
        self,
        target: Union[GatewayRequest, str],
        session_id: Optional[str] = None,
    ) -> Union[GatewayRequest, str]:
        """Asynchronous polymorphic masking method."""
        if isinstance(target, GatewayRequest):
            return await self.mask_request_async(target)
        elif isinstance(target, str):
            if not session_id:
                raise ValueError("session_id is required when masking raw string data.")
            return await self.mask_text_async(target, session_id)
        else:
            raise TypeError(f"Unsupported target type for masking: {type(target)!r}")

    async def unmask_async(
        self,
        target: Union[GatewayRequest, str],
        session_id: Optional[str] = None,
    ) -> Union[GatewayRequest, str]:
        """Asynchronous polymorphic unmasking method."""
        if isinstance(target, GatewayRequest):
            return await self.unmask_request_async(target)
        elif isinstance(target, str):
            if not session_id:
                raise ValueError("session_id is required when unmasking raw string data.")
            return await self.unmask_text_async(target, session_id)
        else:
            raise TypeError(f"Unsupported target type for unmasking: {type(target)!r}")

    # =========================================================================
    # Health Check, Crash Simulation, & Session Management
    # =========================================================================

    def simulate_crash(self, crashed: bool = True) -> None:
        """Set or reset the simulated crash state of the engine."""
        self._simulate_crash = crashed

    def health_check(
        self,
        simulate_crash: bool = False,
        raise_on_crash: bool = True,
    ) -> Dict[str, Any]:
        """Health-check method capable of simulating service crashes."""
        if simulate_crash or self._simulate_crash:
            if raise_on_crash:
                raise ComplianceEngineCrashError(
                    "Simulated service crash: ComplianceEngine is unresponsive."
                )
            return {
                "status": "unhealthy",
                "service": "ComplianceEngine",
                "error": "Simulated service crash",
            }

        return {
            "status": "healthy",
            "service": "ComplianceEngine",
            "backend": type(self.storage).__name__,
        }

    async def health_check_async(
        self,
        simulate_crash: bool = False,
        raise_on_crash: bool = True,
    ) -> Dict[str, Any]:
        """Asynchronous health-check also verifying storage backend connectivity."""
        status = self.health_check(
            simulate_crash=simulate_crash, raise_on_crash=raise_on_crash
        )
        if not await self.storage.ping():
            if raise_on_crash:
                raise ComplianceEngineCrashError(
                    f"Storage backend {type(self.storage).__name__} is unreachable."
                )
            return {
                "status": "unhealthy",
                "service": "ComplianceEngine",
                "error": "Storage backend unreachable",
            }
        return status

    def clear_session(self, session_id: str) -> None:
        """Clear the ephemeral token vault for a given session."""
        if isinstance(self.storage, InMemoryTokenStorage):
            self.storage.clear_session_sync(session_id)
        else:
            asyncio.run(self.storage.clear_session(session_id))

    def get_session_tokens(self, session_id: str) -> Dict[str, str]:
        """Return a copy of the token-to-value map for a session."""
        if isinstance(self.storage, InMemoryTokenStorage):
            return self.storage.get_tokens_for_session_sync(session_id)
        return asyncio.run(self.storage.get_tokens_for_session(session_id))
