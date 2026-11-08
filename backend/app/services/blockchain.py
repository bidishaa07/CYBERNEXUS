"""Provider-neutral blockchain boundary for Phase 6.1.

No implementation is enabled by this phase. Adapters for a configured chain
must implement this interface and must never receive private keys from the API.
"""
from abc import ABC, abstractmethod
from typing import Any

class BlockchainProvider(ABC):
    @abstractmethod
    def network_identity(self) -> dict[str, Any]: ...

    @abstractmethod
    def submit_commitment(self, commitment: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Submit a commitment only after explicit future opt-in."""
        raise NotImplementedError

    @abstractmethod
    def transaction_status(self, transaction_hash: str) -> dict[str, Any]: ...

    @abstractmethod
    def verify_receipt(self, transaction_hash: str) -> dict[str, Any]: ...

    @abstractmethod
    def confirmations(self, transaction_hash: str) -> int | None: ...

    @abstractmethod
    def events(self, transaction_hash: str | None = None) -> list[dict[str, Any]]: ...

class UnconfiguredBlockchainProvider(BlockchainProvider):
    """Explicit fail-closed adapter used until a network adapter is approved."""
    def network_identity(self):
        return {"status": "NOT_CONFIGURED"}

    def submit_commitment(self, commitment, metadata=None):
        return {"status": "NOT_SUBMITTED", "reason": "blockchain provider is not configured"}

    def transaction_status(self, transaction_hash):
        return {"status": "NOT_SUBMITTED"}

    def verify_receipt(self, transaction_hash):
        return {"status": "NOT_SUBMITTED"}

    def confirmations(self, transaction_hash):
        return None

    def events(self, transaction_hash=None):
        return []
