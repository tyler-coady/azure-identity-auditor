from __future__ import annotations

from abc import ABC, abstractmethod

from azure.core.credentials import TokenCredential

from ..models import ScanResult


class BaseScanner(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    def scan(self) -> ScanResult:
        ...


class LiveScanner(BaseScanner, ABC):
    """Scanner that requires an authenticated Azure credential and subscription."""

    def __init__(self, credential: TokenCredential, subscription_id: str) -> None:
        self.credential = credential
        self.subscription_id = subscription_id
