from abc import ABC, abstractmethod

from bs4 import BeautifulSoup

from src.models import RuleResult


class Rule(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def evaluate(self, html: str, soup: BeautifulSoup) -> RuleResult: ...
