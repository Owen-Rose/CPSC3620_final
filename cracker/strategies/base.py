"""
Base Strategy Module

This module defines the abstract base class for all password cracking strategies.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any

from cracker.hash_manager import HashManager


@dataclass
class CrackingResult:
    """
    Data class to store the result of a password cracking attempt.
    """
    success: bool  # Whether the password was found
    password: str = ""  # The cracked password (if found)
    attempts: int = 0  # Number of attempts made
    details: Dict[str, Any] = None  # Additional details about the cracking process
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class BaseStrategy(ABC):
    """
    Abstract base class for all password cracking strategies.
    
    This class defines the common interface that all cracking strategies
    must implement, and provides shared functionality.
    """
    
    def __init__(self, hash_manager: HashManager, config: Dict[str, Any]):
        """
        Initialize the base strategy.
        
        Args:
            hash_manager: The hash manager to use for verification
            config: Configuration parameters for the strategy
        """
        self.hash_manager = hash_manager
        self.config = config
        self.verbose = config.get('verbose', False)
        
    @abstractmethod
    def execute(self) -> CrackingResult:
        """
        Execute the password cracking strategy.
        
        Returns:
            CrackingResult containing the outcome of the cracking attempt
        """
        pass
    
    def _log(self, message: str) -> None:
        """
        Log a message if verbose mode is enabled.
        
        Args:
            message: The message to log
        """
        if self.verbose:
            print(message)