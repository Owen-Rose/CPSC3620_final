"""
Strategy Package Initialization

This module provides factory functions to instantiate appropriate
cracking strategies based on command-line arguments.
"""

import argparse
from typing import Dict, Any, Type

from cracker.hash_manager import HashManager
from cracker.cli import get_attack_config
from cracker.strategies.base import BaseStrategy
from cracker.strategies.dictionary import DictionaryAttack
from cracker.strategies.pattern_based import PatternBasedAttack  # New strategy
from cracker.strategies.brute_force import BruteForceAttack     # New strategy

# Registry of available attack strategies
STRATEGY_REGISTRY: Dict[str, Type[BaseStrategy]] = {
    "dictionary": DictionaryAttack,
    "pattern": PatternBasedAttack,     # Added
    "brute_force": BruteForceAttack,   # Added
}


def get_strategy(args: argparse.Namespace) -> BaseStrategy:
    """
    Create and return the appropriate strategy based on arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Initialized strategy instance
        
    Raises:
        ValueError: If an unsupported attack type is specified
    """
    # Extract configuration from arguments
    config = get_attack_config(args)
    
    # Create hash manager
    hash_manager = HashManager(args.hash, args.hashvalue)
    
    # Check if the requested attack type is supported
    if args.attack not in STRATEGY_REGISTRY:
        raise ValueError(f"Unsupported attack type: {args.attack}")
    
    # Instantiate the appropriate strategy class
    strategy_class = STRATEGY_REGISTRY[args.attack]
    return strategy_class(hash_manager, config)


def list_available_strategies() -> Dict[str, str]:
    """
    Get a list of available attack strategies with descriptions.
    
    Returns:
        Dictionary mapping strategy names to descriptions
    """
    return {
        "dictionary": "Dictionary-based attack using wordlists with a Trie data structure",
        "pattern": "Pattern-based attack using rule transformations and key patterns",
        "brute_force": "Targeted brute force attack using Breadth-First Search",
    }