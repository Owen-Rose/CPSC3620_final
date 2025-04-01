"""
Enhanced Password Transformation System

This module provides sophisticated password transformation capabilities based on
real-world password patterns, statistical analysis of breached passwords,
and advanced rule-based transformations.
"""

from typing import List, Set, Dict, Callable, Tuple, Optional
from dataclasses import dataclass
import re
import string
import os
import json
import itertools
import random

from cracker.utilities.rule_engine import (
    RuleEngine, 
    KeyboardPatternGenerator, 
    MultiWordGenerator
)


class PasswordTransformer:
    """
    Advanced utility class for password transformations with prioritization
    and statistical weighting based on real-world patterns.
    """
    
    # Initialize rule engine
    _rule_engine = RuleEngine()
    
    # Common password components by frequency
    COMMON_WORDS = [
        "password", "admin", "welcome", "login", "user", "test", "love", 
        "hello", "monkey", "dragon", "master", "shadow", "football", "baseball",
        "qwerty", "abc", "computer", "sunshine", "flower", "secret", "summer",
        "winter", "spring", "autumn", "superman", "batman", "princess", "letmein",
        "office", "work", "home", "angel", "house", "forever", "happy", "friend",
        "soccer", "tiger", "cookie", "chocolate", "coffee", "player", "hunter",
        "killer", "manager", "system", "service", "server", "nintendo", "pokemon",
        "money", "jesus", "school", "college", "student", "maggie", "bailey", 
        "jordan", "michael", "thomas", "michelle", "daniel", "anthony"
    ]
    
    # Top numerial suffixes from breached passwords
    COMMON_SUFFIXES = [
        # Numbers (by frequency)
        '123', '1', '12', '2', '0', '3', '4', '5', '7', '11', '6', '8', '9', 
        '13', '01', '99', '10', '88', '21', '69', '00', '01', '02', '03', 
        # Years (by frequency)
        '2023', '2022', '2021', '2020', '2024', '2019', '2018', '2017', '2016', 
        # Common patterns
        '123!', '!', '1!', '!!', '123#', '#', '$', '1234', '12345'
    ]
    
    @classmethod
    def smart_transform(cls, word: str, max_variants: int = 20) -> List[str]:
        """
        Apply smart transformations to a word based on statistical patterns.
        
        Args:
            word: Word to transform
            max_variants: Maximum number of variants to generate
            
        Returns:
            List of transformed variants in order of likelihood
        """
        if not word or len(word) < 3:
            return [word] if word else []
        
        # Apply staged rules from rule engine
        variants = cls._rule_engine.apply_staged_rules(word, max_variants)
        
        # Ensure we don't exceed max_variants
        return variants[:max_variants]
    
    @classmethod
    def advanced_transform(cls, word: str, common_words: List[str] = None, 
                          max_variants: int = 50) -> List[str]:
        """
        Generate advanced password variants using multiple techniques.
        
        Args:
            word: Base word
            common_words: List of common words (or None to use default)
            max_variants: Maximum number of variants
            
        Returns:
            List of password variants ordered by likelihood
        """
        if not word or len(word) < 3:
            return [word] if word else []
            
        # Start with rule-based transformations
        results = set(cls._rule_engine.apply_staged_rules(word, max_variants // 2))
        
        # Make sure we include the original word
        results.add(word)
        
        # Set aside some spots for advanced techniques
        remaining_slots = max_variants - len(results)
        
        if remaining_slots > 0:
            # Add keyboard pattern variants
            keyboard_variants = KeyboardPatternGenerator.generate_variants(
                word, max_variants=remaining_slots // 3
            )
            results.update(keyboard_variants)
            
            # Check if we have room for multi-word variants
            remaining_slots = max_variants - len(results)
            
            if remaining_slots > 0:
                # Use common words if not provided
                words_to_use = common_words or cls.COMMON_WORDS
                
                # Add multi-word compound variants
                compound_variants = MultiWordGenerator.generate_compounds(
                    word, words_to_use, max_variants=remaining_slots
                )
                results.update(compound_variants)
        
        # Convert to list while prioritizing the original word
        result_list = list(results)
        if word in result_list:
            result_list.remove(word)
            result_list.insert(0, word)
        
        # Ensure we don't exceed max_variants
        return result_list[:max_variants]
    
    @classmethod
    def get_common_passwords(cls, limit: int = 100) -> List[str]:
        """
        Return a list of the most common passwords based on frequency analysis.
        
        Args:
            limit: Maximum number of common passwords to return
            
        Returns:
            List of common passwords
        """
        # These are sourced from actual data breaches and ordered by frequency
        common_passwords = [
            "123456", "password", "123456789", "12345678", "12345", "qwerty", 
            "1234567", "111111", "1234567890", "123123", "abc123", "1234", 
            "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", 
            "zaq12wsx", "dragon", "sunshine", "princess", "letmein", "654321",
            "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop", "superman",
            "asdfghjkl", "trustno1", "jordan23", "welcome", "football", "admin",
            "test", "11111111", "222222", "admin123", "password123", "baseball",
            "master", "login", "passw0rd", "hello", "whatever", "555555", "666666",
            "lovely", "michael", "football123", "jennifer", "charlie", "developer",
            "123qwe", "qwerty1", "liverpool", "123abc", "thomas", "chelsea", "batman",
            "andrew", "harley", "jessica", "pepper", "ranger", "joshua", "666666",
            "amanda", "robert", "steven", "patricia", "sean", "azerty", "ashley",
            "secret", "iloveu", "matthew", "thunder", "donald", "cookie", "chocolate",
            "summer", "william", "taylor", "bailey", "playboy", "shadow", "richard",
            "ferrari", "anhyeuem", "killer", "purple", "angel", "hannah", "mario", 
            "justin", "hockey", "dallas", "fender", "guitar", "scooter", "coffee", 
            "jordan", "apple", "orange", "banana", "manager", "peanut", "pepper", 
            "please", "helper", "silver", "golden", "maggie", "access", "flower", 
            "rocket", "saturn", "marina", "system", "google", "compaq", "jasmine", 
            "winter", "spirit", "junior", "stella", "driver", "rocket", "victor", 
            "status", "jaguar", "dakota", "xavier", "runner", "basket", "united", 
            "falcon", "turtle", "sierra", "mexico", "canada", "success", "office",
            "wisdom", "window", "flower", "spider", "rocket", "turtle"
        ]
        
        return common_passwords[:limit]
    
    @classmethod
    def generate_variants_for_common_words(cls, common_words: List[str], 
                                          max_per_word: int = 10) -> List[str]:
        """
        Generate variants for a list of common words with high optimization.
        
        Args:
            common_words: List of common words to transform
            max_per_word: Maximum number of variants per word
            
        Returns:
            List of word variants
        """
        variants = []
        
        for word in common_words:
            # Add the original word first
            variants.append(word)
            
            # Generate high-probability variants
            if len(word) >= 3:
                # Apply smart transformations for each word
                word_variants = cls.smart_transform(word, max_variants=max_per_word)
                variants.extend(word_variants)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variants = []
        for variant in variants:
            if variant not in seen:
                seen.add(variant)
                unique_variants.append(variant)
        
        return unique_variants
    
    @classmethod
    def prepare_prioritized_wordlist(cls, dictionary_path: str, 
                                    output_path: str = None,
                                    limit: int = 100000) -> List[str]:
        """
        Create a prioritized wordlist from a dictionary file.
        
        Args:
            dictionary_path: Path to source dictionary file
            output_path: Optional path to save prioritized list
            limit: Maximum words to include
            
        Returns:
            List of prioritized words
        """
        # First get common passwords
        prioritized = cls.get_common_passwords(200)
        
        # Add their variants
        variants = cls.generate_variants_for_common_words(prioritized[:100], 5)
        prioritized.extend([v for v in variants if v not in prioritized])
        
        # Read the dictionary and filter/prioritize
        try:
            words_from_dict = []
            seen = set(prioritized)
            
            with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and word not in seen and 3 <= len(word) <= 12:
                        words_from_dict.append(word)
                        seen.add(word)
                        
                        if len(words_from_dict) >= limit:
                            break
            
            # Combine lists
            prioritized.extend(words_from_dict)
            
            # Write to output file if requested
            if output_path:
                directory = os.path.dirname(output_path)
                if directory and not os.path.exists(directory):
                    os.makedirs(directory)
                    
                with open(output_path, 'w', encoding='utf-8') as f:
                    for word in prioritized:
                        f.write(word + '\n')
            
            return prioritized
            
        except Exception as e:
            print(f"[!] Error creating prioritized wordlist: {e}")
            return prioritized  # Return what we have so far