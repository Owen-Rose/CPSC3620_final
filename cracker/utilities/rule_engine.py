"""
Advanced Rule Engine for Password Transformations

This module implements a powerful rule-based system for password transformations,
inspired by professional password cracking tools like Hashcat and John the Ripper.
"""

from typing import List, Dict, Callable, Any, Set, Union, Optional, Tuple
import re
import string
import itertools


class Rule:
    """
    Represents a password transformation rule with metadata.
    """
    def __init__(self, name: str, function: Callable, priority: int = 1, 
                 description: str = "", weight: float = 1.0):
        """
        Initialize a transformation rule.
        
        Args:
            name: Rule identifier
            function: Function that transforms a password or generates variants
            priority: Processing priority (higher = earlier)
            description: Human-readable description
            weight: Statistical likelihood weight
        """
        self.name = name
        self.function = function
        self.priority = priority
        self.description = description
        self.weight = weight


class RuleEngine:
    """
    Advanced rule engine inspired by professional password crackers.
    
    This engine manages and applies password transformation rules based on
    real-world password patterns and statistics.
    """
    
    def __init__(self):
        """Initialize the rule engine with default rules."""
        self.rules: Dict[str, Rule] = {}
        self._register_default_rules()
    
    def _register_default_rules(self) -> None:
        """Register the default set of transformation rules."""
        # Basic case transformations (high priority)
        self.add_rule("lowercase", lambda w: w.lower(), 
                    priority=100, description="Convert to lowercase")
        self.add_rule("uppercase", lambda w: w.upper(), 
                    priority=90, description="Convert to uppercase")
        self.add_rule("capitalize", lambda w: w.capitalize(), 
                    priority=95, description="Capitalize first letter")
        self.add_rule("title", lambda w: w.title(), 
                    priority=80, description="Title Case")
        
        # Basic substitutions (leet speak)
        self.add_rule("leet_basic", lambda w: self._apply_leet(w, {
                        'a': '4', 'e': '3', 'i': '1', 'o': '0'}), 
                    priority=70, description="Basic leet speak (a→4, e→3, i→1, o→0)")
        
        self.add_rule("leet_advanced", lambda w: self._apply_leet(w, {
                        'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 
                        't': '7', 'l': '1', 'b': '8', 'g': '9', 'z': '2'}), 
                    priority=65, description="Advanced leet speak")
        
        # Number suffix rules
        self.add_rule("common_numbers", lambda w: [w + str(n) for n in range(10)], 
                    priority=75, description="Add single digit (0-9)")
        
        self.add_rule("common_years", lambda w: [w + str(year) for year in range(2020, 2025)], 
                    priority=72, description="Add recent years (2020-2024)")
        
        self.add_rule("pattern_123", lambda w: [w + "123", w + "1234", w + "12345"], 
                    priority=85, description="Add common number patterns (123, 1234, 12345)")
        
        # Special character rules
        self.add_rule("common_special", lambda w: [w + c for c in "!@#$%&*?"], 
                    priority=60, description="Add common special characters")
        
        # Combination rules
        self.add_rule("capital_number", lambda w: [w.capitalize() + str(n) for n in range(1, 10)], 
                    priority=68, description="Capitalize + single digit")
        
        self.add_rule("capital_123", lambda w: [w.capitalize() + "123"], 
                    priority=78, description="Capitalize + 123")
        
        self.add_rule("capital_year", lambda w: [w.capitalize() + str(year) for year in range(2020, 2025)], 
                    priority=67, description="Capitalize + year")
        
        # Special combinations
        self.add_rule("capital_leet", lambda w: self._apply_leet(w.capitalize(), 
                                                              {'a': '4', 'e': '3', 'i': '1', 'o': '0'}), 
                    priority=62, description="Capitalize + leet speak")
        
        self.add_rule("common_patterns", 
                    lambda w: [w + "123!", w + "!", w + "!!", w + "123#", w + "#"], 
                    priority=64, description="Common number+symbol patterns")
        
        # Prefix rules (less common than suffixes)
        self.add_rule("common_prefixes", 
                    lambda w: [prefix + w for prefix in ["my", "the", "a", "i", "1", "2", "123"]], 
                    priority=50, description="Add common prefixes")
    
    def add_rule(self, name: str, function: Callable, priority: int = 1, 
                description: str = "", weight: float = 1.0) -> None:
        """
        Add a new transformation rule.
        
        Args:
            name: Rule identifier
            function: Function that transforms a password or generates variants
            priority: Processing priority (higher = earlier)
            description: Human-readable description
            weight: Statistical likelihood weight
        """
        self.rules[name] = Rule(name, function, priority, description, weight)
    
    def apply_rule(self, word: str, rule_name: str) -> Union[str, List[str]]:
        """
        Apply a single rule to a word.
        
        Args:
            word: Word to transform
            rule_name: Name of the rule to apply
            
        Returns:
            Transformed word or list of variants
            
        Raises:
            KeyError: If rule_name doesn't exist
        """
        if not word:
            return word
            
        if rule_name not in self.rules:
            raise KeyError(f"Rule '{rule_name}' not found")
            
        return self.rules[rule_name].function(word)
    
    def apply_rules(self, word: str, rule_names: List[str] = None) -> List[str]:
        """
        Apply multiple rules to a word.
        
        Args:
            word: Word to transform
            rule_names: List of rule names to apply (if None, apply all rules)
            
        Returns:
            List of transformed variants
        """
        if not word:
            return []
            
        results = [word]  # Start with the original word
        
        # Determine which rules to apply
        if rule_names is None:
            # Apply all rules by priority
            rules_to_apply = sorted(
                self.rules.values(), 
                key=lambda r: -r.priority
            )
        else:
            # Apply only the specified rules
            rules_to_apply = [
                self.rules[name] for name in rule_names 
                if name in self.rules
            ]
            
        # Apply each rule
        for rule in rules_to_apply:
            new_results = []
            
            for result in results:
                rule_result = rule.function(result)
                
                # Handle both single string results and lists
                if isinstance(rule_result, str):
                    new_results.append(rule_result)
                elif isinstance(rule_result, list):
                    new_results.extend(rule_result)
            
            # Add new results to our collection
            results.extend(new_results)
            
            # Remove duplicates while preserving order
            seen = set()
            results = [x for x in results if not (x in seen or seen.add(x))]
        
        # Remove the original word if it's in the results
        if word in results:
            results.remove(word)
            results.insert(0, word)  # Put it at the beginning
            
        return results
    
    def apply_staged_rules(self, word: str, max_variants: int = 50) -> List[str]:
        """
        Apply rules in stages of increasing complexity until max_variants is reached.
        
        Args:
            word: Word to transform
            max_variants: Maximum number of variants to generate
            
        Returns:
            List of transformed variants, prioritized by likelihood
        """
        if not word or len(word) < 3:
            return [word] if word else []
            
        # Define rule stages from simple to complex
        stages = [
            # Stage 1: Basic transformations (high priority)
            ["lowercase", "capitalize", "uppercase", "pattern_123", "capital_123"],
            
            # Stage 2: Common additions
            ["common_numbers", "common_years", "common_special"],
            
            # Stage 3: Leet speak variations
            ["leet_basic", "capital_leet"],
            
            # Stage 4: Combinations
            ["common_patterns", "capital_number", "capital_year"],
            
            # Stage 5: Advanced and less common (low priority)
            ["leet_advanced", "common_prefixes"]
        ]
        
        # Start with the original word
        results = {word}
        
        # Apply each stage until we reach max_variants
        for stage in stages:
            if len(results) >= max_variants:
                break
                
            # Apply rules for this stage
            new_variants = set()
            
            for existing in results:
                for rule_name in stage:
                    rule_results = self.apply_rule(existing, rule_name)
                    
                    if isinstance(rule_results, str):
                        new_variants.add(rule_results)
                    elif isinstance(rule_results, list):
                        new_variants.update(rule_results)
                        
                    # Check if we've reached the limit
                    if len(results) + len(new_variants) >= max_variants:
                        break
                
                if len(results) + len(new_variants) >= max_variants:
                    break
            
            # Add new variants to our results
            results.update(new_variants)
            
            # Ensure we don't exceed max_variants
            if len(results) > max_variants:
                # Convert to list and trim
                results_list = list(results)
                results = set(results_list[:max_variants])
        
        # Convert to list and ensure original word is first
        results_list = list(results)
        if word in results_list:
            results_list.remove(word)
            results_list.insert(0, word)
            
        return results_list
    
    def _apply_leet(self, word: str, substitutions: Dict[str, str]) -> List[str]:
        """
        Apply leet speak substitutions to a word.
        
        Args:
            word: Word to transform
            substitutions: Dictionary of character substitutions
            
        Returns:
            List of transformed variants
        """
        if not word:
            return []
            
        word_lower = word.lower()
        results = []
        
        # Check which substitutions are applicable
        applicable_subs = {
            c: r for c, r in substitutions.items() 
            if c in word_lower
        }
        
        if not applicable_subs:
            return []
            
        # For a single substitution, replace all occurrences
        for char, replacement in applicable_subs.items():
            results.append(word.replace(char, replacement))
        
        # For words with multiple possible substitutions, create combinations
        # but limit to avoid combinatorial explosion
        if len(applicable_subs) > 1 and len(word) <= 12:
            # Try all combinations of two substitutions
            for (c1, r1), (c2, r2) in itertools.combinations(applicable_subs.items(), 2):
                results.append(word.replace(c1, r1).replace(c2, r2))
                
            # For very common patterns, try three substitutions
            if len(word) <= 8 and len(applicable_subs) >= 3:
                common_triple = {'a': '4', 'e': '3', 'i': '1'}
                if all(c in applicable_subs for c in common_triple):
                    transformed = word
                    for c, r in common_triple.items():
                        transformed = transformed.replace(c, r)
                    results.append(transformed)
        
        return results


class KeyboardPatternGenerator:
    """
    Generator for keyboard pattern-based password variations.
    """
    
    # Adjacent keys on a standard QWERTY keyboard
    ADJACENT_KEYS = {
        'q': ['w', '1', '2'], 'w': ['q', 'e', '2', '3'], 'e': ['w', 'r', '3', '4'],
        'r': ['e', 't', '4', '5'], 't': ['r', 'y', '5', '6'], 'y': ['t', 'u', '6', '7'],
        'u': ['y', 'i', '7', '8'], 'i': ['u', 'o', '8', '9'], 'o': ['i', 'p', '9', '0'],
        'p': ['o', '[', '0', '-'], 'a': ['q', 'w', 's', 'z'], 's': ['a', 'd', 'w', 'e', 'x'],
        'd': ['s', 'f', 'e', 'r', 'c'], 'f': ['d', 'g', 'r', 't', 'v'], 
        'g': ['f', 'h', 't', 'y', 'b'], 'h': ['g', 'j', 'y', 'u', 'n'], 
        'j': ['h', 'k', 'u', 'i', 'm'], 'k': ['j', 'l', 'i', 'o', ','], 
        'l': ['k', ';', 'o', 'p', '.'], 'z': ['a', 's', 'x'], 'x': ['z', 'c', 's', 'd'],
        'c': ['x', 'v', 'd', 'f'], 'v': ['c', 'b', 'f', 'g'], 'b': ['v', 'n', 'g', 'h'],
        'n': ['b', 'm', 'h', 'j'], 'm': ['n', ',', 'j', 'k'], ',': ['m', '.', 'k', 'l'],
        '.': [',', '/', 'l', ';'], '/': ['.', ';', '\''], '1': ['q', '2'], '2': ['1', 'q', 'w', '3'],
        '3': ['2', 'w', 'e', '4'], '4': ['3', 'e', 'r', '5'], '5': ['4', 'r', 't', '6'],
        '6': ['5', 't', 'y', '7'], '7': ['6', 'y', 'u', '8'], '8': ['7', 'u', 'i', '9'],
        '9': ['8', 'i', 'o', '0'], '0': ['9', 'o', 'p', '-'], '-': ['0', 'p', '[', '='],
        '=': ['-', '[', ']'], '[': ['p', '=', ']'], ']': ['[', '=', '\\'], '\\': [']'],
        ';': ['l', '\'', '.', '/'], '\'': [';', '/']
    }
    
    # Common keyboard patterns
    COMMON_PATTERNS = [
        "qwerty", "12345", "asdfg", "zxcvb", "poiuy", "mnbvc", "lkjhg", "098765", "4321"
    ]
    
    @classmethod
    def generate_variants(cls, word: str, max_variants: int = 10) -> List[str]:
        """
        Generate keyboard-based variations of a word.
        
        Args:
            word: Original word
            max_variants: Maximum number of variants to generate
            
        Returns:
            List of variations
        """
        if not word:
            return []
            
        results = []
        
        # Check for keyboard patterns in the word
        has_pattern = any(pattern in word.lower() for pattern in cls.COMMON_PATTERNS)
        
        # Only generate variants for words that might be keyboard patterns
        if has_pattern or len(word) <= 8:
            # Adjacent key substitutions (limited to avoid explosion)
            if len(word) <= 8:
                for i in range(len(word)):
                    char = word[i].lower()
                    if char in cls.ADJACENT_KEYS:
                        for adj in cls.ADJACENT_KEYS[char]:
                            variant = word[:i] + adj + word[i+1:]
                            results.append(variant)
                            
                            # Also try uppercase variant if original was uppercase
                            if word[i].isupper():
                                results.append(word[:i] + adj.upper() + word[i+1:])
                            
                            if len(results) >= max_variants:
                                return results
            
            # Look for shifted patterns on keyboard
            if len(word) <= 6:
                # Try shifted row (e.g., "qwerty" -> "asdfgh")
                if any(c in "qwertyuiop" for c in word.lower()):
                    shifted = word.lower()
                    for c in "qwertyuiop":
                        if c in shifted:
                            row_pos = "qwertyuiop".index(c)
                            if row_pos < len("asdfghjkl"):
                                shifted = shifted.replace(c, "asdfghjkl"[row_pos])
                    results.append(shifted)
                    
                # Try shifted from second row to third
                if any(c in "asdfghjkl" for c in word.lower()):
                    shifted = word.lower()
                    for c in "asdfghjkl":
                        if c in shifted:
                            row_pos = "asdfghjkl".index(c)
                            if row_pos < len("zxcvbnm"):
                                shifted = shifted.replace(c, "zxcvbnm"[row_pos])
                    results.append(shifted)
        
        # Remove duplicates and limit to max_variants
        unique_results = []
        seen = set()
        for variant in results:
            if variant not in seen and variant != word:
                unique_results.append(variant)
                seen.add(variant)
                if len(unique_results) >= max_variants:
                    break
        
        return unique_results
    
    @classmethod
    def is_keyboard_pattern(cls, word: str) -> bool:
        """
        Determine if a word is likely a keyboard pattern.
        
        Args:
            word: Word to check
            
        Returns:
            True if the word matches keyboard pattern criteria
        """
        word = word.lower()
        
        # Check for common patterns
        if any(pattern in word for pattern in cls.COMMON_PATTERNS):
            return True
            
        # Check for sequential adjacent keys
        adjacent_count = 0
        for i in range(1, len(word)):
            if word[i] in cls.ADJACENT_KEYS.get(word[i-1], []):
                adjacent_count += 1
                
        # If more than 60% of characters are adjacent, likely a pattern
        return adjacent_count >= (len(word) - 1) * 0.6


class MultiWordGenerator:
    """
    Generator for multi-word and phrase-based password variations.
    """
    
    # Common phrases used in passwords
    COMMON_PHRASES = [
        "iloveyou", "letmein", "welcome", "trustno1", "monkey", "dragon", 
        "baseball", "football", "qwerty", "superman", "princess", "master"
    ]
    
    # Common connectors between words
    CONNECTORS = ["", "123", ".", "_", "-", "!", "1", "2", "0"]
    
    @classmethod
    def generate_compounds(cls, word: str, common_words: List[str], 
                          max_variants: int = 20) -> List[str]:
        """
        Generate compound words using the input word and common words.
        
        Args:
            word: Base word
            common_words: List of common words to combine with
            max_variants: Maximum number of variants to generate
            
        Returns:
            List of compound word variants
        """
        if not word or len(word) < 3:
            return []
            
        results = []
        
        # Limit to reasonable length words
        if len(word) <= 8:
            # Combine with common words (word first)
            for second_word in common_words[:20]:  # Limit to first 20 common words
                for connector in cls.CONNECTORS[:5]:  # Limit to first 5 connectors
                    if len(word + connector + second_word) <= 16:
                        results.append(word + connector + second_word)
                        
                        # For the most common connector (empty string), try capitalization
                        if connector == "":
                            results.append(word + second_word.capitalize())
                    
                    if len(results) >= max_variants:
                        return results
            
            # Also try word second (for words like "iloveyou")
            for first_word in common_words[:10]:  # More limited for word-second
                for connector in cls.CONNECTORS[:3]:  # More limited connectors
                    if len(first_word + connector + word) <= 16:
                        results.append(first_word + connector + word)
                    
                    if len(results) >= max_variants:
                        return results
        
        return results
    
    @classmethod
    def detect_patterns(cls, word: str) -> bool:
        """
        Detect if a word contains common phrase patterns.
        
        Args:
            word: Word to analyze
            
        Returns:
            True if the word matches phrase patterns
        """
        word_lower = word.lower()
        
        # Check for embedded phrases
        return any(phrase in word_lower for phrase in cls.COMMON_PHRASES)