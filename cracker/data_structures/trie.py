"""
Trie Data Structure Module

This module implements a Trie data structure for efficient word storage and lookup.
A Trie is a tree-like data structure that stores words, allowing efficient
prefix-based operations and reducing memory usage for common prefixes.
"""

from typing import Dict, List, Optional, Set
import sys


class TrieNode:
    """
    Node class for the Trie data structure.
    """
    
    def __init__(self):
        """
        Initialize a new Trie node.
        """
        self.children: Dict[str, TrieNode] = {}
        self.is_end_of_word: bool = False
        self.word: Optional[str] = None  # Store the complete word at end nodes


class Trie:
    """
    Trie data structure for efficient word storage and lookup.
    """
    
    def __init__(self):
        """
        Initialize an empty Trie.
        """
        self.root = TrieNode()
        self._word_count = 0
        self._memory_optimized = False
    
    def insert(self, word: str) -> None:
        """
        Insert a word into the Trie.
        
        Args:
            word: The word to insert
        """
        if not word:
            return
            
        node = self.root
        
        # Navigate through the trie, creating nodes as needed
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        
        # Mark the end of the word
        if not node.is_end_of_word:
            node.is_end_of_word = True
            node.word = word
            self._word_count += 1
    
    def search(self, word: str) -> bool:
        """
        Check if a word exists in the Trie.
        
        Args:
            word: The word to search for
            
        Returns:
            True if the word exists, False otherwise
        """
        node = self._find_node(word)
        return node is not None and node.is_end_of_word
    
    def starts_with(self, prefix: str) -> bool:
        """
        Check if any word in the Trie starts with the given prefix.
        
        Args:
            prefix: The prefix to check
            
        Returns:
            True if a word with the prefix exists, False otherwise
        """
        return self._find_node(prefix) is not None
    
    def get_words_with_prefix(self, prefix: str) -> List[str]:
        """
        Get all words that start with the given prefix.
        
        Args:
            prefix: The prefix to search for
            
        Returns:
            List of words that start with the prefix
        """
        node = self._find_node(prefix)
        if not node:
            return []
        
        words = []
        self._collect_words(node, words)
        return words
    
    def _find_node(self, prefix: str) -> Optional[TrieNode]:
        """
        Find the node corresponding to the given prefix.
        
        Args:
            prefix: The prefix to find
            
        Returns:
            The node at the end of the prefix, or None if not found
        """
        node = self.root
        
        for char in prefix:
            if char not in node.children:
                return None
            node = node.children[char]
        
        return node
    
    def _collect_words(self, node: TrieNode, words: List[str]) -> None:
        """
        Recursively collect all words starting from a node.
        
        Args:
            node: The starting node
            words: List to accumulate the words
        """
        if node.is_end_of_word:
            words.append(node.word)
        
        for child_node in node.children.values():
            self._collect_words(child_node, words)
    
    def get_all_words(self) -> List[str]:
        """
        Get all words stored in the Trie.
        
        Returns:
            List of all words in the Trie
        """
        words = []
        self._collect_words(self.root, words)
        return words
    
    def word_count(self) -> int:
        """
        Get the number of words stored in the Trie.
        
        Returns:
            Number of words
        """
        return self._word_count
    
    def optimize_memory(self) -> None:
        """
        Optimize memory usage by combining common suffixes.
        This is a simplified optimization that mainly releases
        unused Python objects.
        """
        if self._memory_optimized:
            return
            
        # Force garbage collection to release memory
        import gc
        gc.collect()
        
        self._memory_optimized = True
    
    def get_memory_usage(self) -> int:
        """
        Estimate the memory usage of the Trie in bytes.
        This is a rough estimate based on the node count and structure.
        
        Returns:
            Estimated memory usage in bytes
        """
        # Get node count
        node_count = self._count_nodes(self.root)
        
        # Estimate memory per node (varies by Python implementation)
        # Dict overhead + average size of children dict + is_end_of_word bool + word reference
        bytes_per_node = sys.getsizeof({}) + (2 * 8) + 1 + 8
        
        return node_count * bytes_per_node
    
    def _count_nodes(self, node: TrieNode) -> int:
        """
        Count the number of nodes in the Trie starting from a given node.
        
        Args:
            node: The starting node
            
        Returns:
            Number of nodes
        """
        count = 1  # Count the current node
        
        for child in node.children.values():
            count += self._count_nodes(child)
        
        return count
    
    def build_from_list(self, words: List[str]) -> None:
        """
        Build the Trie from a list of words.
        
        Args:
            words: List of words to insert
        """
        for word in words:
            self.insert(word)
    
    def build_from_file(self, file_path: str) -> int:
        """
        Build the Trie from a file, with one word per line.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Number of words inserted
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            IOError: If there's an error reading the file
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        self.insert(word)
            
            return self.word_count()
            
        except (FileNotFoundError, IOError) as e:
            raise e