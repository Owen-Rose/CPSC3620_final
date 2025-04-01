"""
File Handler Module

This module provides utilities for file operations used in the password cracking tool.
"""

import os
from typing import List, Optional


def ensure_directory_exists(directory_path: str) -> None:
    """
    Ensure that a directory exists, creating it if necessary.
    
    Args:
        directory_path: Path to the directory
    """
    os.makedirs(directory_path, exist_ok=True)


def save_to_file(content: str, file_path: str) -> None:
    """
    Save content to a file, creating directories if needed.
    
    Args:
        content: Content to save
        file_path: Path to the file
    """
    # Ensure the directory exists
    directory = os.path.dirname(file_path)
    if directory:
        ensure_directory_exists(directory)
    
    # Write the content to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)


def append_to_file(content: str, file_path: str) -> None:
    """
    Append content to a file, creating it if it doesn't exist.
    
    Args:
        content: Content to append
        file_path: Path to the file
    """
    # Ensure the directory exists
    directory = os.path.dirname(file_path)
    if directory:
        ensure_directory_exists(directory)
    
    # Append the content to the file
    with open(file_path, 'a', encoding='utf-8') as file:
        file.write(content)


def read_lines_from_file(file_path: str) -> List[str]:
    """
    Read lines from a file, stripping whitespace.
    
    Args:
        file_path: Path to the file
        
    Returns:
        List of lines from the file
        
    Raises:
        FileNotFoundError: If the file doesn't exist
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        return [line.strip() for line in file]


def file_exists(file_path: str) -> bool:
    """
    Check if a file exists.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if the file exists, False otherwise
    """
    return os.path.isfile(file_path)