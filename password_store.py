#!/usr/bin/env python3
"""
Password Storage Utility

This script allows users to enter a password, hash it using various algorithms,
and store the hash in a local file for later cracking demonstration.
"""

import argparse
import os
import getpass
import datetime
from typing import Dict, Optional, List

from cracker.hash_manager import HashManager
from utils.file_handler import save_to_file, append_to_file, ensure_directory_exists, read_lines_from_file


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments for the password storage utility.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Password Storage Utility for Cracking Demonstrations",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Hash algorithm selection
    parser.add_argument("--hash", default="md5", choices=HashManager.get_supported_algorithms(),
                        help="Hashing algorithm to use")
    
    # Output options
    parser.add_argument("--output", "-o", default="data/hashes/stored_hashes.txt",
                        help="Path to output file")
    
    # Label for the stored hash
    parser.add_argument("--label", "-l", default=None,
                        help="Label for the stored hash (default: timestamp)")
    
    # Overwrite option
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite existing file instead of appending")
    
    # List stored hashes
    parser.add_argument("--list", action="store_true",
                        help="List stored hashes instead of adding a new one")
    
    # Allow password to be provided on command line (for testing)
    parser.add_argument("--password", "-p", default=None,
                        help="Password to hash (WARNING: visible in command history)")
    
    return parser.parse_args()


def get_password() -> str:
    """
    Prompt the user to enter a password securely.
    
    Returns:
        The entered password
    """
    password = getpass.getpass("Enter password to hash: ")
    confirmation = getpass.getpass("Confirm password: ")
    
    if password != confirmation:
        print("[!] Passwords do not match. Please try again.")
        return get_password()
    
    if not password:
        print("[!] Password cannot be empty. Please try again.")
        return get_password()
    
    return password


def hash_and_store_password(
    password: str, 
    hash_type: str, 
    output_path: str, 
    label: Optional[str] = None,
    overwrite: bool = False
) -> Dict[str, str]:
    """
    Hash a password using the specified algorithm and store it in a file.
    
    Args:
        password: The password to hash
        hash_type: The hash algorithm to use
        output_path: Path to the output file
        label: Label for the stored hash
        overwrite: Whether to overwrite the existing file
        
    Returns:
        Dictionary containing the hash details
    """
    # Create a temporary HashManager instance
    hash_manager = HashManager(hash_type, "")  # Target hash not needed
    
    # Generate the hash
    hash_value = hash_manager.hash_password(password)
    
    # Prepare output directory
    output_dir = os.path.dirname(output_path)
    if output_dir:
        ensure_directory_exists(output_dir)
    
    # Format the hash entry
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry_label = label or f"Password added on {timestamp}"
    
    hash_entry = f"{entry_label}:{hash_type}:{hash_value}\n"
    
    # Store the hash
    if overwrite:
        save_to_file(hash_entry, output_path)
        print(f"[+] Hash stored in {output_path} (overwritten)")
    else:
        append_to_file(hash_entry, output_path)
        print(f"[+] Hash appended to {output_path}")
    
    # Return hash details
    return {
        'hash_type': hash_type,
        'hash_value': hash_value,
        'output_path': output_path,
        'label': entry_label
    }


def list_stored_hashes(file_path: str) -> None:
    """
    List all stored hashes in a file.
    
    Args:
        file_path: Path to the file containing stored hashes
    """
    if not os.path.exists(file_path):
        print(f"[!] Hash file not found: {file_path}")
        return
    
    try:
        lines = read_lines_from_file(file_path)
        
        if not lines:
            print(f"[!] No hashes found in {file_path}")
            return
        
        print(f"\n[*] Stored Hashes in {file_path}:")
        print("=" * 60)
        print(f"{'ID':<4} {'Label':<30} {'Hash Type':<8} {'Hash Value':<32}")
        print("-" * 60)
        
        for i, line in enumerate(lines):
            parts = line.split(":", 2)
            if len(parts) >= 3:
                label, hash_type, hash_value = parts
                print(f"{i+1:<4} {label[:30]:<30} {hash_type:<8} {hash_value[:32]:<32}")
            else:
                print(f"{i+1:<4} {'<Invalid format>':<30}")
        
        print("=" * 60)
        print(f"Total: {len(lines)} hash(es)")
        
    except Exception as e:
        print(f"[!] Error reading hash file: {e}")


def print_banner() -> None:
    """
    Print a banner for the password storage utility.
    """
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║  Password Storage Utility for Demonstrations  ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """
    print(banner)


def main() -> int:
    """
    Main function for the password storage utility.
    
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    # Print banner
    print_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    try:
        # List stored hashes if requested
        if args.list:
            list_stored_hashes(args.output)
            return 0
        
        # Get the password from command line or prompt
        password = args.password or get_password()
        
        # Hash and store the password
        result = hash_and_store_password(
            password,
            args.hash,
            args.output,
            args.label,
            args.overwrite
        )
        
        # Display the command to crack this password
        print("\n[+] To crack this password, use the following command:")
        print(f"python main.py --attack dictionary --hash {result['hash_type']} "
              f"--hashvalue {result['hash_value']} --dictionary <path_to_dictionary>")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())