"""
File Encryption Script
Encrypts a file using another file as key with AES-256 encryption.
Uses AES-256 in CBC mode with PKCS7 padding for secure encryption.
"""

import os
import sys
import argparse
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def derive_key_from_file(key_file_data: bytes) -> bytes:
    """
    Derives a 256-bit AES key from key file data using SHA-256.
    
    Args:
        key_file_data: The raw key file data
        
    Returns:
        32-byte AES key
    """
    if not key_file_data:
        raise ValueError("Key file cannot be empty")
    
    # Use SHA-256 to derive a consistent 32-byte key from any size key file
    return hashlib.sha256(key_file_data).digest()

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypts data using AES-256 in CBC mode.
    
    Args:
        data: The data to be encrypted
        key: 32-byte AES key
    
    Returns:
        IV (16 bytes) + encrypted data
    """
    # Generate random IV
    iv = os.urandom(16)
    
    # Pad data to 16-byte blocks
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return IV + encrypted data
    return iv + encrypted_data

def aes_decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts data using AES-256 in CBC mode.
    
    Args:
        encrypted_data: IV (16 bytes) + encrypted data
        key: 32-byte AES key
    
    Returns:
        The decrypted data
    """
    if len(encrypted_data) < 16:
        raise ValueError("Invalid encrypted data - too short")
    
    # Extract IV and encrypted data
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data)
    data += unpadder.finalize()
    
    return data

def detect_file_type(data: bytes) -> str:
    """
    Detects file type based on magic bytes (file signatures).
    
    Args:
        data: The file data as bytes
        
    Returns:
        The detected file extension
    """
    if not data:
        return ""
    
    # Common file signatures (magic bytes)
    signatures = {
        # Images
        b'\xFF\xD8\xFF': '.jpg',
        b'\x89PNG\r\n\x1a\n': '.png',
        b'GIF87a': '.gif',
        b'GIF89a': '.gif',
        b'RIFF': '.webp',  # WebP files start with RIFF, but we need to check further
        b'BM': '.bmp',
        
        # Documents
        b'%PDF': '.pdf',
        b'PK\x03\x04': '.zip',  # Also used by docx, xlsx, etc.
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': '.doc',
        
        # Audio
        b'ID3': '.mp3',
        b'\xFF\xFB': '.mp3',
        b'\xFF\xF3': '.mp3',
        b'\xFF\xF2': '.mp3',
        b'RIFF': '.wav',  # WAV also uses RIFF
        b'fLaC': '.flac',
        b'OggS': '.ogg',
        
        # Video
        b'\x00\x00\x00\x20ftypmp4': '.mp4',
        b'\x00\x00\x00\x18ftypmp4': '.mp4',
        b'RIFF': '.avi',  # AVI also uses RIFF
        
        # Archives
        b'7z\xBC\xAF\x27\x1C': '.7z',
        b'Rar!\x1a\x07\x00': '.rar',
        b'\x1f\x8b': '.gz',
        
        # Executables
        b'MZ': '.exe',
        b'\x7fELF': '',  # Linux executable (no extension)
        
        # Text-like formats
        b'<!DOCTYPE': '.html',
        b'<html': '.html',
        b'<?xml': '.xml',
        b'{\n': '.json',
        b'[': '.json',
    }
    
    # Check for specific signatures
    for signature, extension in signatures.items():
        if data.startswith(signature):
            # Special handling for RIFF files (WebP, WAV, AVI)
            if signature == b'RIFF' and len(data) >= 12:
                riff_type = data[8:12]
                if riff_type == b'WEBP':
                    return '.webp'
                elif riff_type == b'WAVE':
                    return '.wav'
                elif riff_type == b'AVI ':
                    return '.avi'
            # Special handling for ZIP-based formats
            elif signature == b'PK\x03\x04':
                # Could be ZIP, DOCX, XLSX, etc. - default to ZIP
                return '.zip'
            else:
                return extension
    
    # Check for text files (UTF-8 encoded)
    try:
        decoded_text = data[:1000].decode('utf-8', errors='ignore')
        if decoded_text.isprintable() or '\n' in decoded_text or '\t' in decoded_text:
            # All UTF-8 text files should be .txt regardless of content
            return '.txt'
    except:
        pass
    
    # Default: no extension if type cannot be determined
    return ''

def auto_detect_extension(output_file: str, decrypted_data: bytes) -> str:
    """
    Automatically adds the correct extension to output file based on content.
    
    Args:
        output_file: The original output file path
        decrypted_data: The decrypted file content
        
    Returns:
        The output file path with correct extension
    """
    detected_ext = detect_file_type(decrypted_data)
    
    if detected_ext:
        # Remove existing extension if any
        base_name = os.path.splitext(output_file)[0]
        new_output_file = base_name + detected_ext
        
        print(f"Detected file type: {detected_ext}")
        print(f"Auto-corrected output filename: {new_output_file}")
        
        return new_output_file
    else:
        print("Could not detect file type - using original filename")
        return output_file

def read_file(file_path: str) -> bytes:
    """
    Reads a file and returns the content as bytes.
    
    Args:
        file_path: Path to the file
        
    Returns:
        File content as bytes
    """
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: No permission to read file '{file_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}")
        sys.exit(1)

def write_file(file_path: str, data: bytes, overwrite: bool = False) -> None:
    """
    Writes data to a file.
    
    Args:
        file_path: Path to the output file
        data: Data to write
        overwrite: Whether existing files should be overwritten
    """
    if os.path.exists(file_path) and not overwrite:
        response = input(f"File '{file_path}' already exists. Overwrite? (y/N): ")
        if response.lower() not in ['j', 'ja', 'y', 'yes']:
            print("Cancelled.")
            sys.exit(0)
    
    try:
        with open(file_path, 'wb') as f:
            f.write(data)
        print(f"File successfully written: {file_path}")
    except PermissionError:
        print(f"Error: No permission to write file '{file_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error writing file '{file_path}': {e}")
        sys.exit(1)

def encrypt_file(input_file: str, key_file: str, output_file: str, overwrite: bool = False) -> None:
    """
    Encrypts a file using a key file.
    
    Args:
        input_file: Path to the input file
        key_file: Path to the key file
        output_file: Path to the output file
        overwrite: Whether existing output files should be overwritten
    """
    print(f"Reading input file: {input_file}")
    data = read_file(input_file)
    
    print(f"Reading key file: {key_file}")
    key = read_file(key_file)
    
    if len(key) == 0:
        print("Error: Key file is empty.")
        sys.exit(1)
    
    print("Encrypting data...")
    # Derive AES key from key file
    aes_key = derive_key_from_file(key)
    encrypted_data = aes_encrypt(data, aes_key)
    
    # Ensure encrypted file has .fe extension
    base_name = os.path.splitext(output_file)[0]
    encrypted_output_file = base_name + ".fe"
    
    if encrypted_output_file != output_file:
        print(f"Auto-corrected encrypted filename: {encrypted_output_file}")
    
    print(f"Writing encrypted file: {encrypted_output_file}")
    write_file(encrypted_output_file, encrypted_data, overwrite)
    
    print(f"Encryption completed!")
    print(f"Input file: {input_file} ({len(data)} bytes)")
    print(f"Key file: {key_file} ({len(key)} bytes)")
    print(f"Output file: {encrypted_output_file} ({len(encrypted_data)} bytes)")

def decrypt_file(input_file: str, key_file: str, output_file: str, overwrite: bool = False, auto_ext: bool = True) -> None:
    """
    Decrypts a file using a key file.
    
    Args:
        input_file: Path to the encrypted file
        key_file: Path to the key file
        output_file: Path to the decrypted output file
        overwrite: Whether existing output files should be overwritten
        auto_ext: Whether to automatically detect and correct file extension
    """
    print(f"Reading encrypted file: {input_file}")
    encrypted_data = read_file(input_file)
    
    print(f"Reading key file: {key_file}")
    key = read_file(key_file)
    
    if len(key) == 0:
        print("Error: Key file is empty.")
        sys.exit(1)
    
    print("Decrypting data...")
    # Derive AES key from key file
    aes_key = derive_key_from_file(key)
    decrypted_data = aes_decrypt(encrypted_data, aes_key)
    
    # Auto-detect correct file extension if enabled
    if auto_ext:
        corrected_output_file = auto_detect_extension(output_file, decrypted_data)
    else:
        corrected_output_file = output_file
    
    print(f"Writing decrypted file: {corrected_output_file}")
    write_file(corrected_output_file, decrypted_data, overwrite)
    
    print(f"Decryption completed!")
    print(f"Input file: {input_file} ({len(encrypted_data)} bytes)")
    print(f"Key file: {key_file} ({len(key)} bytes)")
    print(f"Output file: {corrected_output_file} ({len(decrypted_data)} bytes)")

def main():
    parser = argparse.ArgumentParser(
        description="Encrypts or decrypts a file using another file as key",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s encrypt file.txt key.bin encrypted_file
  %(prog)s decrypt encrypted_file.fe key.bin decrypted_file
  %(prog)s encrypt --overwrite document.pdf password.txt secure_document
  
Note: Encrypted files are automatically saved with .fe extension
      Decrypted files get automatic extension detection based on content
        """
    )
    
    parser.add_argument(
        'mode',
        choices=['encrypt', 'decrypt', 'enc', 'dec'],
        help='Mode: encrypt/enc for encryption, decrypt/dec for decryption'
    )
    
    parser.add_argument(
        'input_file',
        help='Path to the input file'
    )
    
    parser.add_argument(
        'key_file',
        help='Path to the key file'
    )
    
    parser.add_argument(
        'output_file',
        help='Path to the output file'
    )
    
    parser.add_argument(
        '--overwrite', '-f',
        action='store_true',
        help='Overwrite existing output files without confirmation'
    )
    
    parser.add_argument(
        '--no-auto-ext',
        action='store_true',
        help='Disable automatic file extension detection during decryption'
    )
    
    args = parser.parse_args()
    
    # Check if input files exist
    if not os.path.exists(args.input_file):
        if args.mode in ['decrypt', 'dec'] and os.path.exists(args.input_file + '.fe'):
            print(f"Found encrypted input file '{args.input_file}.fe'.")
            args.input_file += '.fe'
        else:
            print(f"Error: Input file '{args.input_file}' not found.")
            sys.exit(1)
    
    if not os.path.exists(args.key_file):
        print(f"Error: Key file '{args.key_file}' not found.")
        sys.exit(1)
    
    # Execute encryption or decryption
    if args.mode in ['encrypt', 'enc']:
        encrypt_file(args.input_file, args.key_file, args.output_file, args.overwrite)
    else:  # decrypt, dec
        auto_ext = not args.no_auto_ext  # Enable auto-extension unless --no-auto-ext is specified
        decrypt_file(args.input_file, args.key_file, args.output_file, args.overwrite, auto_ext)

if __name__ == "__main__":
    main()