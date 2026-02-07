import os
import base64
import binascii
import hashlib
import hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_rsa_key_pair():
    """Generate a new RSA key pair (private and public key)."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def encrypt_aes_key(aes_key, public_key):
    """Encrypt an AES key using RSA public key."""
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode('utf-8')


def decrypt_aes_key(encrypted_key_b64, private_key):
    """Decrypt an AES key using RSA private key."""
    encrypted_key = base64.b64decode(encrypted_key_b64)
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_key)


def encrypt_message(message, aes_key):
    """Encrypt a message using AES-256-CBC.
    
    Args:
        message: The message to encrypt (str or bytes)
        aes_key: The AES key to use for encryption (bytes)
    """

    if isinstance(message, str):
        message = message.encode('utf-8')
    elif not isinstance(message, bytes):
        raise ValueError("Message must be either str or bytes")
    

    iv = get_random_bytes(16)
    

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    

    padded_message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    

    encrypted_data = iv + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')



def decrypt_message(encrypted_message_b64, aes_key):
    """Decrypt a message using AES-256-CBC."""
    encrypted_data = base64.b64decode(encrypted_message_b64)
    
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    
    return unpad(padded_message, AES.block_size).decode('utf-8')


def generate_aes_key():
    """Generating a random 32-byte AES key. """
    return get_random_bytes(32) 

def hash_password(password):
    """Hash a password for storing. """
    if not password:
        raise ValueError("Password cannot be empty")
    
    salt = get_random_bytes(32)
    
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000, 
        dklen=32 
    )
    
    combined = salt + key
    
    return base64.b64encode(combined).decode('utf-8')

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    if not stored_password or not provided_password:
        return False
        
    try:
        decoded = base64.b64decode(stored_password)
        
        salt = decoded[:32]
        stored_key = decoded[32:64]  
        
        new_key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        
        return hmac.compare_digest(stored_key, new_key)
        
    except (ValueError, binascii.Error) as e:
        print(f"Error verifying password: {str(e)}")
        return False
