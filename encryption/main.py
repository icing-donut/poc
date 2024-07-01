#!/usr/bin/env python3

import sys
from ffmpy import FFmpeg
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import subprocess

private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)



def encrypt_bitstream(bitstream, peer_public_key_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(bitstream) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext



def decrypt_bitstream(ciphertext, peer_public_key_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data



def process_audio(input_wav):

    process = subprocess.Popen(
        ['ffmpeg', '-i', input_wav, '-ar', '8000', '-b:a', '128k', '-f', 'mp3', 'pipe:1'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return process.stdout.read()


def main():
    input_wav = 'CantinaBand60.wav'

    with open(input_wav, 'rb') as f:
        original_bitstream = f.read()

    processed_bitstream = process_audio(input_wav)

    print("Original WAV bitstream length:", len(original_bitstream))
    print("Processed MP3 bitstream length:", len(processed_bitstream))

    chunk_size = 1024
    for i in range(0, len(processed_bitstream), chunk_size):
        chunk = processed_bitstream[i:i + chunk_size]
        ciphertext = encrypt_bitstream(chunk, public_key_bytes)
        decrypted_chunk = decrypt_bitstream(ciphertext, public_key_bytes)
        with open('output.mp3', 'ab') as f:
            f.write(decrypted_chunk)


if __name__ == "__main__":
    main()
