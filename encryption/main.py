import pyaudio
import wave
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import subprocess
import tempfile

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
    padder = PKCS7(algorithms.AES.block_size).padder()
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
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def process_audio(input_wav_data):
    original_size = len(input_wav_data)
    with tempfile.NamedTemporaryFile(delete=True) as tmp_file:
        tmp_file.write(input_wav_data)
        tmp_file.flush()

        command = [
            'ffmpeg',
            '-i', tmp_file.name,
            '-f', 'amr',
            '-ac', '1',
            '-ar', '8000',
            '-b:a', '12.2k',
            '-filter:a', 'highpass=f=200,lowpass=f=3400',
            'pipe:1'
        ]
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"Error processing audio: {stderr.decode()}")
            return None, original_size, 0
        compressed_size = len(stdout)
        return stdout, original_size, compressed_size

def record_and_process_audio():
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 44100
    CHUNK = 1024
    audio = pyaudio.PyAudio()

    try:
        stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
    except IOError as e:
        print(f"Error opening audio stream: {e}")
        return

    print("Recording... Press Ctrl+C to stop.")
    frames = []
    try:
        while True:
            data = stream.read(CHUNK, exception_on_overflow=False)
            frames.append(data)
    except KeyboardInterrupt:
        print("Recording stopped.")
    finally:
        stream.stop_stream()
        stream.close()
        audio.terminate()

    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp_wav:
        wf = wave.open(tmp_wav, 'wb')
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(audio.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))
        wf.close()

        with open(tmp_wav.name, 'rb') as wav_file:
            wav_data = wav_file.read()
            processed_data, original_size, compressed_size = process_audio(wav_data)
            if processed_data:
                ciphertext = encrypt_bitstream(processed_data, public_key_bytes)
                decrypted_chunk = decrypt_bitstream(ciphertext, public_key_bytes)
                with open('output.amr', 'wb') as f:
                    f.write(decrypted_chunk)
                print(f"Original size: {original_size} bytes")
                print(f"Compressed size: {compressed_size} bytes")
                print(f"Encrypted size: {len(ciphertext)} bytes")
        os.remove(tmp_wav.name)

def main():
    record_and_process_audio()

if __name__ == "__main__":
    main()
