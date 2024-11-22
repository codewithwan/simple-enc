from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import requests
import os

# generate AES key
def generate_aes_key():
    return get_random_bytes(32)  # 256-bit AES key

# enkripsi data/file menggunakan AES
def encrypt_file_with_aes(file_path, aes_key):
    with open(file_path, 'rb') as f:
        data = f.read()

    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

# enkripsi AES key menggunakan RSA public key
def encrypt_aes_key_with_rsa(public_key, aes_key):
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    return encrypted_aes_key

# dekripsi AES key menggunakan RSA private key
def decrypt_aes_key_with_rsa(private_key_base64, encrypted_aes_key):
    private_key = RSA.import_key(base64.b64decode(private_key_base64))
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    return aes_key

# dekripsi file menggunakan AES
def decrypt_file_with_aes(file_path, aes_key, nonce, tag):
    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# Menu 
def main():
    while True:
        print("\n===== Menu =====")
        print("1. Encrypt file")
        print("2. Decrypt file")
        print("3. Exit")
        choice = input("Pilih opsi: ")

        if choice == '1':
            # Dapatkan public key dari server
            response = requests.get("http://localhost:5000/get_public_key")
            response_data = response.json()
            server_id = response_data['id']
            public_key_base64 = response_data['public_key']
            public_key = RSA.import_key(base64.b64decode(public_key_base64))

            # Generate AES key
            aes_key = generate_aes_key()
            print(f"\nAES Key (Randomly Generated): {base64.b64encode(aes_key).decode()}")

            # Encrypt file menggunakan AES
            file_path = "test_encryption.txt"
            nonce, ciphertext, tag = encrypt_file_with_aes(file_path, aes_key)

            # Encrypt AES key menggunakan RSA
            encrypted_aes_key = encrypt_aes_key_with_rsa(public_key, aes_key)

            # Simpan hasil enkripsi
            with open("test_encryption.txt.enc", "wb") as f:
                f.write(ciphertext)
            with open("aes_key.enc", "wb") as f:
                f.write(encrypted_aes_key)
            with open("aes_nonce.tag", "wb") as f:
                f.write(nonce + tag)

            print(f"\nFile terenkripsi! ID: {server_id}")
            print("File terenkripsi disimpan sebagai 'test_encryption.txt.enc'")
            print("AES Key terenkripsi disimpan sebagai 'aes_key.enc'")

        elif choice == '2':
            # Input private key Base64 untuk dekripsi
            private_key_base64 = input("Masukkan RSA Private Key (Base64): ")

            # Load file terenkripsi
            encrypted_file_path = "test_encryption.txt.enc"
            encrypted_key_path = "aes_key.enc"
            nonce_tag_path = "aes_nonce.tag"

            with open(encrypted_key_path, 'rb') as f:
                encrypted_aes_key = f.read()
            with open(nonce_tag_path, 'rb') as f:
                nonce_tag = f.read()
            nonce = nonce_tag[:16]
            tag = nonce_tag[16:]

            # Dekripsi AES key menggunakan RSA
            aes_key = decrypt_aes_key_with_rsa(private_key_base64, encrypted_aes_key)
            print(f"\nAES Key berhasil didekripsi: {base64.b64encode(aes_key).decode()}")

            # Dekripsi file menggunakan AES
            plaintext = decrypt_file_with_aes(encrypted_file_path, aes_key, nonce, tag)

            # Simpan file hasil dekripsi
            decrypted_file_path = "test_encryption_decrypted.txt"
            with open(decrypted_file_path, 'wb') as f:
                f.write(plaintext)
            print(f"\nFile berhasil didekripsi! Disimpan sebagai '{decrypted_file_path}'")

            # Hapus file AES key, nonce, dan file terenkripsi
            os.remove(encrypted_key_path)
            os.remove(nonce_tag_path)
            os.remove(encrypted_file_path)
            print(f"\nFile 'aes_key.enc', 'aes_nonce.tag', dan 'test_encryption.txt.enc' berhasil dihapus.")

        elif choice == '3':
            print("Keluar program.")
            break
        else:
            print("Opsi tidak valid. Coba lagi.")

if __name__ == "__main__":
    main()
