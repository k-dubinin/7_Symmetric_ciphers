import secrets

plaintext_otp = "Hello, World!"

def encrypt_otp(key, plaintext):
    if len(key) != len(plaintext):
        raise ValueError("Key length must be equal to plaintext length")
    ciphertext = ''
    for i in range(len(plaintext)):
        char_code = ord(plaintext[i]) ^ key[i]  # XOR операция
        ciphertext += chr(char_code)
    return ciphertext

def decrypt_otp(key, ciphertext):
    if len(key) != len(ciphertext):
        raise ValueError("Key length must be equal to ciphertext length")
    plaintext = ''
    for i in range(len(ciphertext)):
        char_code = ord(ciphertext[i]) ^ key[i]  # XOR операция
        plaintext += chr(char_code)
    return plaintext

# Пример использования
key_otp = secrets.token_bytes(len(plaintext_otp))  # Генерация случайного ключа длиной plaintext_otp
key_otp = [x for x in key_otp]  # Преобразуем байтовую строку в список байт
encrypted_text_otp = encrypt_otp(key_otp, plaintext_otp)
decrypted_text_otp = decrypt_otp(key_otp, encrypted_text_otp)

print('Original Text:', plaintext_otp)
print('Encrypted Text (OTP):', encrypted_text_otp)
print('Decrypted Text (OTP):', decrypted_text_otp)
