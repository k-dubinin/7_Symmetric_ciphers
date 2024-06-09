def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

def pad(text, block_size):
    padding_len = block_size - len(text) % block_size
    padding = bytes([padding_len]) * padding_len
    return text + padding

def unpad(text):
    padding_len = text[-1]
    return text[:-padding_len]

def encrypt_cbc(key, iv, plaintext):
    block_size = len(key)
    plaintext_padded = pad(plaintext.encode(), block_size)
    blocks = [plaintext_padded[i:i + block_size] for i in range(0, len(plaintext_padded), block_size)]

    prev_cipher_block = iv.encode()  # Преобразуем IV в байтовую строку
    ciphertext = b''
    for block in blocks:
        block_xor_iv = xor_bytes(block, prev_cipher_block)
        encrypted_block = xor_bytes(block_xor_iv, key.encode())
        ciphertext += encrypted_block
        prev_cipher_block = encrypted_block
    return ciphertext

def decrypt_cbc(key, iv, ciphertext):
    block_size = len(key)
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    prev_cipher_block = iv.encode()  # Преобразуем IV в байтовую строку
    plaintext_padded = b''
    for block in blocks:
        decrypted_block = xor_bytes(block, key.encode())
        plaintext_padded += xor_bytes(decrypted_block, prev_cipher_block)
        prev_cipher_block = block

    plaintext = unpad(plaintext_padded).decode()
    return plaintext

# Пример использования
key_cbc = "mysecretkey"
iv_cbc = "initialiv123456"
plaintext_cbc = "Hello, World!"
encrypted_text_cbc = encrypt_cbc(key_cbc, iv_cbc, plaintext_cbc)
decrypted_text_cbc = decrypt_cbc(key_cbc, iv_cbc, encrypted_text_cbc)

print('Original Text:', plaintext_cbc)
print('Encrypted Text (CBC):', encrypted_text_cbc)
print('Decrypted Text (CBC):', decrypted_text_cbc)
