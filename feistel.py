import secrets

def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

def feistel_round(left, right, key):
    new_left = right
    new_right = xor_bytes(left, key)
    return new_left, new_right

def feistel_network(text, rounds, key):
    left, right = text[:len(text) // 2], text[len(text) // 2:]
    for _ in range(rounds):
        left, right = feistel_round(left, right, key)
    return left + right

# Пример использования
key_feistel = secrets.token_bytes(len("mysecretkey"))  # Генерация случайного ключа длиной "mysecretkey"
plaintext_feistel = "Hello, World!"
encrypted_text_feistel = feistel_network(plaintext_feistel.encode(), 10, key_feistel)
decrypted_text_feistel = feistel_network(encrypted_text_feistel, 10, key_feistel)

print('Original Text:', plaintext_feistel)
print('Encrypted Text (Feistel):', encrypted_text_feistel.decode())
print('Decrypted Text (Feistel):', decrypted_text_feistel.decode())
