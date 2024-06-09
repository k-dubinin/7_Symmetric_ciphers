import secrets

def xor_bytes(b1, b2):
    """Выполняет побитовое исключающее ИЛИ для двух байтовых строк."""
    return bytes(x ^ y for x, y in zip(b1, b2))

def feistel_round(left, right, key):
    """Выполняет один раунд сети Фейстеля."""
    new_left = right
    new_right = xor_bytes(left, key)
    return new_left, new_right

def feistel_network(text, rounds, key):
    """Выполняет сеть Фейстеля с заданным количеством раундов."""
    text_bytes = text.encode()
    block_size = len(text_bytes) // 2
    left = text_bytes[:block_size]
    right = text_bytes[block_size:]
    for _ in range(rounds):
        left, right = feistel_round(left, right, key)
    return left + right

def encrypt(text, rounds, key):
    """Шифрует текст с помощью сети Фейстеля."""
    return feistel_network(text, rounds, key)

def decrypt(ciphertext, rounds, key):
    """Расшифровывает текст с помощью сети Фейстеля."""
    return feistel_network(ciphertext, rounds, key).decode()

# Пример использования
key_feistel = secrets.token_bytes(16)  # Генерация случайного ключа длиной 16 байт
plaintext_feistel = "Hello, World!"
encrypted_text_feistel = encrypt(plaintext_feistel, 10, key_feistel)
decrypted_text_feistel = decrypt(encrypted_text_feistel, 10, key_feistel)

print('Original Text:', plaintext_feistel)
print('Encrypted Text (Feistel):', encrypted_text_feistel.hex())  # Вывод в шестнадцатеричном формате
print('Decrypted Text (Feistel):', decrypted_text_feistel)
