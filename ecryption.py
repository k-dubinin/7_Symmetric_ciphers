import random

def encrypt_caesar(k, plaintext):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():  # Проверяем, является ли символ буквой
            shifted = ord(char) + k
            if char.islower():  # Обработка для строчных букв
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():  # Обработка для заглавных букв
                if shifted > ord('Z'):
                    shifted -= 26
            ciphertext += chr(shifted)
        else:
            ciphertext += char  # Сохраняем не-буквенные символы без изменений
    return ciphertext

def decrypt_caesar(k, ciphertext):
    return encrypt_caesar(-k, ciphertext)  # Дешифрование через обратный сдвиг

def encrypt_vernam(key, plaintext):
    random.seed(key)  # Устанавливаем seed для повторяемости
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():  # Проверяем, является ли символ буквой
            shift = random.randint(0, 25)  # Генерируем случайное смещение
            shifted = ord(char) + shift
            if char.islower():  # Обработка для строчных букв
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():  # Обработка для заглавных букв
                if shifted > ord('Z'):
                    shifted -= 26
            ciphertext += chr(shifted)
        else:
            ciphertext += char  # Сохраняем не-буквенные символы без изменений
    return ciphertext

def decrypt_vernam(key, ciphertext):
    random.seed(key)  # Устанавливаем seed для повторяемости
    plaintext = ''
    for char in ciphertext:
        if char.isalpha():  # Проверяем, является ли символ буквой
            shift = random.randint(0, 25)  # Генерируем тот же случайный сдвиг
            shifted = ord(char) - shift
            if char.islower():  # Обработка для строчных букв
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():  # Обработка для заглавных букв
                if shifted < ord('A'):
                    shifted += 26
            plaintext += chr(shifted)
        else:
            plaintext += char  # Сохраняем не-буквенные символы без изменений
    return plaintext

if __name__ == "__main__":
    # Шифр Цезаря
    plaintext_caesar = 'Hello, World!'
    key_caesar = 3
    encrypted_text_caesar = encrypt_caesar(key_caesar, plaintext_caesar)
    decrypted_text_caesar = decrypt_caesar(key_caesar, encrypted_text_caesar)

    print('Original Text (Caesar):', plaintext_caesar)
    print('Encrypted Text (Caesar):', encrypted_text_caesar)
    print('Decrypted Text (Caesar):', decrypted_text_caesar)

    # Шифр Вернама
    plaintext_vernam = 'Hello, World!'
    key_vernam = 'secretkey'
    encrypted_text_vernam = encrypt_vernam(key_vernam, plaintext_vernam)
    decrypted_text_vernam = decrypt_vernam(key_vernam, encrypted_text_vernam)

    print('\nOriginal Text (Vernam):', plaintext_vernam)
    print('Encrypted Text (Vernam):', encrypted_text_vernam)
    print('Decrypted Text (Vernam):', decrypted_text_vernam)
