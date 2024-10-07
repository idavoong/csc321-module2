from Crypto.Cipher import AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
import urllib.parse


# generate key or iv
def gen_key_iv():
    return get_random_bytes(16)


# add padding to data so that its length is a multiple of 16 (bytes)
def pad(data):
    padding = 16 - (len(data) % 16)
    return bytes(data, encoding='utf8') + bytes([padding] * padding)


# remove padding from data
def unpad(data):
    padding = data[-1]
    return data[:-padding]


def submit(input, key, iv):
    prepend = "userid=456;userdata="
    append = ";session-id=31337"
    string = prepend + input + append # prepend and append strings to input
    encoded_data = urllib.parse.quote(string) # URL encode ; and =
    padded_data = pad(encoded_data) # pad data

    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded_data) # encrypt using AES-128-CBC

    return encrypted


def verify(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted)
    pattern = b";admin=true;"

    if pattern in unpadded_data:
        return True
    else:
        return False
    

def attack(ciphertext, injection):
    result = []

if __name__ == '__main__':
    key = gen_key_iv()
    iv = gen_key_iv()
    ciphertext = submit("test message", key, iv)
    print(verify(ciphertext, key, iv))
