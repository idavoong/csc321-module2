from Crypto.Cipher import AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
import urllib.parse


# generate key or iv
def gen_key_iv():
    return get_random_bytes(16)


# add padding to data so that its length is a multiple of 16 (bytes)
def pad(data):
    padding = 16 - (len(data) % 16)
    return bytes(data, encoding='utf-8') + bytes([padding] * padding)


# remove padding from data
def unpad(data):
    padding = data[-1]
    return data[:-padding]


def submit(input, key, iv):
    prepend = "userid=456;userdata="
    append = ";session-id=31337"
    string = prepend + input + append # prepend and append strings to input
    encoded_data = urllib.parse.quote(string) # URL encode ; and =
    print("ORIGINAL: ", encoded_data)

    padded_data = pad(encoded_data) # pad data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded_data) # encrypt using AES-128-CBC

    return encrypted


def verify(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted)
    decode = urllib.parse.unquote(unpadded_data)

    pattern = b";admin=true;"

    print("DECRPYTED: ", decode)

    if pattern in unpadded_data:
        return True
    else:
        return False


def xor_blocks(block, prev_block):
    return bytes([x ^ y for x, y in zip(block, prev_block)])


# def attack(ciphertext, injection):
#     # result = []

#     modified_ciphertext = bytearray(ciphertext)

#     modified_ciphertext[4] ^= ord("@") ^ ord(";")
#     modified_ciphertext[10] ^= ord("$") ^ ord("=")
#     modified_ciphertext[15] ^= ord("*") ^ ord(";")

#     target = bytes(injection, 'utf-8')

#     for i in range(len(target)):
#         modified_ciphertext[i] ^= ord("?") ^ target[i]

#     return bytes(modified_ciphertext)


def attack(ciphertext ,injection, key, iv):
    prepend = "userid=456;userdata="
    prepend_len = len(prepend)
    target = prepend_len // 16


if __name__ == '__main__':
    key = gen_key_iv()
    iv = gen_key_iv()
    ciphertext = submit("test message", key, iv)
    print("CIPHERTEXT: ", ciphertext)

    result = verify(ciphertext, key, iv)
    print("Admin access granted: ", result)
    # modified_ciphertext = attack(ciphertext, ";admin=true;")
    # is_admin = verify(modified_ciphertext, key, iv)
    # print(verify(ciphertext, key, iv))
    # print(attack)
    # print(modified_ciphertext)
    # print(f"Admin access granted: {is_admin}")
