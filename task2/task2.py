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
    print("ORIGINAL: ", string)
    encoded_data = urllib.parse.quote(string) # URL encode ; and =
    print("ENCODED: ", encoded_data[32:])

    padded_data = pad(encoded_data) # pad data
    # padded_data = pad(string)
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


def attack(ciphertext):
    modified_ciphertext = bytearray(ciphertext)
    target = ["t", "e", "s", "t", "t", "m", "e", "s", "s", "a", "g", "e", "s", "s", "s", "s", "s", "s", "s", "s", "s", "s"]
    inject = [";", "a", "d", "m", "i", "n", "=", "t", "r", "u", "e", ";"] 

    print(target[32-31] + " " + inject[32-32])
    for i in range(32, 33):
        modified_ciphertext[i] ^= ord(target[i-31]) ^ ord(inject[i-32])

    # prev = modified_ciphertext[16:32]
    # cur = modified_ciphertext[32:48]
    # block = bytes([x ^ y for x, y in zip(prev, cur)])
    # ciphertext = ciphertext[:32] + block + ciphertext[48:]

    return bytes(modified_ciphertext)


if __name__ == '__main__':
    key = gen_key_iv()
    iv = gen_key_iv()
    ciphertext = submit("testtmessagessssssssss", key, iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    print("CIPHERTEXT: ", cipher.decrypt(ciphertext))


    modify = attack(ciphertext)

    result = verify(modify, key, iv)
    print("Admin access granted: ", result)
