from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import urllib.parse


# generate key or iv
def gen_key_iv():       #done
    return get_random_bytes(16)


# add padding to data so that its length is a multiple of 16 (bytes)
def pad(data):      #done
    padding = 16 - (len(data) % 16)
    return data + bytes([padding] * padding)

# remove padding from data
def unpad(data):        #done
    padding = data[-1]
    return data[:-padding]

# submit user input for encryption
def submit(input, key, iv):     #done
    prepend = "userid=456;userdata="
    append = ";session-id=31337"

    string = prepend + input + append # prepend and append strings to input

    cipher = AES.new(key, AES.MODE_CBC, iv)

    padded_data = pad(string.encode('utf-8')) # pad data

    encrypted = cipher.encrypt(padded_data) # encrypt using AES-128-CBC

    return encrypted


def verify(ciphertext, key, iv):
    '''Decrypts ct, check admin and return result'''
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = unpad(cipher.decrypt(ciphertext))

    decoded = decrypted_data[16:].decode('utf-8')

    print(f"Decrypted data: {decoded}")

    pattern = ";admin=true;"

    return pattern in decoded


def attack(ciphertext):     #done
    # convert ct to mutuable bytearray
    modified_ciphertext = bytearray(ciphertext)

    modified_ciphertext[4] ^= ord('@') ^ ord(';')
    modified_ciphertext[10] ^= ord('$') ^ ord('=')
    modified_ciphertext[15] ^= ord('*') ^ ord(';')

    return bytes(modified_ciphertext)


if __name__ == '__main__':
    key = gen_key_iv()
    iv = gen_key_iv()

    ciphertext = submit("@admin$true*", key, iv)
    print("Original Verify:", verify(ciphertext, key, iv))

    # bit flipping attack
    modified_ciphertext = attack(ciphertext)

    # verify tampered
    is_admin = verify(modified_ciphertext, key, iv)

    print(f"Second Verify after attack: {is_admin}")
    