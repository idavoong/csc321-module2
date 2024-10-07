from Crypto.Cipher import AES # type: ignore
from Crypto.Random import get_random_bytes # type: ignore
import urllib.parse 

# add padding to data so that its length is a multiple of 16 (bytes)
def pad_pkcs7(data):
    padding = 16 - (len(data) % 16)
    return data + bytes([padding] * padding)

def unpad_pkcs7(data):
    padding = data[-1]
    return data[:-padding]

# two block of bytes
def xor_blocks(block, prev_block):
    return bytes([x ^ y for x, y in zip(block[0], prev_block)])

def tamper_cipherText(cipherText):
    enc_lst = bytearray(cipherText)

    # xor operation - admin = true
    enc_lst[4] ^= (ord("@") ^ ord(";"))     #
    enc_lst[10] ^= (ord("$") ^ ord("="))
    enc_lst[15] ^= (ord("*") ^ ord(";"))

    # modified ciphertext
    return bytes(cipherText)


def submit(input):
    # input: Arbitrary user string
    prepend_str = "userid=456;userdata="
    append_str = ";session-id=31337"

    # URL encode(convert) user input
    url_encode = urllib.parse.quote(input)

    # Apply PKCS#7 padding

    # Encrypt using AES-128-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipherText = cipher.encrypt()


    # output: Ciphertext
    return cipherText

def verify(bytes):
    print("VERIFY", cipherText)

    # Decrypt ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_txt = cipher.decrypt(cipherText)

    # Remove padding
    decrypted_data = unpad_pkcs7(decrypted_txt)

    # Url decode decrypted data
    decoded_data = url_decoding(decrypted_data[16:].decode('utf-8'))

    print("ORIGINAL", decoded_data)


    # search for admin = true
    # Output: Boolean
    return ";admin=true;" in decoded_data
