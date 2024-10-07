from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# generate key or iv
def gen_key_iv():
    return get_random_bytes(16)


# add padding to data so that its length is a multiple of 16 (bytes)
def pad(data):
    padding = 16 - (len(data) % 16)
    return data + bytes([padding] * padding)


# remove padding from data
def unpad(data):
    padding = data[-1]
    return data[:-padding]


# output the data to a file
def visualize(data, output_file):
    with open(output_file, 'wb') as file:
        file.write(data)


# encrypt the image using AES in ECB or CBC mode
def encrypt_image(file, mode, key=None, iv=None):
    # read the image file
    with open(file, 'rb') as file:
        header = file.read(54)
        data = file.read()
    file.close()

    data = pad(data) # pad the data
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)] # separate data in 16-byte blocks
    combine = header # combine variable will be used to store the encrypted data
    cipher = AES.new(key, AES.MODE_ECB)

    if mode == 'ECB':
        for block in blocks:
            combine += cipher.encrypt(block)

        visualize(combine, 'encrypt_ecb.bmp')
    elif mode == 'CBC':
        prev = iv
        first_block = bytes([x ^ y for x, y in zip(blocks[0], prev)])
        prev = cipher.encrypt(first_block)
        combine += prev

        i = 1
        while i < len(blocks):
            cur = blocks[i]
            block = bytes([x ^ y for x, y in zip(prev, cur)])
            prev = cipher.encrypt(block)
            combine += prev
            i += 1

        visualize(combine, 'encrypt_cbc.bmp')


# decrypt the image using AES in ECB or CBC mode
def decrypt_image(file, mode, key, iv=None):
    with open(file, 'rb') as file:
        header = file.read(54)
        data = file.read()
    file.close()

    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    cipher = AES.new(key, AES.MODE_ECB)
    combine = header

    if mode == 'ECB': 
        for block in blocks:
            combine += cipher.decrypt(block)

        combine = unpad(combine)
        visualize(combine, 'decrypt_ecb.bmp')
    elif mode == 'CBC':
        prev = iv
        for block in blocks:
            decrypted_block = cipher.decrypt(block)
            first_block = bytes([x ^ y for x, y in zip(decrypted_block, prev)])
            combine += first_block
            prev = block

        combine = unpad(combine)
        visualize(combine, 'decrypt_cbc.bmp')


if __name__ == '__main__':
    input_file = "cp-logo.bmp"
    key = gen_key_iv()
    iv = gen_key_iv()

    # ECB
    encrypt_image(input_file, 'ECB', key)
    decrypt_image('encrypt_ecb.bmp', 'ECB', key)

    # CBC
    encrypt_image(input_file, 'CBC', key, iv)
    decrypt_image('encrypt_cbc.bmp', 'CBC', key, iv)
