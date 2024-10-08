import matplotlib.pyplot as plt
import subprocess
import re


def plot(data, title, xlabel, ylabel):
    for key_size, throughput in data.items():
        plt.plot(throughput, label=f'{key_size}-bit')

    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.legend()
    plt.grid(True)
    plt.savefig(f"{title}.png")


def run_aes():
    result = subprocess.run(['openssl', 'speed', 'aes'], capture_output=True, text=True)
    output = result.stdout
    data = {}

    regex = re.compile(r'aes-\d{3}-cbc\s+([\d\.]+k)\s+([\d\.]+k)\s+([\d\.]+k)\s+([\d\.]+k)\s+([\d\.]+k)')
    for match in regex.finditer(output):
        key_size = match.group(0).split('-')[1]
        throughput = [float(value.replace('k', '')) for value in match.groups()]
        data[key_size] = throughput

    plot(data, "AES", "Block Size (bytes)", "Throughput (signatures/sec)")


def run_rsa():
    result = subprocess.run(['openssl', 'speed', 'rsa'], capture_output=True, text=True)
    output = result.stdout
    data = {}

    regex = re.compile(r'rsa\s+(\d+)\s+bits\s+[\d\.]+s\s+[\d\.]+s\s+([\d\.]+)\s+([\d\.]+)')
    for match in regex.finditer(output):
        key_size = match.group(1)  # RSA key size (e.g., 512, 1024, 2048, etc.)
        sign_per_sec = float(match.group(2))  # Signatures per second
        verify_per_sec = float(match.group(3))  # Verifications per second

    data[key_size] = (sign_per_sec, verify_per_sec)  # Store as a tuple (sign, verify)

    plot(data, "RSA", "Key Size (bits)", "Throughput (signatures/sec)")


if __name__ == '__main__':
    run_aes()
    run_rsa()
