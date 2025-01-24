import os
import sys
import subprocess

required_packages = ['ecdsa', 'base58', 'requests']

def check_and_install_packages():
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            user_input = input(f"'{package}' package is not installed. Do you want to install it? (Y/n): ").strip().lower()
            if user_input == 'y':
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            else:
                print(f"The '{package}' package is required to run the program.")
                sys.exit(1)

check_and_install_packages()

def generate_secret():
    return os.urandom(32).hex()

import hashlib
import ecdsa
import base58
import requests
import time

def private_key_from_secret(secret):
    return hashlib.sha256(secret.encode()).hexdigest()

def public_key_from_private_key(private_key):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def bitcoin_address_from_public_key(public_key):
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_hash).digest()
    extended_ripemd160 = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160).digest()).digest()[:4]
    binary_address = extended_ripemd160 + checksum
    return base58.b58encode(binary_address).decode()

def check_balance(address):
    url = f"https://blockstream.info/api/address/{address}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        balance = data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
        return balance / 1e8
    except requests.RequestException as e:
        print(f"API Error: {e}")
        return "Error"

def write_to_file(secret, private_key, address, balance, filename='prize.txt'):
    with open(filename, 'a') as file:
        file.write(f"Secret: {secret}\n")
        file.write(f"Private Key: {private_key}\n")
        file.write(f"Bitcoin Address: {address}\n")
        file.write(f"Balance: {balance} BTC\n")
        file.write("-" * 40 + "\n")

def main():
    try:
        num_iterations = int(input("How many times do you want to process: "))
    except ValueError:
        print("Please enter a valid number.")
        return

    for i in range(1, num_iterations + 1):
        print(f"\n...{i}/{num_iterations}...")

        secret = generate_secret()
        private_key = private_key_from_secret(secret)
        public_key = public_key_from_private_key(private_key)
        bitcoin_address = bitcoin_address_from_public_key(public_key)

        balance = check_balance(bitcoin_address)

        print(f"Secret: {secret}")
        print(f"Private Key: {private_key}")
        print(f"Bitcoin Address: {bitcoin_address}")
        print(f"Balance: {balance} BTC")

        if isinstance(balance, float) and balance > 0:
            write_to_file(secret, private_key, bitcoin_address, balance)
            print("YOU FOUND IT!")
        elif balance == "Error":
            print("API Error")
        else:
            print("UNLUCKY")

        time.sleep(0.1)

    print("\nNeiman, you're done.")

if __name__ == "__main__":
    main()
