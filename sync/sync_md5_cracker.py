import hashlib
import sys


class Cracker:
    def __init__(self, salt: str, hash: str, username: str, password_list: str) -> None:
        self.salt = salt
        self.hash = hash
        self.username = username
        self.password_list = password_list

    def generate_hash(self):
        with open(self.password_list, 'r', encoding="ISO-8859-1") as wordlist:
            for password in wordlist:
                hash_data = f"{self.salt}|{self.username}|{password.strip()}"
                try:
                    generated_hash = hashlib.md5(hash_data.encode())
                except Exception as e:
                    print(e)
                    continue

                hex_hash = generated_hash.hexdigest()

                if self.compare_hashes(str(hex_hash)):
                    print(f"[+] Cracked: {self.username}:{password}")
                    sys.exit(0)
            print("[!] Could not crack!")

    def compare_hashes(self, generated_hash: str):
        if generated_hash == self.hash:
            return True
        else:
            return


if __name__ == '__main__':
    salt = sys.argv[1]
    username = sys.argv[2]
    password_list = sys.argv[3]
    hash = sys.argv[4]

    cracker = Cracker(salt, hash, username, password_list)
    cracker.generate_hash()
