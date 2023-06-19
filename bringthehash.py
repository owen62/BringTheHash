
import hashlib
import pyfiglet
import getopt
import sys

def banner():
    b = pyfiglet.figlet_format("Bring The Hash")
    print(b)
    print("Version 1.0, made by Drackk")
    print("Hash Algorithms available: MD4 | MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | SHA3_224 | SHA3_256 | SHA3_384 | SHA3_512 | BLAKE2S | BLAKE2B")

def info():
    print("")
    print("Information:")
    print("[*] Options:")
    print("[~] -v value")
    print("[~] -t hashtype")
    print("[*] Supported Hashes:")
    print("[~] md4, md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2s, blake2b")
    print('[~] ./bringthehash.py -v <"value"> -t <hashtype> ')


class HashGenerator:
    def create_hash(self, value, hashtype):
        supported_algorithms = ["md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2s", "blake2b"]
        
        if hashtype not in supported_algorithms:
            print("[-] Unsupported hash type")
            exit()

        else :
            hash_object = hashlib.new(hashtype)
            hash_object.update(value.encode('utf-8'))
            hash_value = hash_object.hexdigest()
            return hash_value

def start(argv):
    value = None
    hashtype = None
    banner()

    try:
        opts, args = getopt.getopt(argv, "v:t:", ["value=", "type="])
    except getopt.GetoptError:
        info()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ("-v", "--value"):
            value = arg
        elif opt in ["-t", "--type"]:
            hashtype = arg

    if not (value and hashtype):
        info()
        sys.exit()

    print("[*] value:", value)
    print("[*] Hash type:", hashtype)
    print("[+] Hash creation...")

    try:
        hasher = HashGenerator()
        hash_value = hasher.create_hash(value, hashtype)
        print("[+] Hash value: \033[1;32m", hash_value, "\033[0m")

    except KeyboardInterrupt:
        print("\n[Exiting...]")

if __name__ == "__main__":
    start(sys.argv[1:])
