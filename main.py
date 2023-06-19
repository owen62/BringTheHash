import hashlib
import pyfiglet
import getopt
import sys

def banner():
    b = pyfiglet.figlet_format("Bring The Hash")
    print(b)
    print("Version 1.0, made by Drackk")
    print("Hash Algorithm available: MD4 | MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512")

def info():
    print("")
    print("Information:")
    print("[*] Options:")
    print("[~] -v value")
    print("[~] -t hashtype")
    print("[*] Supported Hashes:")
    print("[~] md4, md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2s, blake2b")
    print('[~] ./bringthehash.py -v <"value"> -t <hashtype> ')


class hashCracking:
    def CreatingHash(self, value, hashtype):
        if "md5" in hashtype:
            v = hashlib.md5(value.encode('utf-8')).hexdigest()
        elif "md4" in hashtype:
            v = hashlib.new('md4', value.encode('utf-8')).hexdigest()
        elif "sha1" in hashtype:
            v = hashlib.sha1(value.encode('utf-8')).hexdigest()
        elif "sha224" in hashtype:
            v = hashlib.sha224(value.encode('utf-8')).hexdigest()
        elif "sha256" in hashtype:
            v = hashlib.sha256(value.encode('utf-8')).hexdigest()
        elif "sha384" in hashtype:
            v = hashlib.sha384(value.encode('utf-8')).hexdigest()
        elif "sha512" in hashtype:
            v = hashlib.sha512(value.encode('utf-8')).hexdigest()
        elif "sha3_224" in hashtype:
            v = hashlib.sha3_224(value.encode('utf-8')).hexdigest()
        elif "sha3_256" in hashtype:
            v = hashlib.sha3_256(value.encode('utf-8')).hexdigest()
        elif "sha3_384" in hashtype:
            v = hashlib.sha3_384(value.encode('utf-8')).hexdigest()
        elif "sha3_512" in hashtype:
            v = hashlib.sha3_512(value.encode('utf-8')).hexdigest()
        elif "blake2s" in hashtype:
            v = hashlib.blake2s(value.encode('utf-8')).hexdigest()
        elif "blake2b" in hashtype:
            v = hashlib.blake2b(value.encode('utf-8')).hexdigest()
        else:
            print("[-] I think this is not a supported hash type")
            exit()
        return v

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

    print("[*] value: %s" % value)
    print("[*] Hash type: %s" % hashtype)
    print("[+] Hash creation...")

    try:
        v= hashCracking()
        hash_value = v.CreatingHash(value, hashtype)
        print("[+] \033[1;32mHash value:", hash_value, "\033[0m")

    except IndexError:
        print("\n[-] Hash not created:")

    except KeyboardInterrupt:
        print("\n[Exiting...]")


if __name__ == "__main__":
    start(sys.argv[1:])
