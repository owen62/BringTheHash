import hashlib
import pyfiglet
import getopt
import sys


def banner():
    b = pyfiglet.figlet_format("Bring The Hash")
    print(b)
    print("Version 1.0, made by Drackk")
    print("Hash Algorithm available: MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512")

def info():
    print("")
    print("Information:")
    print("[*] Options:")
    print("[~] (-i) info")
    print("[~] (-v) value")
    print("[~] (-t) hashtype")
    print("[*] Supported Hashes:")
    print("[~] md5, sha1, sha224, sha256, sha384, sha512")
    print('[*] ./bringthehash.py -v <"value"> -t <hashtype> ')


class hashCracking:
    def CreatingHash(self, value, hashtype):
        if "md5" in hashtype:
            v = hashlib.md5(value.encode('utf-8')).hexdigest()
        elif "sha1" in hashtype:
            v = hashlib.sha1(value.encode('utf-8')).hexdigest()
        elif "sha224" in hashtype:
            v = hashlib.sha1(value.encode('utf-8')).hexdigest()
        elif "sha256" in hashtype:
            v = hashlib.sha1(value.encode('utf-8')).hexdigest()
        elif "sha384" in hashtype:
            v = hashlib.sha1(value.encode('utf-8')).hexdigest()
        elif "sha512" in hashtype:
            v = hashlib.sha1(value.encode('utf-8')).hexdigest()
        else:
            print("[-] I think this is not a supported hash type")
            exit()
        return v


def start(argv):
    value = None
    hashtype = None
    banner()

    try:
        opts, args = getopt.getopt(argv, "v:t:", ["info", "value=", "type="])
    except getopt.GetoptError:
        info()
        sys.exit(1)

    for opt, arg in opts:
        if opt == ('-i'):
            info()
            sys.exit()
        elif opt in ("-v", "--value"):
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
        print("[+] Hash value:", hash_value)

    except IndexError:
        print("\n[-] Hash not created:")

    except KeyboardInterrupt:
        print("\n[Exiting...]")


if __name__ == "__main__":
    start(sys.argv[1:])
