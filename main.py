import hashlib
import pyfiglet
import getopt
import sys
import os
import time


def banner():
    ascii_banner = pyfiglet.figlet_format("BringMeTheHash")
    print(ascii_banner)
    print("Hash Algorithm available: MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512")
    print("Version 1.0 Made by Drackk")


def info():
    print("")
    print("Information:")
    print("[*] Options:")
    print("[*] (-i) info")
    print("[*] (-v) value")
    print("[*] (-t) hashtype [See supported hashes]")
    print("[*] (-o) output")
    print("[*] Supported Hashes:")
    print("[>] md5, sha1, sha224, sha256, sha384, sha512")
    print("[*] That's all folks!\n")


def start(argv):
    value = None
    hashtype = None
    banner()

    try:
        opts, args = getopt.getopt(argv, "ih:v:t:", ["info", "value=", "type="])
    except getopt.GetoptError:
        print('[*] ./main.py -v <value> -t <type> ')
        print('[*] Type ./main.py -i for information')
        sys.exit(1)

    for opt, arg in opts:
        if opt == ('-i'):
            info()
            sys.exit()
        elif opt in ("-v", "--value"):
            value = arg
        elif opt in ["-t", "--type"]:
            hashtype = arg

    print(hashtype)
    print(value)

    if not (value and hashtype):
        print('[*] ./main.py -v <value> -t <type>')
        sys.exit()


if __name__ == "__main__":
    start(sys.argv[1:])



def CreatingHash(value, hashtype):
    if "md5" in hashtype:
        v = hashlib.md5(value.encode()).hexdigest()
    elif "sha1" in hashtype:
        v = hashlib.sha1(value.encode()).hexdigest()
    elif "sha224" in hashtype:
        v = hashlib.sha1(value.encode()).hexdigest()
    elif "sha256" in hashtype:
        v = hashlib.sha1(value.encode()).hexdigest()
    elif "sha384" in hashtype:
        v = hashlib.sha1(value.encode()).hexdigest()
    elif "sha512" in hashtype:
        v = hashlib.sha1(value.encode()).hexdigest()
    else:
        print("[-] I think this is not a supported hash type")
        exit()