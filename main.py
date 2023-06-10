import hashlib
import pyfiglet
import sys
import getopt

def banner():
    ascii_banner = pyfiglet.figlet_format("BringMeTheHash")
    print(ascii_banner)
    print("Hash Algorithm available: MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512")
    print ("Version 1.0 Made by Drackk")

def info():
    print ("")
    print ("Information:")
    print ("[*] Options:")
    print ("[*] (-h) info")
    print ("[*] (-v) value")
    print ("[*] (-t) Type [See supported hashes]")
    print ("[*] (-o) output")
    print ("[*] Supported Hashes:")
    print ("[>] md5, sha1, sha224, sha256, sha384, sha512")
    print ("[*] That's all folks!\n")

def CreatingHash(value, hashtype, verbose):
    if "md5" in hashtype:
        h = hashlib.md5(value.encode()).hexdigest()
    elif "sha1" in hashtype:
        h = hashlib.sha1(value.encode()).hexdigest()
    elif "sha224" in hashtype:
        h = hashlib.sha1(value.encode()).hexdigest()
    elif "sha256" in hashtype:
        h = hashlib.sha1(value.encode()).hexdigest()
    elif "sha384" in hashtype:
        h = hashlib.sha1(value.encode()).hexdigest()
    elif "sha512" in hashtype:
        h = hashlib.sha1(value.encode()).hexdigest()
    else:
        print("[-] I think this is not a supported hash type")

def start(argv):
    banner()
    if len(sys.argv) < 3:
        info()
        sys.exit()
    try:
        opts, argv = getopt.getopt(argv, "h:v:t:o")
    except getopt.GetoptError:
        print("[!!] Error on argument ")
        sys.exit()
    for opt, arg in opts:
        if opt == "-h":
            info()
        elif opt == "-v":
            value = arg
        elif opt == "-t":
            value = arg
        else :
            info()

if __name__ == "__main__":
    start(sys.argv)

"""
hash_type = input("Hash type desired : ")
value = input("Value : ")

if hash_type == "MD5":
    encoded_string = value.encode()
    hash_value = hashlib.md5(encoded_string).hexdigest()
    print("MD5 : ", hash_value)

elif hash_type == "SHA1":
    encoded_string = value.encode()
    hash_value = hashlib.sha1(encoded_string).hexdigest()
    print("sha1 : ", hash_value)

elif hash_type == "SHA224":
    encoded_string = value.encode()
    hash_value = hashlib.sha224(encoded_string).hexdigest()
    print("sha224 : ", hash_value)


elif hash_type == "SHA256":
    encoded_string = value.encode()
    hash_value = hashlib.sha256(encoded_string).hexdigest()
    print("sha256 : ", hash_value)


elif hash_type == "SHA512":
    encoded_string = value.encode()
    hash_value = hashlib.sha512(encoded_string).hexdigest()
    print("sha512 : ", hash_value)

else :
    print(" This hash is not available ")

"""