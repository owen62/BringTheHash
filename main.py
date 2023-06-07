import hashlib
import pyfiglet


ascii_banner = pyfiglet.figlet_format("BringMeTheHash")
print(ascii_banner)

print("Hash Algorithm available: MD5 | SHA1")

hash_type = input(" Hash type desired : ")
value = input(" Value : ")

if hash_type == "MD5":
    encoded_string = value.encode()
    hash_value = hashlib.md5(encoded_string).hexdigest()
    print("MD5 : ", hash_value)
