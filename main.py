import hashlib
import sys
import pyfiglet

ascii_banner = pyfiglet.figlet_format("BringMeTheHash")
print(ascii_banner)

print("Hash Algorithm available : MD5 | SHA1 ")

hash_type = str(input("Hash type : "))
wordlist = str(input("Enter wordlist location"))
hash_value = str(input("Hash value"))

word_list = open(f"(wordlist)").read()
lists = word_list.splitlines

for word in lists:
    if hash_type == "MD5":
        hash_object = hashlib.md5(f"{word}".encode('utf-8'))
        hashed = hash_object.hexdigest()
        if hash_value == hashed:
            print(f"\033[1;32m HASH FOUND: {word} \n]")
            
    elif hash_type =="SHA1":
        hash_object = hashlib.sha1(f"{word}".encode('utf-8'))
        hashed = hash_object.hexdigest()
        if hash_value == hashed:
            print(f"\033[1;32m HASH FOUND: {word} \n]")
    else :
        print("Please choose an available option")