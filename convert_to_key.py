#!/usr/bin/python3
import os

def main():

    key = b"\x6d\x75\xd5\x3e\x5f\xb4\x8c\xca\xca\x03\x81\xec\x4c\x68\x64\x63\x57\xb2\xf5\xc8\x03\xa9\x46\xa3\x56\x7c\xe9\xa7\xf5\xaa\xba\xe8\x68\xf4\xe9"

    #temp_key = key.replace('\\x', ' ')
    #key_bytes = bytearray.fromhex(key)


    with open('key', 'wb') as f:
        f.write(key)
        

if __name__ == '__main__':
    main()
