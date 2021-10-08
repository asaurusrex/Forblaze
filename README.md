# Forblaze - A Python Mac Steganography Payload Generator
Author: AsaurusRex

## Disclaimer
DO NOT use this project for purposes other than legitimate red teaming/pentesting jobs, or research.  DO NOT use this for illegal activity of any kind, and know that this project is intended for research purposes and to help advance the missions of both red and blue teams.  

## Purpose
Forblaze is a project designed to provide steganography capabilities to Mac OS payloads.  Using python3, it will build an Obj-C file for you which will be compiled to pull desired encrypted URLs out of the stego file, fetch payloads over https, and execute them directly into memory.  It utilizes custom encryption - it is not cryptographically secure, but purely to thwart analysis by AV engines.  It is a slight deviation on my previously built custom encryption for Windows, called Rubicon, and is more simple in practice.  Forblaze utilizes header and footer bytes to identify where in the stego file your encrypted bytes are, and then decrypts them with a hard-coded key in compile_forblaze.m.  This key can be saved and re-used, with the effect that a different URL could be used to fetch a different payload, and the same compiled forblaze should still be able to execute and process it (provided the header and footer bytes aren't changed, and the new stego file is uploaded to the correct location.) 

## Requirements:
Python3 (only tested with Python3.9+), and some associated Python libraries - pip3 should take care of any python dependencies you need.  In addition, clang will be used for compilation, and forblaze should be run on a mac so that forblaze can be correctly compiled.  

## Usage

usage: forblaze_url.py [-h] [-innocent_path PATH] [-o OUTPUT] [-len_key LENGTH_OF_KEY] [-compile_file COMPILE_FILE]
                       [-url_to_encrypt URL] [-supply_key SUPPLIED_KEY] [-stego_location STEGO_LOCATION]
                       [-compiled_binary COMPILED_BINARY]

Generate stego for implants.

optional arguments:

  -h, --help            show this help message and exit

  -innocent_path PATH   Provide the full path to the innocent file to be used.

  -o OUTPUT             Provide the path where you want your stego file to be placed.

  -len_key LENGTH_OF_KEY
                        Provide a positive integer that will be the length of the key in bytes. Default is 16. Must be between 10 and 50 bytes.


  -url_to_encrypt URL   Provide the URL you want to stick inside the compile file.

  -supply_key SUPPLIED_KEY
                        If you wish to use a specific key, provide it here. It must be in the format: -supply_key "\\x6e\\x60\\x..." - aka two double slashes are needed between each byte,
                        or else it WILL NOT WORK.

  -stego_location STEGO_LOCATION
                        You must provide a location on target where the stego file will reside. It is wise to follow strict full paths: /Users/<>/Documents/file.jpg for example.

  -compiled_binary COMPILED_BINARY
                        Give the name of the compiled binary to extract the URL and run code in memory from the stego file. The default is forblaze.

  -method METHOD        Select which method you wish to use. Method 1 relies on executing a dylib directly into memory, and works with Go payloads as well as regular payloads. Method 2
                        relies on executing a macho file directly into memory, but does not work with Go compiled payloads. Method 3 is method 1 but relies on fetchting the decrypting key
                        over a server, which is more opsec friendly. The default method is 1. NOTE: You still might need to edit the 'module' (aka RunMain) manually depending on your
                        execution method!

  -key_url KEY_URL      Provide the URL to the key to decrypt the stego file.

## Opsec Concerns
Honestly, not too many.  Mac OS detections are still pretty poor, especially for in-memory activity.  As an exercise for the reader, you could also call payload bytes directly vs a URL with some slight modifications to this code.  However, depending on the size of your payload, the encryption piece in the python script might take an unacceptably long time to complete.  

Note: since this code compiles to a Mach-O binary (not a dylib, although that can be changed pretty easily in the code), controls like Gatekeeper will prevent it from executing by default unless you can sign the payload or remove the quarantine attribute.  

I would recommend changing things like the number of random bytes generated from the default, and changing the default header and footer bytes that forblaze uses to find the payload in the stego file (as well as the length of those header and footer bytes to perhaps be more inconspicuous). 

For the best OpSec, I recommend fetching your decryption key from an external server you control - then you can control access to that key strictly, making RE much more difficult.

## Detection/Prevention
Steganography is pretty difficult to detect.  If you know where the stego file is, you can begin to extract the suspect bytes after the end of the normal file EOF (so after "FFD9" for jpegs for example).  These suspect bytes will still include the actual encrypted payload and nonsense random bytes, which would be hard to distinguish from each other unless you possess the header and trailing bytes specified by Forblaze.  You could look through these bytes and look for patterns of repeating bytes, since this is how the header and footer bytes with forblaze tend to work, but a skilled operator could make that more difficult to find than the default.  If a payload is caught you could obviously RE the binary and try to locate the stego file, and then try to use the hard-coded key and headers/footers to reverse the URL being called (or other bytes).  But that all assumes you found the binary by some other means.  


## Testing 
This tool has been tested on various versions of Mac OS, including Big Sur and Catalina (x64 systems).  Please let me know if you have problems. 

## Technical Nitty Gritty

The custom encryption is a basic Caesar cipher, where different bytes of the key are used to shift the bytes of your plaintext bytes.  This is why larger keys aren't NECESSARILY better for your encryption - it depends on the length of your plaintext.  If your plaintext is 50 bytes, and you use a 150 byte key, only the first 50 bytes of your key will be used.  If your plaintext is > 150 bytes however, the longer keys would be more secure.  

The steganography is quite simple: the bytes of your original innocent file  are kept the same, and random bytes (along with your encrypted payload bytes) are appended after these bytes.  These random bytes are by default anywhere between 2 and 2000 in length (this should likely be changed to fit your plaintext size -> larger plaintexts should mean more random bytes are generated).  

The in-memory execution piece is following https://blogs.blackberry.com/en/2017/02/running-executables-on-macos-from-memory, as well as the maisal loader (can't find the link at the moment), with the simple change that instead of reading payload bytes from an on-disk file, they are read over http/https.    


## Contributions/Comments/Criticisms
I am very open to receiving comments and to collaboration!  Hopefully this helps generate useful discussion around the topic of custom crypto, or provides researchers some new insights.  
