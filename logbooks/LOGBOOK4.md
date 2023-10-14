# LOGBOOK 4

This lab intends to show how environment variables affect program and system behaviors. Environment variables are dynamic values that are set at the operating system level and are used by various applications and processes to configure their behavior or access specific resources. They are essentially named values that can be accessed by programs during runtime, allowing for customization and configuration.

To complete this lab, we followed the instructions available on the [SEED Labs – Environment Variable and Set-UID Program Lab](https://seedsecuritylabs.org/Labs_20.04/Files/Environment_Variable_and_SetUID/Environment_Variable_and_SetUID.pdf), and draw our conclusions by analyzing the results at the end of each task, both of which we will present here in this logbook.


## Task 1: Manipulating Environment Variables

In this task, we explored the usage of `printenv` and `env` commands, both of which display in the Bash a list of the environment variables and their assigned values.

![printenv and env](./images/logbook-4/log4_img1.png){width=50%}

*Figure 1. Output of printenv command*

If instead of the whole list of pairs name/value of the environment variables we wish to know the value for a specific environment variable we can add the variables name as an argument to the `printenv` command (or by using the `grep` command to search for a match of the environment variables name in the list produced by the  env command). In the following image we printed the value of the USER and LANG environment variables:

![printenv and env](./images/logbook-4/log4_img4.png){width=25%}

*Figure 2. Output of printenv command*

We manipulated environment variables values through bash's `export` and `unset` commands. With the `unset` commant we are able to delete variables and with `export` we can create or modify environment variables.

![unset and export](./images/logbook-4/log4_img2.png){width=30%}

*Figure 3. Example of export and unset*

It is worth mentioning that any changes applied to the environment variables are specific only to the current session, and therefore such changes won't be reflected in a new terminal session, as exemplified in the following image:

![unset and export](./images/logbook-4/log4_img3.png){width=35%}

*Figure 4. Changes applied in the Bash session above are not applicable to a new session*


## Task 2: Passing Environment Variables from Parent Process to Child Process

For task 2, we followed the steps indicated, in order to better understand how a child process gets its environment variables from its parent.

### Step 1

- After compiling and running myprintenv.c program, we were able to observe that the output of this program was the same as the output of the `printenv` or `env` commands. By analyzing the myprintenv.c code, we were able to understand that the program itself is calling the printenv() command. More specifically, the program is creating a **child process** by calling `fork()` and printing its environment variables. 

![t2_step1](./images/logbook-4/t2_step1.png){width=45%}

*Figure 5. Output of myprintenv.c program*

### Step 2
- A child process is a duplicate of its parent (the calling process), and as suggested by the seed lab, we checked the manual of `fork()` and realized that there were a few things in which a child process differes from its parent. 
- In step1, we were printing out the environment variables of a child process and now in step2, we commented out the printenv() statement in the child process case and uncommented the printenv() statement in the parent process case. After compiling and running the code again, the program was once more outputting a list of environment variables, but this time the variables printed belonged to the **parent process** and not to the child process.

### Step 3
- At the end of both step 1 and step 2, the output of the program was saved in files step1.txt and step2.txt respectively. Therefore, in step1.txt file was a list of the environment variables of the child process and in step2.txt file was a list of the environment variables of the parent process. We used `diff` command to check the differences between this two files, and no differences were found.
- **We concluded that the environment variables were in fact being inherited by the child process.**

![t2_step3](./images/logbook-4/t2_step3.png){width=40%}

*Figure 6. Result of diff command*


## Task 3: Environment Variables and execve()

In this task we explored what happens to environment variables when a new program is executed via `execve()`.

### Step 1

In step 1, we compiled and ran myenv.c program. Through the use of `execve()` function, myenv.c executes a program called /usr/bin/env. This causes the program currently being run to be replaced with the /usr/bin/env program, which according to the seed lab guide, is supposed to print out the environment variables of the current process.

The `execve()` function receives 3 arguments: 
- *pathname* - a pathname (which is the program to be executed);
- *argv[]* - an array of pointers to strings passed to the new program;
- *envp* - an array of pointers which are passed as the environment of the new program;

There was no output in the terminal after running myenv.c, and we believe this behaviour can be explained by the fact that myenv.c is passing a NULL pointer to the third argument of `execve()` function, and therefore no environment variables are printed.


![t3_step1](./images/logbook-4/t3_step1.png){width=45%}

*Figure 7. Output of myenv.c program with NULL value*


### Step 2

For step 2, we had to modify the invocation of `execve()`. This time, instead of the NULL value, the **environ variable** was passed as the third argument to execve(), which is an array of pointers to the environment variables of the calling process. After this change, when we execute myenv.c, the program prints out the environment variables of the current process.

![t3_step2](./images/logbook-4/t3_step2.png){width=48%}

*Figure 8. Output of myenv.c program with environ value*


### Step 3

**We were able to conclude that when the new program is executed via `execve()`, it has access to the environment variables of the calling process and inherits those variables.**


## Task 4: Environment Variables and system()

In task 4 we learned what happens to environment variables when a new program is executed via `system()` function. This function can be used to execute a program just like `execve()`, but they work in different ways. 
While `execve()` directly excutes a command and replaces the currently running program with a new one, `system()` function uses `fork` to create a child process that will invoke the shell and that shell executes the specified command. The child process executes the shell with `execve()` function, which means that this shell program will have the same environment variables of the calling process.

![task4](./images/logbook-4/step4.png){width=45%}

*Figure 9. Output after running seed labs system code*


## Task 5: Environment Variable and Set-UID Programs

This task's goal is to understand how Set-UID programs are affected by environment variables and whether they are inherited by the Set-UID program’s process from the user’s process.

**Set-UID is a security mechanism** in Unix that allows programs to have the same privileges of the program's owner. For instance, if the program's owner is root, the program gains root's privileges when executed.

This means that even if a normal user without any special privileges runs a Set-UID program whose owner has for instance, administrative priveleges over the system, **the program will also have administrative priveleges even though the user that is running it, does not**.


### Step 1

We followed the instructions and wrote the code below from the seed labs guide to a file named foo.c


```c
#include <stdio.h>
#include <stdlib.h>
extern char **environ;

int main()
{
  int i = 0;
  while (environ[i] != NULL) {
   printf("%s\n", environ[i]);
   i++;
  }
}
```

### Step 2

Next, we compiled foo.c and ran it, and the output was all the environment variables of the current process. After that, we **changed the program's ownership to root** with the command `sudo chown root foo` (*chown*: change owner) **and made it a Set-UID program** with the command `sudo chmod 4755 foo` (*chmod*: change mode; *4755*: sudothe permissions set). We also ran `ls -l foo` before and after applying these changes in order to see in the terminal the difference in the permissions of the file.

![task4_step2](./images/logbook-4/task5_st2.png){width=35%}

*Figure 10. Before and after of the permissions of foo*

After making this chages we ran foo again to check if there were any differences in the output of the environment variables, but there were none.


### Step 3

For step 3, we used the `export` command to set *PATH* and *LD_LIBRARY_PATH* environment variables, as well as one made up by us called *MYENV*:


```bash
$ export PATH="task5":$PATH
$ export LD_LIBRARY_PATH="task5"
$ export MYENV="task5"
```

Afterwards, we ran again the Set-UID program foo from Step 2 and checked if the environment variables we setted previously had been inherited by the Set-UID child process. We were able to confirm that **all variables were inherited except LD_LIBRARY_PATH**. 

![task5_final](./images/logbook-4/task5_final.png){width=45%}

*Figure 11. Environment variables PATH, LD_LIBRARY_PATH and MYENV*

LD_LIBRARY_PATH specifies a list of directories where shared libraries are searched for by the dynamic link loader, and inheriting this environmental variable could lead to security issues. This is because inheriting LD_LIBRARY_PATH could enable the child process to load shared libraries from directories unintended by the original user or that could have been maliciously altered.



## Task 6: The PATH Environment Variable and Set-UID Programs

In task 6, we compiled and ran the program below (named task6.c), that should execute the `ls` command (/bin/ls). However, the system() function is using a relative path for the ls command, making it vulnerable to manipulation of the PATH environment variable. PATH is an environment variable that specifies a set of directories where executable programs are located.

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
  system("ls");
  return 0;
}
```

The output of task6 was, as expected, simply the list of content of the current directory. We changed the program's owner to root and made it a Set-UID program. 

Afterwards, we created a not so well intended program named bad_ls.c that would print the message "I'm a naughty ls instead". 

```C
#include <stdio.h>
#include <stdlib.h>

int main() {
  printf("I'm a naughty ls instead\n");
  return 0;
}
```

We compiled it and named the executable "ls". We then manipulated `PATH` environment variable, in order to include the directory of our programs executable. Afterwards, we ran task.c again, and this time, the output was the message "I'm a naughty ls instead". This is because when we compiled the program, the `PATH` variable now is including the directory of our 'ls' executable, and so when the task6.c program tries to execute `ls` through `system()`, it will load our 'ls' binary instead.


![task_6](./images/logbook-4/task_6.png){width=45%}

*Figure 12. Task 6*