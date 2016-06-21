# A small linux rootkit works on kernel 4.0.X #

## About ##
### liinux_vfs.c ###
It works with the backdoor using inline hook in vfs, hides the process of backdoor and grants root privileges for it.It also hides itself in kernel modules and hides itself and backdoor in file system, but no network connection hiding yet.

You can modify it to hides other files or modules or processes and grant root privileges for them.

### bd.c ###
A backdoor which provide you a shell with root privileges and move itself with lkm into target directory to hide better.

### liinux_syscall.c ###
It is just a sample with hijack system call of write in sys_call_table to hide target file. Because sys_call_table is not export symbol any more since kernel 2.6.x, it get its address by define a kernel memory range then brute force it.


## Usage ##
Make sure you have kernel header files. If not, get them with shell command:

```sudo apt-get install linux-headers-$(uname -r)```

After that you can edit some configurations in liinux_vfs.c and bd.c such as listening port, filename  that should be hidden etc. Compile the rootkit with Makefile and backdoor with gcc.

Then use "insmod " to load the rootkit and execute the backdoor.

## Notes ##
It should works on kernel version 4.0.X or higher. I test it on kernel 4.0.0, x64 and it works fine.  
