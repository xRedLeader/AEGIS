/* Trusted synthetic boundary probe. Never runs against an application target. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int tcp(int port) {
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0) return -1;
    struct timeval limit={1,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit));
    struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(port)};
    inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
    if(connect(fd,(void*)&address,sizeof(address))<0){close(fd);return -1;}
    return fd;
}

int main(int argc,char **argv) {
    if(argc>1 && !strcmp(argv[1],"/tmp/escape-script")){puts("TMP_ESCAPE");return 0;}
    char config[16385]={0},url[1024]={0},host[128]={0};
    FILE *file=fopen("/rules.yaml","rb"); if(!file)return 9;
    fread(config,1,16384,file);fclose(file);
    file=fopen("/targets","r");if(!file)return 9;fgets(url,sizeof(url),file);fclose(file);
    url[strcspn(url,"\r\n")]=0;
    char *path=strchr(url+7,'/');if(!path)return 9;
    size_t authority=(size_t)(path-(url+7));if(authority>=sizeof(host))return 9;
    memcpy(host,url+7,authority);
    int port=atoi(strrchr(host,':')+1);
    if(strstr(config,"PROBE_NETWORK")) {
        int fd=tcp(port);puts(fd<0?"DIRECT_NETWORK_BLOCKED":"DIRECT_NETWORK_ESCAPE");if(fd>=0)close(fd);
        fd=socket(AF_INET,SOCK_DGRAM,0);puts(fd<0&&errno==EPERM?"UDP_BLOCKED":"UDP_ESCAPE");if(fd>=0)close(fd);
        fd=socket(AF_UNIX,SOCK_STREAM,0);puts(fd<0&&errno==EPERM?"UNIX_BLOCKED":"UNIX_ESCAPE");if(fd>=0)close(fd);
        pid_t child=fork();if(child==0)_exit(1);puts(child<0&&errno==EPERM?"FORK_BLOCKED":"FORK_ESCAPE");if(child>0)waitpid(child,0,0);
        int result=unshare(CLONE_NEWNET);puts(result<0&&errno==EPERM?"UNSHARE_BLOCKED":"UNSHARE_ESCAPE");
        fd=open("/etc/passwd",O_RDONLY);puts(fd<0?"HOST_FILES_BLOCKED":"HOST_FILES_ESCAPE");if(fd>=0)close(fd);
        fd=open("/proc/self/fd",O_RDONLY);puts(fd<0?"PROC_BLOCKED":"PROC_ESCAPE");if(fd>=0)close(fd);
        puts(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1?"NO_NEW_PRIVS":"PRIVILEGE_ESCAPE");
        struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2]={{0},{0}};
        int capresult=syscall(SYS_capget,&header,caps);
        puts(capresult==0&&!(caps[0].effective|caps[0].permitted|caps[0].inheritable|caps[1].effective|caps[1].permitted|caps[1].inheritable)?"CAPABILITIES_DROPPED":"CAPABILITY_ESCAPE");
        fd=open("/tmp/escape-script",O_CREAT|O_WRONLY|O_EXCL,0700);if(fd<0)return 9;
        write(fd,"#!/scanner\n",11);close(fd);fflush(stdout);
        char *args[]={"/tmp/escape-script",NULL};char *env[]={NULL};execve(args[0],args,env);
        puts(errno==EACCES?"TMP_EXEC_BLOCKED":"TMP_EXEC_ESCAPE");
    } else {
        const char *method=strstr(config,"PROBE_METHOD")?"POST":"GET";
        const char *extra=strstr(config,"PROBE_COOKIE")?"Cookie: PRIVATE_PROBE_CANARY\r\n":
                          strstr(config,"PROBE_PROXY_AUTH")?"Proxy-Authorization: PRIVATE_PROBE_CANARY\r\n":
                          strstr(config,"PROBE_BODY")?"Content-Length: 1\r\n":
                          strstr(config,"PROBE_DUPLICATE")?"Content-Length: 0\r\ncontent-length: 0\r\n":"";
        if(strstr(config,"PROBE_ROUTE"))snprintf(url,sizeof(url),"http://%s/unauthorized",host);
        if(strstr(config,"PROBE_ORIGIN")){snprintf(host,sizeof(host),"127.0.0.2:%d",port);snprintf(url,sizeof(url),"http://%s/fixture",host);}
        int concurrent=strstr(config,"PROBE_CONCURRENT")!=NULL,pending[2]={-1,-1};
        int repeats=strstr(config,"PROBE_REPEAT")||concurrent?2:1;
        for(int index=0;index<repeats;index++){
            if(concurrent)snprintf(url,sizeof(url),"http://%s/medium%d",host,index+1);
            int fd=tcp(18464);if(fd<0)return 8;
            char request[4096];int length=snprintf(request,sizeof(request),"%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n",method,url,host,extra);
            if(strstr(config,"PROBE_PIPELINE")){memcpy(request+length,request,(size_t)length);length*=2;}
            if(write(fd,request,(size_t)length)!=length)return 7;
            if(concurrent){pending[index]=fd;continue;}
            char response[1024];while(read(fd,response,sizeof(response))>0){}close(fd);
        }
        for(int index=0;index<2;index++)if(pending[index]>=0){char response[1024];while(read(pending[index],response,sizeof(response))>0){}close(pending[index]);}
    }
    file=fopen("/tmp/report.json","w");if(!file)return 6;fputs(strstr(config,"PROBE_CONCURRENT")?"[":"[]",file);fclose(file);return 0;
}
