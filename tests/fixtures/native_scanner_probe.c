/* Trusted synthetic boundary probe, never an assessed application executable. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef AEGIS_SEMGREP_PROFILE
#define RULE_FILE "/rules.json"
#define SOURCE_FILE "/repo/safe.js"
#define CHECK_COUNT 16
#else
#define RULE_FILE "/rules"
#define SOURCE_FILE "/repo/safe.env"
#define CHECK_COUNT 13
#endif

int main(void) {
  char config[4096]={0}; int fd=open(RULE_FILE,O_RDONLY);
  if(fd<0 || read(fd,config,sizeof(config)-1)<1)return 90;
  close(fd);
  if(strstr(config,"native_test_flood")) {
    char data[8192];memset(data,'A',sizeof(data));
    for(;;)if(write(1,data,sizeof(data))<0)return 91;
  }
  if(strstr(config,"native_test_wait")) { for(;;)usleep(10000); }
  int checks[CHECK_COUNT];
  checks[0]=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1;
  checks[1]=prctl(PR_GET_SECCOMP,0,0,0,0)==2;
  struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
  struct __user_cap_data_struct caps[2];memset(caps,0,sizeof(caps));
  checks[2]=syscall(SYS_capget,&header,caps)==0 && caps[0].effective==0 && caps[1].effective==0 && caps[0].permitted==0 && caps[1].permitted==0;
  errno=0;fd=socket(AF_INET,SOCK_STREAM,0);checks[3]=fd<0 && errno==EPERM;if(fd>=0)close(fd);
  errno=0;fd=socket(AF_UNIX,SOCK_STREAM,0);checks[4]=fd<0 && errno==EPERM;if(fd>=0)close(fd);
  errno=0;pid_t child=fork();if(child==0)_exit(92);checks[5]=child<0 && errno==EPERM;
  errno=0;checks[6]=unshare(CLONE_NEWUSER)<0 && errno==EPERM;
  errno=0;checks[7]=mount("tmpfs","/tmp","tmpfs",0,NULL)<0 && errno==EPERM;
  errno=0;fd=open(SOURCE_FILE,O_WRONLY|O_TRUNC);checks[8]=fd<0 && errno==EROFS;if(fd>=0)close(fd);
  const char *hidden[]={"/etc/passwd","/proc/self/fd","/run/docker.sock","/var/lib/aegis-controller","/etc/aegis"};
  checks[9]=1;for(unsigned n=0;n<sizeof(hidden)/sizeof(*hidden);n++){fd=open(hidden[n],O_RDONLY);if(fd>=0){checks[9]=0;close(fd);}}
  errno=0;void *memory=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  checks[10]=memory==MAP_FAILED && errno==EPERM;if(memory!=MAP_FAILED)munmap(memory,4096);
  errno=0;memory=mmap(NULL,600UL*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  checks[11]=memory==MAP_FAILED && errno==ENOMEM;if(memory!=MAP_FAILED)munmap(memory,600UL*1024*1024);
  memory=mmap(NULL,4UL*1024*1024*1024,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
#ifdef AEGIS_SEMGREP_PROFILE
  checks[12]=memory==MAP_FAILED && errno==ENOMEM;
  if(memory!=MAP_FAILED)munmap(memory,4UL*1024*1024*1024);
  errno=0;fd=open(RULE_FILE,O_WRONLY|O_TRUNC);checks[13]=fd<0 && errno==EROFS;if(fd>=0)close(fd);
  checks[14]=1;for(int n=3;n<64;n++){errno=0;if(fcntl(n,F_GETFD)!=-1 || errno!=EBADF)checks[14]=0;}
  fd=open("/tmp/noexec-probe",O_WRONLY|O_CREAT|O_EXCL,0500);checks[15]=0;
  if(fd>=0){
    const char script[]="#!/nonexistent-interpreter\n";int wrote=write(fd,script,sizeof(script)-1);close(fd);
    char *const argv[]={"/tmp/noexec-probe",NULL};char *const env[]={NULL};
    errno=0;execve(argv[0],argv,env);checks[15]=wrote==(int)sizeof(script)-1 && errno==EACCES;
  }
#else
  checks[12]=memory!=MAP_FAILED;
  if(memory!=MAP_FAILED){errno=0;checks[12]=mprotect(memory,600UL*1024*1024,PROT_READ|PROT_WRITE)<0 && errno==ENOMEM;munmap(memory,4UL*1024*1024*1024);}
#endif
  const char *names[]={"no_new_privileges","seccomp","no_capabilities","inet_denied","unix_denied","fork_denied","new_namespace_denied","mount_denied","source_readonly","host_paths_absent","shared_memory_denied","writable_memory_bounded",
#ifdef AEGIS_SEMGREP_PROFILE
    "virtual_memory_bounded","root_readonly","inherited_handles_closed","scratch_noexec"
#else
    "reserved_virtual_memory_cannot_bypass_data_limit"
#endif
  };
  int ok=1;printf("{\"checks\":{");for(unsigned n=0;n<CHECK_COUNT;n++){if(n)printf(",");printf("\"%s\":%s",names[n],checks[n]?"true":"false");ok &= checks[n];}printf("}}\n");
  return ok?0:95;
}
