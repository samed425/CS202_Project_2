#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#define MAX_PROC 10

struct pinfo {
    int ppid;
    int syscall_count;
    int page_usage;
};

int main(int arc, char *argv[]){

    struct pinfo param;
    param.ppid = 4001;
    param.page_usage = 782;
    param.syscall_count = 200;
    int result = procinfo(&param);


    printf("\n Parent id is %d", param.ppid);
    printf("\n number of page usages is %d", param.page_usage);
    printf("\n number of system calls made by the current process is: %d", param.syscall_count);
    printf("\n Result is: %d", result);

    exit(0);
}