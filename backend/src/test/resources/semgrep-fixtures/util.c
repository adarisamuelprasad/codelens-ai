#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet(const char *name) {
    char buf[32];
    char line[64];
    // codelens-expect: UNSAFE_BUFFER_FUNCTION
    strcpy(buf, name);
    strcpy(buf, "guest");
    strncpy(buf, name, sizeof(buf) - 1);
    // codelens-expect: UNSAFE_BUFFER_FUNCTION
    sprintf(line, "hello %s", name);
    snprintf(line, sizeof(line), "hello %s", name);
    sprintf(line, "%d items", 3);
    // codelens-expect: UNSAFE_BUFFER_FUNCTION
    scanf("%s", buf);
    scanf("%31s", buf);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping %s", name);
    // codelens-expect: COMMAND_INJECTION
    system(cmd);
    system("clear");
}
