#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main () {

    int i = 15;
    while (1) {
        printf("ping\n");
        sleep(i);
    }
        
    return 0;
}
