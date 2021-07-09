#include "library.h"
#include <cstring>
#include <unistd.h>

int main() {
    init("2.7");

    log_info("python rasp start");
    log_error("this is error log example");

    for (int i = 0; i < 1000; i++)
        post_message("hello world");

    sleep(10);

    for (int i = 0; i < 1000; i++) {
        char message[10240] = {};
        pop_message(message);

        if (strlen(message) == 0) {
            log_info("no more message");
            break;
        }

        log_info(message);
    }

    destroy();

    return 0;
}
