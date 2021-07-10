#include "library.h"
#include "client/smith_client.h"
#include <common/log.h>

int init(const char *version) {
    INIT_FILE_LOG(INFO, "python-client");

    gSmithClient->mVersion = version;
    return gSmithClient->start() ? 0 : -1;
}

void log_info(const char *message) {
    LOG_INFO("python info: %s", message);
}

void log_error(const char *message) {
    LOG_ERROR("python error: %s", message);
}

int destroy() {
    return gSmithClient->stop() ? 0 : -1;
}

int post_message(const char *message) {
    return gSmithClient->writeBuffer(message) ? 0 : -1;
}

int pop_message(char *buffer) {
    // buffer size need > 10240 - PROTOCOL_MAX_SIZE
    std::string message;

    if (!gSmithClient->fetch(message)) {
        LOG_INFO("no message");
        return -1;
    }

    strcpy(buffer, message.c_str());

    return 0;
}
