#ifndef PYTHON_CLIENT_LIBRARY_H
#define PYTHON_CLIENT_LIBRARY_H

extern "C" {
int __attribute__ ((visibility ("default"))) init(const char *version);
int __attribute__ ((visibility ("default"))) destroy();

void __attribute__ ((visibility ("default"))) log_info(const char *message);
void __attribute__ ((visibility ("default"))) log_error(const char *message);

int __attribute__ ((visibility ("default"))) pop_message(char *buffer);
int __attribute__ ((visibility ("default"))) post_message(const char *message);
}

#endif //PYTHON_CLIENT_LIBRARY_H
