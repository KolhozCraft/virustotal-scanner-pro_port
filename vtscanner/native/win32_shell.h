#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VtHttpResponse {
    int status;
    int network_error;
    int timed_out;
    char* body;
    size_t body_len;
} VtHttpResponse;

enum { VT_TRAY_SHOW = 1, VT_TRAY_EXIT = 2 };

typedef void (*VtTrayCallback)(int event, void* user);

void f3un4d5fjcu(char* s);

char* f6nep1f9o7n(void);
char* fjdckhr30rn(const char* plain_utf8);
char* f2funfd6n3n(const char* base64_utf8);
int f3uktifcxgm(int enable);

void* ffzma9z86zi(void);
char* fkzznls4w30(void* owner);
void f32pnbb7me8(const char* url_utf8);
void f9jwldhl375(const char* text_utf8);
void fksaxrq228o(void);
void fy4vo2fr45h(void);

void ffy9yybo2ia(const char* url_utf8, const char* api_key_utf8, int timeout_ms, VtHttpResponse* out);
void f1t55yc0vd7(const char* url_utf8, const char* api_key_utf8, const char* file_path_utf8,
                       const char* field_name, const char* file_name_utf8, int timeout_ms,
                       VtHttpResponse* out);
void fs064iemdmn(VtHttpResponse* r);

int fuw8nd6w1gk(VtTrayCallback callback, void* user, const char* tooltip_utf8,
                   const char* show_label_utf8, const char* exit_label_utf8);
void f8tgjs2kv3w(const char* show_label_utf8, const char* exit_label_utf8);
void fcn40nf3rzw(void);

#ifdef __cplusplus
}
#endif
