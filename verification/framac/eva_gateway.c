#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "__fc_builtin.h"

#define MAX_FDS 100000
#define BUFFER_SIZE 16384

typedef enum {
    SESS_TLS_HANDSHAKE,
    SESS_CONNECT_BACK,
    SESS_ACTIVE_PUMP,
    SESS_DRAINING
} SessState;

typedef struct {
    int c_fd;
    int u_fd;
    SessState state;
    
    char c2u_buf[BUFFER_SIZE];
    int c2u_len;
    
    char u2c_buf[BUFFER_SIZE];
    int u2c_len;
} Session;

// Frama-C Eva Abstract Abstraction of Gateway Logic
static const char GET_VERB[] = "GET ";
static const char POST_VERB[] = "POST ";
static const char MIGRATION_ROUTE[] = "/api/migration/";
static const char HTTP_VER[] = " HTTP/1.";

void send_403_forbidden(Session *s) {
    if (s->u_fd > 0) {
        s->u_fd = -1;
    }
    
    const char err403[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    int err_len = 64;
    
    s->u2c_len = 0; 
    
    if (s->u2c_len + err_len < BUFFER_SIZE) {
        for(int k = 0; k < err_len; k++) {
            s->u2c_buf[s->u2c_len + k] = err403[k];
        }
        s->u2c_len += err_len;
    }
    
    s->state = SESS_DRAINING;
}

void handle_client_in_mock(Session *s) {
    if (s->c2u_len > 4) {
        bool is_get = true;
        bool is_post = true;
        for(int k = 0; k < 4; k++) { if (s->c2u_buf[k] != GET_VERB[k]) is_get = false; }
        for(int k = 0; k < 5; k++) { if (s->c2u_buf[k] != POST_VERB[k]) is_post = false; }
        
        if (is_get || is_post) {
            int scan_len = s->c2u_len < 4096 ? s->c2u_len : 4096;
            
            for(int i = 0; i <= scan_len - 15; i++) {
                bool match = true;
                for(int m = 0; m < 15; m++) { if (s->c2u_buf[i + m] != MIGRATION_ROUTE[m]) match = false; }
                if (match) {
                    return; // Valid route
                }
            }
            
            for(int j = 0; j <= scan_len - 8; j++) {
                bool match = true;
                for(int m = 0; m < 8; m++) { if (s->c2u_buf[j + m] != HTTP_VER[m]) match = false; }
                if (match) {
                    send_403_forbidden(s);
                    return;
                }
            }
        }
    }
}

// Eva Abstract State Generator
void main(void) {
    Session s;
    
    // Abstractly initialize the global structs across valid bounds safely
    s.c_fd = Frama_C_interval(1, 100);
    s.u_fd = Frama_C_interval(-1, 200);
    s.state = SESS_ACTIVE_PUMP;
    
    s.c2u_len = Frama_C_interval(0, BUFFER_SIZE - 1);
    s.u2c_len = Frama_C_interval(0, BUFFER_SIZE - 1);
    
    // Instantiate random HTTP payload abstraction natively
    for (int idx = 0; idx < s.c2u_len; idx++) {
        s.c2u_buf[idx] = Frama_C_char_interval(0, 127);
    }
    s.c2u_buf[s.c2u_len] = '\0'; // Null boundary terminator
    
    handle_client_in_mock(&s);
}
