#include <stdbool.h>
#include <stdint.h>
#include <string.h>

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



static const char GET_VERB[] = "GET ";
static const char POST_VERB[] = "POST ";
static const char MIGRATION_ROUTE[] = "/api/migration/";
static const char HTTP_VER[] = " HTTP/1.";

/* ACSL Formal Specifications for L7 Application Firewall Routing */

/*@
  requires \valid(s);
  requires 0 <= s->c2u_len <= BUFFER_SIZE;
  requires 0 <= s->u2c_len <= BUFFER_SIZE;
  assigns s->state, s->u_fd, s->u2c_len, s->u2c_buf[s->u2c_len .. s->u2c_len + 70];
  ensures s->state == SESS_DRAINING;
  ensures s->u_fd == -1;
  ensures s->u2c_len <= BUFFER_SIZE;
*/
void send_403_forbidden(Session *s) {
    if (s->u_fd > 0) {
        s->u_fd = -1;
    }
    
    const char *err403 = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    int err_len = 69; // sizeof("...") - 1 statically derived
    
    s->u2c_len = 0; 
    
    if (s->u2c_len + err_len < BUFFER_SIZE) {
        /*@ loop invariant 0 <= k <= err_len;
            loop invariant s->u2c_len == \at(s->u2c_len, Pre);
            loop assigns k, s->u2c_buf[s->u2c_len .. s->u2c_len + err_len - 1];
            loop variant err_len - k;
        */
        for(int k = 0; k < err_len; k++) {
            s->u2c_buf[s->u2c_len + k] = err403[k];
        }
        s->u2c_len += err_len;
    }
    
    s->state = SESS_DRAINING;
}

/*@
  requires \valid(s);
  requires 0 <= s->c2u_len <= BUFFER_SIZE;
  requires 0 <= s->u2c_len <= BUFFER_SIZE;
  requires \valid_read(s->c2u_buf + (0 .. BUFFER_SIZE - 1));
  assigns s->state, s->u_fd, s->u2c_len, s->u2c_buf[0 .. BUFFER_SIZE - 1];
*/
void handle_client_in_mock(Session *s) {
    bool is_get = true;
    bool is_post = true;
    /*@ loop invariant 0 <= k <= 4;
        loop assigns k, is_get;
        loop variant 4 - k;
    */
    for(int k = 0; k < 4; k++) { if (s->c2u_buf[k] != GET_VERB[k]) is_get = false; }
    
    /*@ loop invariant 0 <= k <= 5;
        loop assigns k, is_post;
        loop variant 5 - k;
    */
    for(int k = 0; k < 5; k++) { if (s->c2u_buf[k] != POST_VERB[k]) is_post = false; }
    
    if (s->c2u_len > 4 && (is_get || is_post)) {
        
        int scan_len = s->c2u_len < 4096 ? s->c2u_len : 4096;
        
        /*@ assert \valid_read(MIGRATION_ROUTE + (0 .. 14)); */
        /*@ loop invariant 0 <= i <= scan_len - 15;
            loop assigns i;
            loop variant scan_len - 15 - i;
        */
        for(int i = 0; i <= scan_len - 15; i++) {
            bool match = true;
            /*@ loop invariant 0 <= m <= 15;
                loop assigns m, match;
                loop variant 15 - m;
            */
            for(int m = 0; m < 15; m++) { if (s->c2u_buf[i + m] != MIGRATION_ROUTE[m]) match = false; }
            if (match) {
                return; // Valid route
            }
        }
        
        /*@ assert \valid_read(HTTP_VER + (0 .. 7)); */
        /*@ loop invariant 0 <= j <= scan_len - 8;
            loop assigns j;
            loop variant scan_len - 8 - j;
        */
        for(int j = 0; j <= scan_len - 8; j++) {
            bool match = true;
            /*@ loop invariant 0 <= m <= 8;
                loop assigns m, match;
                loop variant 8 - m;
            */
            for(int m = 0; m < 8; m++) { if (s->c2u_buf[j + m] != HTTP_VER[m]) match = false; }
            if (match) {
                // Synthesize Reject
                send_403_forbidden(s);
                return;
            }
        }
    }
}
