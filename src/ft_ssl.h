#include <search.h>

#define OPTION_P (1 << 0) // 00000001
#define OPTION_Q (1 << 1) // 00000010
#define OPTION_R (1 << 2) // 00000100
#define OPTION_S (1 << 3) // 00001000

#define SET_OPTION_P(options) (options |= OPTION_P)
#define SET_OPTION_Q(options) (options |= OPTION_Q)
#define SET_OPTION_R(options) (options |= OPTION_R)
#define SET_OPTION_S(options) (options |= OPTION_S)

typedef struct {
    ENTRY entry;        // constant per execution
    uint8_t options;    // constant per execution
    char * filename;    // null or mutable per execution
    char * message;     // null or mutable per execution
    long message_len;   // null or mutable per execution (uint64_t)
} ft_ssl_context_t;

typedef char * hash_type_t;
typedef void (*hash_function_t)(ft_ssl_context_t *);

void do_md5(ft_ssl_context_t *);
void do_sha256(ft_ssl_context_t *);

const hash_type_t hash_types[] = { "md5", "sha256" }; // possible values for ENTRY key
const hash_function_t hash_functions[] = { do_md5, do_sha256 }; // possible values for ENTRY data