/*
 * s2n_wrapper.h - C wrappers for s2n-tls functions
 *
 * These wrappers capture error information from thread-local storage
 * immediately after s2n function calls, making error handling safe
 * for Haskell FFI where TLS can be unreliable.
 */

#ifndef S2N_WRAPPER_H
#define S2N_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

/* Size of the owned debug string buffer in S2nErrorInfo */
#define S2N_ERROR_DEBUG_STRING_SIZE 256

/*
 * Error Functions Struct
 * Holds pointers to s2n error functions, loaded first during initialization.
 * These are used by all wrappers to capture error information.
 */
typedef struct
{
    int *(*errno_location)(void);
    const char *(*strerror_debug)(int error, const char *lang);
} S2nErrorFuncs;

/*
 * Error Info Output Struct
 * Populated by wrappers on failure with full error information.
 * Uses an owned buffer for the debug string since s2n's string pointers
 * are ephemeral and may become invalid.
 */
typedef struct
{
    int error_code;
    char debug_string[S2N_ERROR_DEBUG_STRING_SIZE];
} S2nErrorInfo;

/*
 * Helper macro to populate error info on failure.
 * Copies the debug string into the owned buffer.
 */
#define S2N_FILL_ERROR(err_funcs, err_out)                                           \
    do                                                                               \
    {                                                                                \
        (err_out)->error_code = *(err_funcs)->errno_location();                      \
        const char *_dbg = (err_funcs)->strerror_debug((err_out)->error_code, "EN"); \
        if (_dbg)                                                                    \
        {                                                                            \
            strncpy((err_out)->debug_string, _dbg, S2N_ERROR_DEBUG_STRING_SIZE - 1); \
            (err_out)->debug_string[S2N_ERROR_DEBUG_STRING_SIZE - 1] = '\0';         \
        }                                                                            \
        else                                                                         \
        {                                                                            \
            (err_out)->debug_string[0] = '\0';                                       \
        }                                                                            \
    } while (0)

/* ============================================================================
 * Wrapper Function Declarations
 * ============================================================================
 * Each wrapper takes:
 * - Function pointer to the underlying s2n function
 * - Same arguments as the original function
 * - Pointer to S2nErrorFuncs struct
 * - Pointer to S2nErrorInfo output struct
 * Returns the same type as the underlying function.
 */

/* --- Initialization & Cleanup --- */
int s2n_wrap_init(
    int (*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cleanup(
    int (*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cleanup_final(
    int (*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_crypto_disable_init(
    int (*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_disable_atexit(
    int (*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* s2n_get_openssl_version returns long, no error - no wrapper needed */
/* s2n_get_fips_mode takes output param */
int s2n_wrap_get_fips_mode(
    int (*fn)(int *),
    int *fips_mode,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Stack Traces --- */
/* s2n_stack_traces_enabled returns bool, no wrapper needed */

int s2n_wrap_stack_traces_enabled_set(
    int (*fn)(int),
    int enabled,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_calculate_stacktrace(
    int (*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_free_stacktrace(
    int (*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_get_stacktrace(
    int (*fn)(void *),
    void *stacktrace,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Config Management --- */
void *s2n_wrap_config_new(
    void *(*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

void *s2n_wrap_config_new_minimal(
    void *(*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_free(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_free_dhparams(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_free_cert_chain_and_key(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_wall_clock(
    int (*fn)(void *, void *, void *),
    void *config, void *clock_fn, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_monotonic_clock(
    int (*fn)(void *, void *, void *),
    void *config, void *clock_fn, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Cache Callbacks --- */
int s2n_wrap_config_set_cache_store_callback(
    int (*fn)(void *, void *, void *),
    void *config, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_cache_retrieve_callback(
    int (*fn)(void *, void *, void *),
    void *config, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_cache_delete_callback(
    int (*fn)(void *, void *, void *),
    void *config, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Memory & Random Callbacks --- */
int s2n_wrap_mem_set_callbacks(
    int (*fn)(void *, void *, void *, void *),
    void *init_cb, void *cleanup_cb, void *malloc_cb, void *free_cb,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_rand_set_callbacks(
    int (*fn)(void *, void *, void *, void *),
    void *init_cb, void *cleanup_cb, void *seed_cb, void *mix_cb,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Certificate Chain Management --- */
void *s2n_wrap_cert_chain_and_key_new(
    void *(*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_and_key_load_pem(
    int (*fn)(void *, const char *, const char *),
    void *chain_and_key, const char *chain_pem, const char *private_key_pem,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_and_key_load_pem_bytes(
    int (*fn)(void *, const uint8_t *, uint32_t, const uint8_t *, uint32_t),
    void *chain_and_key, const uint8_t *chain_pem, uint32_t chain_pem_len,
    const uint8_t *private_key_pem, uint32_t private_key_pem_len,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_and_key_load_public_pem_bytes(
    int (*fn)(void *, const uint8_t *, uint32_t),
    void *chain_and_key, const uint8_t *chain_pem, uint32_t chain_pem_len,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_and_key_free(
    int (*fn)(void *),
    void *chain_and_key,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_and_key_set_ctx(
    int (*fn)(void *, void *),
    void *chain_and_key, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

void *s2n_wrap_cert_chain_and_key_get_ctx(
    void *(*fn)(void *),
    void *chain_and_key,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

void *s2n_wrap_cert_chain_and_key_get_private_key(
    void *(*fn)(void *),
    void *chain_and_key,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_and_key_set_ocsp_data(
    int (*fn)(void *, const uint8_t *, uint32_t),
    void *chain_and_key, const uint8_t *data, uint32_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_and_key_set_sct_list(
    int (*fn)(void *, const uint8_t *, uint32_t),
    void *chain_and_key, const uint8_t *data, uint32_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_cert_tiebreak_callback(
    int (*fn)(void *, void *),
    void *config, void *callback,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_add_cert_chain_and_key(
    int (*fn)(void *, const char *, const char *),
    void *config, const char *chain_pem, const char *private_key_pem,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_add_cert_chain_and_key_to_store(
    int (*fn)(void *, void *),
    void *config, void *chain_and_key,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_cert_chain_and_key_defaults(
    int (*fn)(void *, void **, uint32_t),
    void *config, void **chain_and_key_array, uint32_t count,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Trust Store --- */
int s2n_wrap_config_set_verification_ca_location(
    int (*fn)(void *, const char *, const char *),
    void *config, const char *ca_pem_filename, const char *ca_dir,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_add_pem_to_trust_store(
    int (*fn)(void *, const char *),
    void *config, const char *pem,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_wipe_trust_store(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_load_system_certs(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_cert_authorities_from_trust_store(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Verification & Validation --- */
int s2n_wrap_config_set_verify_after_sign(
    int (*fn)(void *, int),
    void *config, int mode,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_check_stapled_ocsp_response(
    int (*fn)(void *, uint8_t),
    void *config, uint8_t check,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_disable_x509_time_verification(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_disable_x509_verification(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_max_cert_chain_depth(
    int (*fn)(void *, uint16_t),
    void *config, uint16_t depth,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_verify_host_callback(
    int (*fn)(void *, void *, void *),
    void *config, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- DH Parameters --- */
int s2n_wrap_config_add_dhparams(
    int (*fn)(void *, const char *),
    void *config, const char *dhparams_pem,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Security Policies & Preferences --- */
int s2n_wrap_config_set_cipher_preferences(
    int (*fn)(void *, const char *),
    void *config, const char *version,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_append_protocol_preference(
    int (*fn)(void *, const uint8_t *, uint8_t),
    void *config, const uint8_t *protocol, uint8_t protocol_len,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_protocol_preferences(
    int (*fn)(void *, const char **, int),
    void *config, const char **protocols, int protocol_count,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_status_request_type(
    int (*fn)(void *, int),
    void *config, int type,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_ct_support_level(
    int (*fn)(void *, int),
    void *config, int level,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_alert_behavior(
    int (*fn)(void *, int),
    void *config, int behavior,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Extension Data --- */
int s2n_wrap_config_set_extension_data(
    int (*fn)(void *, int, const uint8_t *, uint32_t),
    void *config, int extension_type, const uint8_t *data, uint32_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_send_max_fragment_length(
    int (*fn)(void *, int),
    void *config, int mfl_code,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_accept_max_fragment_length(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Session & Ticket Configuration --- */
int s2n_wrap_config_set_session_state_lifetime(
    int (*fn)(void *, uint64_t),
    void *config, uint64_t lifetime,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_session_tickets_onoff(
    int (*fn)(void *, uint8_t),
    void *config, uint8_t enabled,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_session_cache_onoff(
    int (*fn)(void *, uint8_t),
    void *config, uint8_t enabled,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_ticket_encrypt_decrypt_key_lifetime(
    int (*fn)(void *, uint64_t),
    void *config, uint64_t lifetime,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_ticket_decrypt_key_lifetime(
    int (*fn)(void *, uint64_t),
    void *config, uint64_t lifetime,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_add_ticket_crypto_key(
    int (*fn)(void *, const uint8_t *, uint32_t, const uint8_t *, uint32_t, uint64_t),
    void *config, const uint8_t *name, uint32_t name_len,
    const uint8_t *key, uint32_t key_len, uint64_t intro_time_in_seconds_from_epoch,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_require_ticket_forward_secrecy(
    int (*fn)(void *, int),
    void *config, int enabled,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Buffer & I/O Configuration --- */
int s2n_wrap_config_set_send_buffer_size(
    int (*fn)(void *, uint32_t),
    void *config, uint32_t size,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_recv_multi_record(
    int (*fn)(void *, int),
    void *config, int enabled,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Miscellaneous Config --- */
int s2n_wrap_config_set_ctx(
    int (*fn)(void *, void *),
    void *config, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_get_ctx(
    int (*fn)(void *, void **),
    void *config, void **ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_client_hello_cb(
    int (*fn)(void *, void *, void *),
    void *config, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_client_hello_cb_mode(
    int (*fn)(void *, int),
    void *config, int mode,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_max_blinding_delay(
    int (*fn)(void *, uint32_t),
    void *config, uint32_t max_delay,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_get_client_auth_type(
    int (*fn)(void *, int *),
    void *config, int *auth_type,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_client_auth_type(
    int (*fn)(void *, int),
    void *config, int auth_type,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_initial_ticket_count(
    int (*fn)(void *, uint8_t),
    void *config, uint8_t count,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_psk_mode(
    int (*fn)(void *, int),
    void *config, int mode,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_psk_selection_callback(
    int (*fn)(void *, void *, void *),
    void *config, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_async_pkey_callback(
    int (*fn)(void *, void *),
    void *config, void *callback,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_async_pkey_validation_mode(
    int (*fn)(void *, int),
    void *config, int mode,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_session_ticket_cb(
    int (*fn)(void *, void *, void *),
    void *config, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_key_log_cb(
    int (*fn)(void *, void *, void *),
    void *config, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_enable_cert_req_dss_legacy_compat(
    int (*fn)(void *),
    void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_server_max_early_data_size(
    int (*fn)(void *, uint32_t),
    void *config, uint32_t size,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_early_data_cb(
    int (*fn)(void *, void *),
    void *config, void *callback,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_get_supported_groups(
    int (*fn)(void *, uint16_t *, uint16_t, uint16_t *),
    void *config, uint16_t *groups, uint16_t groups_count, uint16_t *groups_count_out,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_config_set_serialization_version(
    int (*fn)(void *, int),
    void *config, int version,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Connection Creation & Management --- */
void *s2n_wrap_connection_new(
    void *(*fn)(int),
    int mode,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_config(
    int (*fn)(void *, void *),
    void *conn, void *config,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_ctx(
    int (*fn)(void *, void *),
    void *conn, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

void *s2n_wrap_connection_get_ctx(
    void *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_cb_done(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_server_name_extension_used(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Client Hello Access --- */
void *s2n_wrap_connection_get_client_hello(
    void *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

void *s2n_wrap_client_hello_parse_message(
    void *(*fn)(const uint8_t *, uint32_t),
    const uint8_t *data, uint32_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_free(
    int (*fn)(void **),
    void **client_hello,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_client_hello_get_raw_message_length(
    ssize_t (*fn)(void *),
    void *client_hello,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_client_hello_get_raw_message(
    ssize_t (*fn)(void *, uint8_t *, uint32_t),
    void *client_hello, uint8_t *out, uint32_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_client_hello_get_cipher_suites_length(
    ssize_t (*fn)(void *),
    void *client_hello,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_client_hello_get_cipher_suites(
    ssize_t (*fn)(void *, uint8_t *, uint32_t),
    void *client_hello, uint8_t *out, uint32_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_client_hello_get_extensions_length(
    ssize_t (*fn)(void *),
    void *client_hello,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_client_hello_get_extensions(
    ssize_t (*fn)(void *, uint8_t *, uint32_t),
    void *client_hello, uint8_t *out, uint32_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_client_hello_get_extension_length(
    ssize_t (*fn)(void *, int),
    void *client_hello, int extension_type,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_client_hello_get_extension_by_id(
    ssize_t (*fn)(void *, int, uint8_t *, uint32_t),
    void *client_hello, int extension_type, uint8_t *out, uint32_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_has_extension(
    int (*fn)(void *, uint16_t, int *),
    void *client_hello, uint16_t extension_iana, int *exists,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_session_id_length(
    int (*fn)(void *, uint32_t *),
    void *client_hello, uint32_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_session_id(
    int (*fn)(void *, uint8_t *, uint32_t *, uint32_t),
    void *client_hello, uint8_t *out, uint32_t *out_length, uint32_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_compression_methods_length(
    int (*fn)(void *, uint32_t *),
    void *client_hello, uint32_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_compression_methods(
    int (*fn)(void *, uint8_t *, uint32_t, uint32_t *),
    void *client_hello, uint8_t *out, uint32_t max_length, uint32_t *out_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_legacy_protocol_version(
    int (*fn)(void *, uint8_t *),
    void *client_hello, uint8_t *version,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_supported_groups(
    int (*fn)(void *, uint16_t *, uint16_t, uint16_t *),
    void *client_hello, uint16_t *groups, uint16_t groups_count, uint16_t *groups_count_out,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_server_name_length(
    int (*fn)(void *, uint16_t *),
    void *client_hello, uint16_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_server_name(
    int (*fn)(void *, uint8_t *, uint16_t, uint16_t *),
    void *client_hello, uint8_t *out, uint16_t max_length, uint16_t *out_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_client_hello_get_legacy_record_version(
    int (*fn)(void *, uint8_t *),
    void *client_hello, uint8_t *version,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- File Descriptor & I/O --- */
int s2n_wrap_connection_set_fd(
    int (*fn)(void *, int),
    void *conn, int fd,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_read_fd(
    int (*fn)(void *, int),
    void *conn, int fd,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_write_fd(
    int (*fn)(void *, int),
    void *conn, int fd,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_read_fd(
    int (*fn)(void *, int *),
    void *conn, int *fd,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_write_fd(
    int (*fn)(void *, int *),
    void *conn, int *fd,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_use_corked_io(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_recv_ctx(
    int (*fn)(void *, void *),
    void *conn, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_send_ctx(
    int (*fn)(void *, void *),
    void *conn, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_recv_cb(
    int (*fn)(void *, void *),
    void *conn, void *callback,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_send_cb(
    int (*fn)(void *, void *),
    void *conn, void *callback,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Connection Preferences --- */
int s2n_wrap_connection_prefer_throughput(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_prefer_low_latency(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_recv_buffering(
    int (*fn)(void *, int),
    void *conn, int enabled,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* s2n_peek_buffered returns uint32, no error - no wrapper needed */

int s2n_wrap_connection_set_dynamic_buffers(
    int (*fn)(void *, int),
    void *conn, int enabled,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_dynamic_record_threshold(
    int (*fn)(void *, uint32_t, uint16_t),
    void *conn, uint32_t resize_threshold, uint16_t timeout_threshold,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Host Verification --- */
int s2n_wrap_connection_set_verify_host_callback(
    int (*fn)(void *, void *, void *),
    void *conn, void *callback, void *ctx,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Blinding & Security --- */
int s2n_wrap_connection_set_blinding(
    int (*fn)(void *, int),
    void *conn, int blinding,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* s2n_connection_get_delay returns uint64, no error - no wrapper needed */

/* --- Cipher & Protocol Configuration --- */
int s2n_wrap_connection_set_cipher_preferences(
    int (*fn)(void *, const char *),
    void *conn, const char *version,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_request_key_update(
    int (*fn)(void *, int),
    void *conn, int peer_request,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_append_protocol_preference(
    int (*fn)(void *, const uint8_t *, uint8_t),
    void *conn, const uint8_t *protocol, uint8_t protocol_len,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_protocol_preferences(
    int (*fn)(void *, const char **, int),
    void *conn, const char **protocols, int protocol_count,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Server Name (SNI) --- */
int s2n_wrap_set_server_name(
    int (*fn)(void *, const char *),
    void *conn, const char *server_name,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

const char *s2n_wrap_get_server_name(
    const char *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Application Protocol (ALPN) --- */
const char *s2n_wrap_get_application_protocol(
    const char *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- OCSP & Certificate Transparency --- */
const uint8_t *s2n_wrap_connection_get_ocsp_response(
    const uint8_t *(*fn)(void *, uint32_t *),
    void *conn, uint32_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

const uint8_t *s2n_wrap_connection_get_sct_list(
    const uint8_t *(*fn)(void *, uint32_t *),
    void *conn, uint32_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Handshake & TLS Operations --- */
int s2n_wrap_negotiate(
    int (*fn)(void *, int *),
    void *conn, int *blocked,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_send(
    ssize_t (*fn)(void *, const void *, ssize_t, int *),
    void *conn, const void *buf, ssize_t size, int *blocked,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

ssize_t s2n_wrap_recv(
    ssize_t (*fn)(void *, void *, ssize_t, int *),
    void *conn, void *buf, ssize_t size, int *blocked,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* s2n_peek returns uint32, no error - no wrapper needed */

int s2n_wrap_connection_free_handshake(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_release_buffers(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_wipe(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_free(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_shutdown(
    int (*fn)(void *, int *),
    void *conn, int *blocked,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_shutdown_send(
    int (*fn)(void *, int *),
    void *conn, int *blocked,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Client Authentication --- */
int s2n_wrap_connection_get_client_auth_type(
    int (*fn)(void *, int *),
    void *conn, int *auth_type,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_client_auth_type(
    int (*fn)(void *, int),
    void *conn, int auth_type,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_client_cert_chain(
    int (*fn)(void *, const uint8_t **, uint32_t *),
    void *conn, const uint8_t **cert_chain, uint32_t *cert_chain_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_client_cert_used(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Session Management --- */
int s2n_wrap_connection_add_new_tickets_to_send(
    int (*fn)(void *, uint8_t),
    void *conn, uint8_t num_tickets,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_tickets_sent(
    int (*fn)(void *, uint16_t *),
    void *conn, uint16_t *tickets_sent,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_server_keying_material_lifetime(
    int (*fn)(void *, uint32_t),
    void *conn, uint32_t lifetime,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_session_ticket_get_data_len(
    int (*fn)(void *, size_t *),
    void *ticket, size_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_session_ticket_get_data(
    int (*fn)(void *, size_t, uint8_t *),
    void *ticket, size_t max_length, uint8_t *data,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_session_ticket_get_lifetime(
    int (*fn)(void *, uint32_t *),
    void *ticket, uint32_t *lifetime,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_session(
    int (*fn)(void *, const uint8_t *, size_t),
    void *conn, const uint8_t *session, size_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_session(
    int (*fn)(void *, uint8_t *, size_t),
    void *conn, uint8_t *session, size_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_session_ticket_lifetime_hint(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_session_length(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_session_id_length(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_session_id(
    int (*fn)(void *, uint8_t *, size_t),
    void *conn, uint8_t *session_id, size_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_is_session_resumed(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Certificate Information --- */
int s2n_wrap_connection_is_ocsp_stapled(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_selected_signature_algorithm(
    int (*fn)(void *, int *),
    void *conn, int *sig_alg,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_selected_digest_algorithm(
    int (*fn)(void *, int *),
    void *conn, int *hash_alg,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_selected_client_cert_signature_algorithm(
    int (*fn)(void *, int *),
    void *conn, int *sig_alg,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_selected_client_cert_digest_algorithm(
    int (*fn)(void *, int *),
    void *conn, int *hash_alg,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

void *s2n_wrap_connection_get_selected_cert(
    void *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_get_length(
    int (*fn)(void *, uint32_t *),
    void *chain, uint32_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_chain_get_cert(
    int (*fn)(void *, void **, uint32_t),
    void *chain, void **cert, uint32_t index,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_get_der(
    int (*fn)(void *, const uint8_t **, uint32_t *),
    void *cert, const uint8_t **der, uint32_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_peer_cert_chain(
    int (*fn)(void *, void *),
    void *conn, void *cert_chain,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_get_x509_extension_value_length(
    int (*fn)(void *, const uint8_t *, uint32_t *),
    void *cert, const uint8_t *oid, uint32_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_get_x509_extension_value(
    int (*fn)(void *, const uint8_t *, uint8_t *, uint32_t *, int *),
    void *cert, const uint8_t *oid, uint8_t *value, uint32_t *length, int *critical,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_get_utf8_string_from_extension_data_length(
    int (*fn)(const uint8_t *, uint32_t, uint32_t *),
    const uint8_t *data, uint32_t data_length, uint32_t *utf8_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_cert_get_utf8_string_from_extension_data(
    int (*fn)(const uint8_t *, uint32_t, uint8_t *, uint32_t *),
    const uint8_t *data, uint32_t data_length, uint8_t *utf8, uint32_t *utf8_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Pre-Shared Keys (PSK) --- */
void *s2n_wrap_external_psk_new(
    void *(*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_psk_free(
    int (*fn)(void **),
    void **psk,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_psk_set_identity(
    int (*fn)(void *, const uint8_t *, uint16_t),
    void *psk, const uint8_t *identity, uint16_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_psk_set_secret(
    int (*fn)(void *, const uint8_t *, uint16_t),
    void *psk, const uint8_t *secret, uint16_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_psk_set_hmac(
    int (*fn)(void *, int),
    void *psk, int hmac,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_append_psk(
    int (*fn)(void *, void *),
    void *conn, void *psk,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_psk_mode(
    int (*fn)(void *, int),
    void *conn, int mode,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_negotiated_psk_identity_length(
    int (*fn)(void *, uint16_t *),
    void *conn, uint16_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_negotiated_psk_identity(
    int (*fn)(void *, uint8_t *, uint16_t),
    void *conn, uint8_t *identity, uint16_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

void *s2n_wrap_offered_psk_new(
    void *(*fn)(void),
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_offered_psk_free(
    int (*fn)(void **),
    void **psk,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_offered_psk_get_identity(
    int (*fn)(void *, uint8_t **, uint16_t *),
    void *psk, uint8_t **identity, uint16_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* s2n_offered_psk_list_has_next returns bool, no error - no wrapper needed */

int s2n_wrap_offered_psk_list_next(
    int (*fn)(void *, void *),
    void *psk_list, void *psk,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_offered_psk_list_reread(
    int (*fn)(void *),
    void *psk_list,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_offered_psk_list_choose_psk(
    int (*fn)(void *, void *),
    void *psk_list, void *psk,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_psk_configure_early_data(
    int (*fn)(void *, uint32_t, uint8_t, uint8_t),
    void *psk, uint32_t max_early_data_size, uint8_t cipher_suite_first_byte, uint8_t cipher_suite_second_byte,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_psk_set_application_protocol(
    int (*fn)(void *, const uint8_t *, uint8_t),
    void *psk, const uint8_t *protocol, uint8_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_psk_set_early_data_context(
    int (*fn)(void *, const uint8_t *, uint16_t),
    void *psk, const uint8_t *context, uint16_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Connection Statistics --- */
/* s2n_connection_get_wire_bytes_in returns uint64, no error - no wrapper needed */
/* s2n_connection_get_wire_bytes_out returns uint64, no error - no wrapper needed */

/* --- Protocol Version Information --- */
int s2n_wrap_connection_get_client_protocol_version(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_server_protocol_version(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_actual_protocol_version(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_client_hello_version(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Cipher & Security Information --- */
const char *s2n_wrap_connection_get_cipher(
    const char *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_certificate_match(
    int (*fn)(void *, int *),
    void *conn, int *cert_match,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_master_secret(
    int (*fn)(void *, uint8_t *, size_t),
    void *conn, uint8_t *secret, size_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_tls_exporter(
    int (*fn)(void *, const uint8_t *, uint32_t, const uint8_t *, uint32_t, uint8_t *, uint32_t),
    void *conn, const uint8_t *label, uint32_t label_length,
    const uint8_t *context, uint32_t context_length,
    uint8_t *output, uint32_t output_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_cipher_iana_value(
    int (*fn)(void *, uint8_t *, uint8_t *),
    void *conn, uint8_t *first, uint8_t *second,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_is_valid_for_cipher_preferences(
    int (*fn)(void *, const char *),
    void *conn, const char *version,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

const char *s2n_wrap_connection_get_curve(
    const char *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

const char *s2n_wrap_connection_get_kem_name(
    const char *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

const char *s2n_wrap_connection_get_kem_group_name(
    const char *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_key_exchange_group(
    int (*fn)(void *, const char **),
    void *conn, const char **group_name,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_alert(
    int (*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

const char *s2n_wrap_connection_get_handshake_type_name(
    const char *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

const char *s2n_wrap_connection_get_last_message_name(
    const char *(*fn)(void *),
    void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Async Private Key Operations --- */
int s2n_wrap_async_pkey_op_perform(
    int (*fn)(void *, void *),
    void *op, void *key,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_async_pkey_op_apply(
    int (*fn)(void *, void *),
    void *op, void *conn,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_async_pkey_op_free(
    int (*fn)(void *),
    void *op,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_async_pkey_op_get_op_type(
    int (*fn)(void *, int *),
    void *op, int *op_type,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_async_pkey_op_get_input_size(
    int (*fn)(void *, uint32_t *),
    void *op, uint32_t *size,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_async_pkey_op_get_input(
    int (*fn)(void *, uint8_t *, uint32_t),
    void *op, uint8_t *data, uint32_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_async_pkey_op_set_output(
    int (*fn)(void *, const uint8_t *, uint32_t),
    void *op, const uint8_t *data, uint32_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Early Data --- */
int s2n_wrap_connection_set_server_max_early_data_size(
    int (*fn)(void *, uint32_t),
    void *conn, uint32_t size,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_set_server_early_data_context(
    int (*fn)(void *, const uint8_t *, uint16_t),
    void *conn, const uint8_t *context, uint16_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_early_data_status(
    int (*fn)(void *, int *),
    void *conn, int *status,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_remaining_early_data_size(
    int (*fn)(void *, uint32_t *),
    void *conn, uint32_t *size,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_get_max_early_data_size(
    int (*fn)(void *, uint32_t *),
    void *conn, uint32_t *size,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_send_early_data(
    int (*fn)(void *, const uint8_t *, ssize_t, ssize_t *, int *),
    void *conn, const uint8_t *data, ssize_t data_len, ssize_t *written, int *blocked,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_recv_early_data(
    int (*fn)(void *, uint8_t *, ssize_t, ssize_t *, int *),
    void *conn, uint8_t *data, ssize_t max_data_len, ssize_t *read, int *blocked,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_offered_early_data_get_context_length(
    int (*fn)(void *, uint16_t *),
    void *early_data, uint16_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_offered_early_data_get_context(
    int (*fn)(void *, uint8_t *, uint16_t),
    void *early_data, uint8_t *context, uint16_t max_length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_offered_early_data_reject(
    int (*fn)(void *),
    void *early_data,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_offered_early_data_accept(
    int (*fn)(void *),
    void *early_data,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

/* --- Connection Serialization --- */
int s2n_wrap_connection_serialization_length(
    int (*fn)(void *, uint32_t *),
    void *conn, uint32_t *length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_serialize(
    int (*fn)(void *, uint8_t *, uint32_t),
    void *conn, uint8_t *buffer, uint32_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

int s2n_wrap_connection_deserialize(
    int (*fn)(void *, const uint8_t *, uint32_t),
    void *conn, const uint8_t *buffer, uint32_t length,
    const S2nErrorFuncs *err_funcs, S2nErrorInfo *err_out);

#endif /* S2N_WRAPPER_H */
