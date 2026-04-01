{-# LANGUAGE RecordWildCards #-}

-- {-# LANGUAGE ForeignFunctionInterface #-}

{- |
Module      : S2nTls.Sys.Dynamic
Description : Dynamic loading bindings to s2n-tls
License     : BSD-3-Clause

This module provides s2n-tls bindings via dynamic loading (dlopen).
It is only available when the package is built with the @dynamic@ flag.

Use 'withDynamicTlsSys' to load the s2n-tls library at runtime and
obtain a 'S2nTlsSys' record populated with dynamically resolved
function pointers.
-}
module S2nTls.Sys.Dynamic (
    withDynamicTlsSys,
    DynamicLoadError (..),
) where

import Control.Exception (Exception, bracket, throwIO)
import Data.Word (Word16, Word32, Word64, Word8)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (..), CLong (..), CSize (..))
import Foreign.Ptr (FunPtr, Ptr, castFunPtrToPtr, nullFunPtr)
import System.Posix.DynamicLinker (
    DL,
    RTLDFlags (RTLD_LAZY, RTLD_LOCAL),
    dlclose,
    dlopen,
    dlsym,
 )
import System.Posix.Types (CSsize (..))

import S2nTls.Sys.Types

-- | Errors that can occur when dynamically loading the s2n-tls library.
data DynamicLoadError
    = LibraryNotFound FilePath
    | SymbolNotFound String
    deriving (Show, Eq)

instance Exception DynamicLoadError

{- | Load the s2n-tls library dynamically and provide a 'S2nTlsSys' record
to the given callback. The library is automatically unloaded when the
callback returns (or throws an exception).

@
withDynamicTlsSys "libs2n.so" $ \\sys -> do
    -- use sys here
@
-}
withDynamicTlsSys ::
    -- | Path to the s2n-tls shared library (e.g., "libs2n.so")
    FilePath ->
    -- | Callback that receives the populated 'S2nTlsSys' record
    (S2nTlsSys -> IO a) ->
    IO a
withDynamicTlsSys libPath action =
    bracket (dlopen libPath [RTLD_LAZY, RTLD_LOCAL]) dlclose $ \dl -> do
        sys <- loadSymbols dl
        action sys

-- | Helper to load a symbol and throw if not found.
loadSym :: DL -> String -> IO (FunPtr a)
loadSym dl name = do
    ptr <- dlsym dl name
    if castFunPtrToPtr ptr == castFunPtrToPtr nullFunPtr
        then throwIO (SymbolNotFound name)
        else pure ptr

-- | Load all s2n-tls symbols from the given dynamic library handle.
loadSymbols :: DL -> IO S2nTlsSys
loadSymbols dl = do
    -- Initialization & Cleanup
    s2n_init <- mk_s2n_init <$> loadSym dl "s2n_init"
    s2n_cleanup <- mk_s2n_cleanup <$> loadSym dl "s2n_cleanup"
    s2n_cleanup_final <- mk_s2n_cleanup_final <$> loadSym dl "s2n_cleanup_final"
    s2n_crypto_disable_init <- mk_s2n_crypto_disable_init <$> loadSym dl "s2n_crypto_disable_init"
    s2n_disable_atexit <- mk_s2n_disable_atexit <$> loadSym dl "s2n_disable_atexit"
    s2n_get_openssl_version <- mk_s2n_get_openssl_version <$> loadSym dl "s2n_get_openssl_version"
    s2n_get_fips_mode <- mk_s2n_get_fips_mode <$> loadSym dl "s2n_get_fips_mode"

    -- Error Handling
    s2n_errno_location <- mk_s2n_errno_location <$> loadSym dl "s2n_errno_location"
    s2n_error_get_type <- mk_s2n_error_get_type <$> loadSym dl "s2n_error_get_type"
    s2n_strerror <- mk_s2n_strerror <$> loadSym dl "s2n_strerror"
    s2n_strerror_debug <- mk_s2n_strerror_debug <$> loadSym dl "s2n_strerror_debug"
    s2n_strerror_name <- mk_s2n_strerror_name <$> loadSym dl "s2n_strerror_name"
    s2n_strerror_source <- mk_s2n_strerror_source <$> loadSym dl "s2n_strerror_source"

    -- Stack Traces
    s2n_stack_traces_enabled <- mk_s2n_stack_traces_enabled <$> loadSym dl "s2n_stack_traces_enabled"
    s2n_stack_traces_enabled_set <- mk_s2n_stack_traces_enabled_set <$> loadSym dl "s2n_stack_traces_enabled_set"
    s2n_calculate_stacktrace <- mk_s2n_calculate_stacktrace <$> loadSym dl "s2n_calculate_stacktrace"
    s2n_free_stacktrace <- mk_s2n_free_stacktrace <$> loadSym dl "s2n_free_stacktrace"
    s2n_get_stacktrace <- mk_s2n_get_stacktrace <$> loadSym dl "s2n_get_stacktrace"

    -- Config Management
    s2n_config_new <- mk_s2n_config_new <$> loadSym dl "s2n_config_new"
    s2n_config_new_minimal <- mk_s2n_config_new_minimal <$> loadSym dl "s2n_config_new_minimal"
    s2n_config_free <- mk_s2n_config_free <$> loadSym dl "s2n_config_free"
    s2n_config_free_dhparams <- mk_s2n_config_free_dhparams <$> loadSym dl "s2n_config_free_dhparams"
    s2n_config_free_cert_chain_and_key <- mk_s2n_config_free_cert_chain_and_key <$> loadSym dl "s2n_config_free_cert_chain_and_key"
    s2n_config_set_wall_clock <- mk_s2n_config_set_wall_clock <$> loadSym dl "s2n_config_set_wall_clock"
    s2n_config_set_monotonic_clock <- mk_s2n_config_set_monotonic_clock <$> loadSym dl "s2n_config_set_monotonic_clock"

    -- Cache Callbacks
    s2n_config_set_cache_store_callback <- mk_s2n_config_set_cache_store_callback <$> loadSym dl "s2n_config_set_cache_store_callback"
    s2n_config_set_cache_retrieve_callback <- mk_s2n_config_set_cache_retrieve_callback <$> loadSym dl "s2n_config_set_cache_retrieve_callback"
    s2n_config_set_cache_delete_callback <- mk_s2n_config_set_cache_delete_callback <$> loadSym dl "s2n_config_set_cache_delete_callback"

    -- Memory & Random Callbacks
    s2n_mem_set_callbacks <- mk_s2n_mem_set_callbacks <$> loadSym dl "s2n_mem_set_callbacks"
    s2n_rand_set_callbacks <- mk_s2n_rand_set_callbacks <$> loadSym dl "s2n_rand_set_callbacks"

    -- Certificate Chain Management
    s2n_cert_chain_and_key_new <- mk_s2n_cert_chain_and_key_new <$> loadSym dl "s2n_cert_chain_and_key_new"
    s2n_cert_chain_and_key_load_pem <- mk_s2n_cert_chain_and_key_load_pem <$> loadSym dl "s2n_cert_chain_and_key_load_pem"
    s2n_cert_chain_and_key_load_pem_bytes <- mk_s2n_cert_chain_and_key_load_pem_bytes <$> loadSym dl "s2n_cert_chain_and_key_load_pem_bytes"
    s2n_cert_chain_and_key_load_public_pem_bytes <- mk_s2n_cert_chain_and_key_load_public_pem_bytes <$> loadSym dl "s2n_cert_chain_and_key_load_public_pem_bytes"
    s2n_cert_chain_and_key_free <- mk_s2n_cert_chain_and_key_free <$> loadSym dl "s2n_cert_chain_and_key_free"
    s2n_cert_chain_and_key_set_ctx <- mk_s2n_cert_chain_and_key_set_ctx <$> loadSym dl "s2n_cert_chain_and_key_set_ctx"
    s2n_cert_chain_and_key_get_ctx <- mk_s2n_cert_chain_and_key_get_ctx <$> loadSym dl "s2n_cert_chain_and_key_get_ctx"
    s2n_cert_chain_and_key_get_private_key <- mk_s2n_cert_chain_and_key_get_private_key <$> loadSym dl "s2n_cert_chain_and_key_get_private_key"
    s2n_cert_chain_and_key_set_ocsp_data <- mk_s2n_cert_chain_and_key_set_ocsp_data <$> loadSym dl "s2n_cert_chain_and_key_set_ocsp_data"
    s2n_cert_chain_and_key_set_sct_list <- mk_s2n_cert_chain_and_key_set_sct_list <$> loadSym dl "s2n_cert_chain_and_key_set_sct_list"
    s2n_config_set_cert_tiebreak_callback <- mk_s2n_config_set_cert_tiebreak_callback <$> loadSym dl "s2n_config_set_cert_tiebreak_callback"
    s2n_config_add_cert_chain_and_key <- mk_s2n_config_add_cert_chain_and_key <$> loadSym dl "s2n_config_add_cert_chain_and_key"
    s2n_config_add_cert_chain_and_key_to_store <- mk_s2n_config_add_cert_chain_and_key_to_store <$> loadSym dl "s2n_config_add_cert_chain_and_key_to_store"
    s2n_config_set_cert_chain_and_key_defaults <- mk_s2n_config_set_cert_chain_and_key_defaults <$> loadSym dl "s2n_config_set_cert_chain_and_key_defaults"

    -- Trust Store
    s2n_config_set_verification_ca_location <- mk_s2n_config_set_verification_ca_location <$> loadSym dl "s2n_config_set_verification_ca_location"
    s2n_config_add_pem_to_trust_store <- mk_s2n_config_add_pem_to_trust_store <$> loadSym dl "s2n_config_add_pem_to_trust_store"
    s2n_config_wipe_trust_store <- mk_s2n_config_wipe_trust_store <$> loadSym dl "s2n_config_wipe_trust_store"
    s2n_config_load_system_certs <- mk_s2n_config_load_system_certs <$> loadSym dl "s2n_config_load_system_certs"
    s2n_config_set_cert_authorities_from_trust_store <- mk_s2n_config_set_cert_authorities_from_trust_store <$> loadSym dl "s2n_config_set_cert_authorities_from_trust_store"

    -- Verification & Validation
    s2n_config_set_verify_after_sign <- mk_s2n_config_set_verify_after_sign <$> loadSym dl "s2n_config_set_verify_after_sign"
    s2n_config_set_check_stapled_ocsp_response <- mk_s2n_config_set_check_stapled_ocsp_response <$> loadSym dl "s2n_config_set_check_stapled_ocsp_response"
    s2n_config_disable_x509_time_verification <- mk_s2n_config_disable_x509_time_verification <$> loadSym dl "s2n_config_disable_x509_time_verification"
    s2n_config_disable_x509_intent_verification <- mk_s2n_config_disable_x509_intent_verification <$> loadSym dl "s2n_config_disable_x509_intent_verification"
    s2n_config_disable_x509_verification <- mk_s2n_config_disable_x509_verification <$> loadSym dl "s2n_config_disable_x509_verification"
    s2n_config_set_max_cert_chain_depth <- mk_s2n_config_set_max_cert_chain_depth <$> loadSym dl "s2n_config_set_max_cert_chain_depth"
    s2n_config_set_verify_host_callback <- mk_s2n_config_set_verify_host_callback <$> loadSym dl "s2n_config_set_verify_host_callback"

    -- DH Parameters
    s2n_config_add_dhparams <- mk_s2n_config_add_dhparams <$> loadSym dl "s2n_config_add_dhparams"

    -- Security Policies & Preferences
    s2n_config_set_cipher_preferences <- mk_s2n_config_set_cipher_preferences <$> loadSym dl "s2n_config_set_cipher_preferences"
    s2n_config_append_protocol_preference <- mk_s2n_config_append_protocol_preference <$> loadSym dl "s2n_config_append_protocol_preference"
    s2n_config_set_protocol_preferences <- mk_s2n_config_set_protocol_preferences <$> loadSym dl "s2n_config_set_protocol_preferences"
    s2n_config_set_status_request_type <- mk_s2n_config_set_status_request_type <$> loadSym dl "s2n_config_set_status_request_type"
    s2n_config_set_ct_support_level <- mk_s2n_config_set_ct_support_level <$> loadSym dl "s2n_config_set_ct_support_level"
    s2n_config_set_alert_behavior <- mk_s2n_config_set_alert_behavior <$> loadSym dl "s2n_config_set_alert_behavior"

    -- Extension Data
    s2n_config_set_extension_data <- mk_s2n_config_set_extension_data <$> loadSym dl "s2n_config_set_extension_data"
    s2n_config_send_max_fragment_length <- mk_s2n_config_send_max_fragment_length <$> loadSym dl "s2n_config_send_max_fragment_length"
    s2n_config_accept_max_fragment_length <- mk_s2n_config_accept_max_fragment_length <$> loadSym dl "s2n_config_accept_max_fragment_length"

    -- Session & Ticket Configuration
    s2n_config_set_session_state_lifetime <- mk_s2n_config_set_session_state_lifetime <$> loadSym dl "s2n_config_set_session_state_lifetime"
    s2n_config_set_session_tickets_onoff <- mk_s2n_config_set_session_tickets_onoff <$> loadSym dl "s2n_config_set_session_tickets_onoff"
    s2n_config_set_session_cache_onoff <- mk_s2n_config_set_session_cache_onoff <$> loadSym dl "s2n_config_set_session_cache_onoff"
    s2n_config_set_ticket_encrypt_decrypt_key_lifetime <- mk_s2n_config_set_ticket_encrypt_decrypt_key_lifetime <$> loadSym dl "s2n_config_set_ticket_encrypt_decrypt_key_lifetime"
    s2n_config_set_ticket_decrypt_key_lifetime <- mk_s2n_config_set_ticket_decrypt_key_lifetime <$> loadSym dl "s2n_config_set_ticket_decrypt_key_lifetime"
    s2n_config_add_ticket_crypto_key <- mk_s2n_config_add_ticket_crypto_key <$> loadSym dl "s2n_config_add_ticket_crypto_key"
    s2n_config_require_ticket_forward_secrecy <- mk_s2n_config_require_ticket_forward_secrecy <$> loadSym dl "s2n_config_require_ticket_forward_secrecy"

    -- Buffer & I/O Configuration
    s2n_config_set_send_buffer_size <- mk_s2n_config_set_send_buffer_size <$> loadSym dl "s2n_config_set_send_buffer_size"
    s2n_config_set_recv_multi_record <- mk_s2n_config_set_recv_multi_record <$> loadSym dl "s2n_config_set_recv_multi_record"

    -- Miscellaneous Config
    s2n_config_set_ctx <- mk_s2n_config_set_ctx <$> loadSym dl "s2n_config_set_ctx"
    s2n_config_get_ctx <- mk_s2n_config_get_ctx <$> loadSym dl "s2n_config_get_ctx"
    s2n_config_set_client_hello_cb <- mk_s2n_config_set_client_hello_cb <$> loadSym dl "s2n_config_set_client_hello_cb"
    s2n_config_set_client_hello_cb_mode <- mk_s2n_config_set_client_hello_cb_mode <$> loadSym dl "s2n_config_set_client_hello_cb_mode"
    s2n_config_set_max_blinding_delay <- mk_s2n_config_set_max_blinding_delay <$> loadSym dl "s2n_config_set_max_blinding_delay"
    s2n_config_get_client_auth_type <- mk_s2n_config_get_client_auth_type <$> loadSym dl "s2n_config_get_client_auth_type"
    s2n_config_set_client_auth_type <- mk_s2n_config_set_client_auth_type <$> loadSym dl "s2n_config_set_client_auth_type"
    s2n_config_set_initial_ticket_count <- mk_s2n_config_set_initial_ticket_count <$> loadSym dl "s2n_config_set_initial_ticket_count"
    s2n_config_set_psk_mode <- mk_s2n_config_set_psk_mode <$> loadSym dl "s2n_config_set_psk_mode"
    s2n_config_set_psk_selection_callback <- mk_s2n_config_set_psk_selection_callback <$> loadSym dl "s2n_config_set_psk_selection_callback"
    s2n_config_set_async_pkey_callback <- mk_s2n_config_set_async_pkey_callback <$> loadSym dl "s2n_config_set_async_pkey_callback"
    s2n_config_set_async_pkey_validation_mode <- mk_s2n_config_set_async_pkey_validation_mode <$> loadSym dl "s2n_config_set_async_pkey_validation_mode"
    s2n_config_set_session_ticket_cb <- mk_s2n_config_set_session_ticket_cb <$> loadSym dl "s2n_config_set_session_ticket_cb"
    s2n_config_set_key_log_cb <- mk_s2n_config_set_key_log_cb <$> loadSym dl "s2n_config_set_key_log_cb"
    s2n_config_enable_cert_req_dss_legacy_compat <- mk_s2n_config_enable_cert_req_dss_legacy_compat <$> loadSym dl "s2n_config_enable_cert_req_dss_legacy_compat"
    s2n_config_set_server_max_early_data_size <- mk_s2n_config_set_server_max_early_data_size <$> loadSym dl "s2n_config_set_server_max_early_data_size"
    s2n_config_set_early_data_cb <- mk_s2n_config_set_early_data_cb <$> loadSym dl "s2n_config_set_early_data_cb"
    s2n_config_get_supported_groups <- mk_s2n_config_get_supported_groups <$> loadSym dl "s2n_config_get_supported_groups"
    s2n_config_set_serialization_version <- mk_s2n_config_set_serialization_version <$> loadSym dl "s2n_config_set_serialization_version"

    -- Connection Creation & Management
    s2n_connection_new <- mk_s2n_connection_new <$> loadSym dl "s2n_connection_new"
    s2n_connection_set_config <- mk_s2n_connection_set_config <$> loadSym dl "s2n_connection_set_config"
    s2n_connection_set_ctx <- mk_s2n_connection_set_ctx <$> loadSym dl "s2n_connection_set_ctx"
    s2n_connection_get_ctx <- mk_s2n_connection_get_ctx <$> loadSym dl "s2n_connection_get_ctx"
    s2n_client_hello_cb_done <- mk_s2n_client_hello_cb_done <$> loadSym dl "s2n_client_hello_cb_done"
    s2n_connection_server_name_extension_used <- mk_s2n_connection_server_name_extension_used <$> loadSym dl "s2n_connection_server_name_extension_used"

    -- Client Hello Access
    s2n_connection_get_client_hello <- mk_s2n_connection_get_client_hello <$> loadSym dl "s2n_connection_get_client_hello"
    s2n_client_hello_parse_message <- mk_s2n_client_hello_parse_message <$> loadSym dl "s2n_client_hello_parse_message"
    s2n_client_hello_free <- mk_s2n_client_hello_free <$> loadSym dl "s2n_client_hello_free"
    s2n_client_hello_get_raw_message_length <- mk_s2n_client_hello_get_raw_message_length <$> loadSym dl "s2n_client_hello_get_raw_message_length"
    s2n_client_hello_get_raw_message <- mk_s2n_client_hello_get_raw_message <$> loadSym dl "s2n_client_hello_get_raw_message"
    s2n_client_hello_get_cipher_suites_length <- mk_s2n_client_hello_get_cipher_suites_length <$> loadSym dl "s2n_client_hello_get_cipher_suites_length"
    s2n_client_hello_get_cipher_suites <- mk_s2n_client_hello_get_cipher_suites <$> loadSym dl "s2n_client_hello_get_cipher_suites"
    s2n_client_hello_get_extensions_length <- mk_s2n_client_hello_get_extensions_length <$> loadSym dl "s2n_client_hello_get_extensions_length"
    s2n_client_hello_get_extensions <- mk_s2n_client_hello_get_extensions <$> loadSym dl "s2n_client_hello_get_extensions"
    s2n_client_hello_get_extension_length <- mk_s2n_client_hello_get_extension_length <$> loadSym dl "s2n_client_hello_get_extension_length"
    s2n_client_hello_get_extension_by_id <- mk_s2n_client_hello_get_extension_by_id <$> loadSym dl "s2n_client_hello_get_extension_by_id"
    s2n_client_hello_has_extension <- mk_s2n_client_hello_has_extension <$> loadSym dl "s2n_client_hello_has_extension"
    s2n_client_hello_get_session_id_length <- mk_s2n_client_hello_get_session_id_length <$> loadSym dl "s2n_client_hello_get_session_id_length"
    s2n_client_hello_get_session_id <- mk_s2n_client_hello_get_session_id <$> loadSym dl "s2n_client_hello_get_session_id"
    s2n_client_hello_get_compression_methods_length <- mk_s2n_client_hello_get_compression_methods_length <$> loadSym dl "s2n_client_hello_get_compression_methods_length"
    s2n_client_hello_get_compression_methods <- mk_s2n_client_hello_get_compression_methods <$> loadSym dl "s2n_client_hello_get_compression_methods"
    s2n_client_hello_get_legacy_protocol_version <- mk_s2n_client_hello_get_legacy_protocol_version <$> loadSym dl "s2n_client_hello_get_legacy_protocol_version"
    s2n_client_hello_get_random <- mk_s2n_client_hello_get_random <$> loadSym dl "s2n_client_hello_get_random"
    s2n_client_hello_get_supported_groups <- mk_s2n_client_hello_get_supported_groups <$> loadSym dl "s2n_client_hello_get_supported_groups"
    s2n_client_hello_get_server_name_length <- mk_s2n_client_hello_get_server_name_length <$> loadSym dl "s2n_client_hello_get_server_name_length"
    s2n_client_hello_get_server_name <- mk_s2n_client_hello_get_server_name <$> loadSym dl "s2n_client_hello_get_server_name"
    s2n_client_hello_get_legacy_record_version <- mk_s2n_client_hello_get_legacy_record_version <$> loadSym dl "s2n_client_hello_get_legacy_record_version"

    -- File Descriptor & I/O
    s2n_connection_set_fd <- mk_s2n_connection_set_fd <$> loadSym dl "s2n_connection_set_fd"
    s2n_connection_set_read_fd <- mk_s2n_connection_set_read_fd <$> loadSym dl "s2n_connection_set_read_fd"
    s2n_connection_set_write_fd <- mk_s2n_connection_set_write_fd <$> loadSym dl "s2n_connection_set_write_fd"
    s2n_connection_get_read_fd <- mk_s2n_connection_get_read_fd <$> loadSym dl "s2n_connection_get_read_fd"
    s2n_connection_get_write_fd <- mk_s2n_connection_get_write_fd <$> loadSym dl "s2n_connection_get_write_fd"
    s2n_connection_use_corked_io <- mk_s2n_connection_use_corked_io <$> loadSym dl "s2n_connection_use_corked_io"
    s2n_connection_set_recv_ctx <- mk_s2n_connection_set_recv_ctx <$> loadSym dl "s2n_connection_set_recv_ctx"
    s2n_connection_set_send_ctx <- mk_s2n_connection_set_send_ctx <$> loadSym dl "s2n_connection_set_send_ctx"
    s2n_connection_set_recv_cb <- mk_s2n_connection_set_recv_cb <$> loadSym dl "s2n_connection_set_recv_cb"
    s2n_connection_set_send_cb <- mk_s2n_connection_set_send_cb <$> loadSym dl "s2n_connection_set_send_cb"

    -- Connection Preferences
    s2n_connection_prefer_throughput <- mk_s2n_connection_prefer_throughput <$> loadSym dl "s2n_connection_prefer_throughput"
    s2n_connection_prefer_low_latency <- mk_s2n_connection_prefer_low_latency <$> loadSym dl "s2n_connection_prefer_low_latency"
    s2n_connection_set_recv_buffering <- mk_s2n_connection_set_recv_buffering <$> loadSym dl "s2n_connection_set_recv_buffering"
    s2n_peek_buffered <- mk_s2n_peek_buffered <$> loadSym dl "s2n_peek_buffered"
    s2n_connection_set_dynamic_buffers <- mk_s2n_connection_set_dynamic_buffers <$> loadSym dl "s2n_connection_set_dynamic_buffers"
    s2n_connection_set_dynamic_record_threshold <- mk_s2n_connection_set_dynamic_record_threshold <$> loadSym dl "s2n_connection_set_dynamic_record_threshold"

    -- Host Verification
    s2n_connection_set_verify_host_callback <- mk_s2n_connection_set_verify_host_callback <$> loadSym dl "s2n_connection_set_verify_host_callback"

    -- Blinding & Security
    s2n_connection_set_blinding <- mk_s2n_connection_set_blinding <$> loadSym dl "s2n_connection_set_blinding"
    s2n_connection_get_delay <- mk_s2n_connection_get_delay <$> loadSym dl "s2n_connection_get_delay"

    -- Cipher & Protocol Configuration
    s2n_connection_set_cipher_preferences <- mk_s2n_connection_set_cipher_preferences <$> loadSym dl "s2n_connection_set_cipher_preferences"
    s2n_connection_request_key_update <- mk_s2n_connection_request_key_update <$> loadSym dl "s2n_connection_request_key_update"
    s2n_connection_append_protocol_preference <- mk_s2n_connection_append_protocol_preference <$> loadSym dl "s2n_connection_append_protocol_preference"
    s2n_connection_set_protocol_preferences <- mk_s2n_connection_set_protocol_preferences <$> loadSym dl "s2n_connection_set_protocol_preferences"

    -- Server Name (SNI)
    s2n_set_server_name <- mk_s2n_set_server_name <$> loadSym dl "s2n_set_server_name"
    s2n_get_server_name <- mk_s2n_get_server_name <$> loadSym dl "s2n_get_server_name"

    -- Application Protocol (ALPN)
    s2n_get_application_protocol <- mk_s2n_get_application_protocol <$> loadSym dl "s2n_get_application_protocol"

    -- OCSP & Certificate Transparency
    s2n_connection_get_ocsp_response <- mk_s2n_connection_get_ocsp_response <$> loadSym dl "s2n_connection_get_ocsp_response"
    s2n_connection_get_sct_list <- mk_s2n_connection_get_sct_list <$> loadSym dl "s2n_connection_get_sct_list"

    -- Handshake & TLS Operations
    s2n_negotiate <- mk_s2n_negotiate <$> loadSym dl "s2n_negotiate"
    s2n_send <- mk_s2n_send <$> loadSym dl "s2n_send"
    s2n_recv <- mk_s2n_recv <$> loadSym dl "s2n_recv"
    s2n_peek <- mk_s2n_peek <$> loadSym dl "s2n_peek"
    s2n_connection_free_handshake <- mk_s2n_connection_free_handshake <$> loadSym dl "s2n_connection_free_handshake"
    s2n_connection_release_buffers <- mk_s2n_connection_release_buffers <$> loadSym dl "s2n_connection_release_buffers"
    s2n_connection_wipe <- mk_s2n_connection_wipe <$> loadSym dl "s2n_connection_wipe"
    s2n_connection_free <- mk_s2n_connection_free <$> loadSym dl "s2n_connection_free"
    s2n_shutdown <- mk_s2n_shutdown <$> loadSym dl "s2n_shutdown"
    s2n_shutdown_send <- mk_s2n_shutdown_send <$> loadSym dl "s2n_shutdown_send"

    -- Client Authentication
    s2n_connection_get_client_auth_type <- mk_s2n_connection_get_client_auth_type <$> loadSym dl "s2n_connection_get_client_auth_type"
    s2n_connection_set_client_auth_type <- mk_s2n_connection_set_client_auth_type <$> loadSym dl "s2n_connection_set_client_auth_type"
    s2n_connection_get_client_cert_chain <- mk_s2n_connection_get_client_cert_chain <$> loadSym dl "s2n_connection_get_client_cert_chain"
    s2n_connection_client_cert_used <- mk_s2n_connection_client_cert_used <$> loadSym dl "s2n_connection_client_cert_used"

    -- Session Management
    s2n_connection_add_new_tickets_to_send <- mk_s2n_connection_add_new_tickets_to_send <$> loadSym dl "s2n_connection_add_new_tickets_to_send"
    s2n_connection_get_tickets_sent <- mk_s2n_connection_get_tickets_sent <$> loadSym dl "s2n_connection_get_tickets_sent"
    s2n_connection_set_server_keying_material_lifetime <- mk_s2n_connection_set_server_keying_material_lifetime <$> loadSym dl "s2n_connection_set_server_keying_material_lifetime"
    s2n_session_ticket_get_data_len <- mk_s2n_session_ticket_get_data_len <$> loadSym dl "s2n_session_ticket_get_data_len"
    s2n_session_ticket_get_data <- mk_s2n_session_ticket_get_data <$> loadSym dl "s2n_session_ticket_get_data"
    s2n_session_ticket_get_lifetime <- mk_s2n_session_ticket_get_lifetime <$> loadSym dl "s2n_session_ticket_get_lifetime"
    s2n_connection_set_session <- mk_s2n_connection_set_session <$> loadSym dl "s2n_connection_set_session"
    s2n_connection_get_session <- mk_s2n_connection_get_session <$> loadSym dl "s2n_connection_get_session"
    s2n_connection_get_session_ticket_lifetime_hint <- mk_s2n_connection_get_session_ticket_lifetime_hint <$> loadSym dl "s2n_connection_get_session_ticket_lifetime_hint"
    s2n_connection_get_session_length <- mk_s2n_connection_get_session_length <$> loadSym dl "s2n_connection_get_session_length"
    s2n_connection_get_session_id_length <- mk_s2n_connection_get_session_id_length <$> loadSym dl "s2n_connection_get_session_id_length"
    s2n_connection_get_session_id <- mk_s2n_connection_get_session_id <$> loadSym dl "s2n_connection_get_session_id"
    s2n_connection_is_session_resumed <- mk_s2n_connection_is_session_resumed <$> loadSym dl "s2n_connection_is_session_resumed"

    -- Certificate Information
    s2n_connection_is_ocsp_stapled <- mk_s2n_connection_is_ocsp_stapled <$> loadSym dl "s2n_connection_is_ocsp_stapled"
    s2n_connection_get_selected_signature_algorithm <- mk_s2n_connection_get_selected_signature_algorithm <$> loadSym dl "s2n_connection_get_selected_signature_algorithm"
    s2n_connection_get_selected_digest_algorithm <- mk_s2n_connection_get_selected_digest_algorithm <$> loadSym dl "s2n_connection_get_selected_digest_algorithm"
    s2n_connection_get_selected_client_cert_signature_algorithm <- mk_s2n_connection_get_selected_client_cert_signature_algorithm <$> loadSym dl "s2n_connection_get_selected_client_cert_signature_algorithm"
    s2n_connection_get_selected_client_cert_digest_algorithm <- mk_s2n_connection_get_selected_client_cert_digest_algorithm <$> loadSym dl "s2n_connection_get_selected_client_cert_digest_algorithm"
    s2n_connection_get_signature_scheme <- mk_s2n_connection_get_signature_scheme <$> loadSym dl "s2n_connection_get_signature_scheme"
    s2n_connection_get_selected_cert <- mk_s2n_connection_get_selected_cert <$> loadSym dl "s2n_connection_get_selected_cert"
    s2n_cert_chain_get_length <- mk_s2n_cert_chain_get_length <$> loadSym dl "s2n_cert_chain_get_length"
    s2n_cert_chain_get_cert <- mk_s2n_cert_chain_get_cert <$> loadSym dl "s2n_cert_chain_get_cert"
    s2n_cert_get_der <- mk_s2n_cert_get_der <$> loadSym dl "s2n_cert_get_der"
    s2n_connection_get_peer_cert_chain <- mk_s2n_connection_get_peer_cert_chain <$> loadSym dl "s2n_connection_get_peer_cert_chain"
    s2n_cert_get_x509_extension_value_length <- mk_s2n_cert_get_x509_extension_value_length <$> loadSym dl "s2n_cert_get_x509_extension_value_length"
    s2n_cert_get_x509_extension_value <- mk_s2n_cert_get_x509_extension_value <$> loadSym dl "s2n_cert_get_x509_extension_value"
    s2n_cert_get_utf8_string_from_extension_data_length <- mk_s2n_cert_get_utf8_string_from_extension_data_length <$> loadSym dl "s2n_cert_get_utf8_string_from_extension_data_length"
    s2n_cert_get_utf8_string_from_extension_data <- mk_s2n_cert_get_utf8_string_from_extension_data <$> loadSym dl "s2n_cert_get_utf8_string_from_extension_data"

    -- Pre-Shared Keys (PSK)
    s2n_external_psk_new <- mk_s2n_external_psk_new <$> loadSym dl "s2n_external_psk_new"
    s2n_psk_free <- mk_s2n_psk_free <$> loadSym dl "s2n_psk_free"
    s2n_psk_set_identity <- mk_s2n_psk_set_identity <$> loadSym dl "s2n_psk_set_identity"
    s2n_psk_set_secret <- mk_s2n_psk_set_secret <$> loadSym dl "s2n_psk_set_secret"
    s2n_psk_set_hmac <- mk_s2n_psk_set_hmac <$> loadSym dl "s2n_psk_set_hmac"
    s2n_connection_append_psk <- mk_s2n_connection_append_psk <$> loadSym dl "s2n_connection_append_psk"
    s2n_connection_set_psk_mode <- mk_s2n_connection_set_psk_mode <$> loadSym dl "s2n_connection_set_psk_mode"
    s2n_connection_get_negotiated_psk_identity_length <- mk_s2n_connection_get_negotiated_psk_identity_length <$> loadSym dl "s2n_connection_get_negotiated_psk_identity_length"
    s2n_connection_get_negotiated_psk_identity <- mk_s2n_connection_get_negotiated_psk_identity <$> loadSym dl "s2n_connection_get_negotiated_psk_identity"
    s2n_offered_psk_new <- mk_s2n_offered_psk_new <$> loadSym dl "s2n_offered_psk_new"
    s2n_offered_psk_free <- mk_s2n_offered_psk_free <$> loadSym dl "s2n_offered_psk_free"
    s2n_offered_psk_get_identity <- mk_s2n_offered_psk_get_identity <$> loadSym dl "s2n_offered_psk_get_identity"
    s2n_offered_psk_list_has_next <- mk_s2n_offered_psk_list_has_next <$> loadSym dl "s2n_offered_psk_list_has_next"
    s2n_offered_psk_list_next <- mk_s2n_offered_psk_list_next <$> loadSym dl "s2n_offered_psk_list_next"
    s2n_offered_psk_list_reread <- mk_s2n_offered_psk_list_reread <$> loadSym dl "s2n_offered_psk_list_reread"
    s2n_offered_psk_list_choose_psk <- mk_s2n_offered_psk_list_choose_psk <$> loadSym dl "s2n_offered_psk_list_choose_psk"
    s2n_psk_configure_early_data <- mk_s2n_psk_configure_early_data <$> loadSym dl "s2n_psk_configure_early_data"
    s2n_psk_set_application_protocol <- mk_s2n_psk_set_application_protocol <$> loadSym dl "s2n_psk_set_application_protocol"
    s2n_psk_set_early_data_context <- mk_s2n_psk_set_early_data_context <$> loadSym dl "s2n_psk_set_early_data_context"

    -- Connection Statistics
    s2n_connection_get_wire_bytes_in <- mk_s2n_connection_get_wire_bytes_in <$> loadSym dl "s2n_connection_get_wire_bytes_in"
    s2n_connection_get_wire_bytes_out <- mk_s2n_connection_get_wire_bytes_out <$> loadSym dl "s2n_connection_get_wire_bytes_out"

    -- Protocol Version Information
    s2n_connection_get_client_protocol_version <- mk_s2n_connection_get_client_protocol_version <$> loadSym dl "s2n_connection_get_client_protocol_version"
    s2n_connection_get_server_protocol_version <- mk_s2n_connection_get_server_protocol_version <$> loadSym dl "s2n_connection_get_server_protocol_version"
    s2n_connection_get_actual_protocol_version <- mk_s2n_connection_get_actual_protocol_version <$> loadSym dl "s2n_connection_get_actual_protocol_version"
    s2n_connection_get_client_hello_version <- mk_s2n_connection_get_client_hello_version <$> loadSym dl "s2n_connection_get_client_hello_version"

    -- Cipher & Security Information
    s2n_connection_get_cipher <- mk_s2n_connection_get_cipher <$> loadSym dl "s2n_connection_get_cipher"
    s2n_connection_get_certificate_match <- mk_s2n_connection_get_certificate_match <$> loadSym dl "s2n_connection_get_certificate_match"
    s2n_connection_get_master_secret <- mk_s2n_connection_get_master_secret <$> loadSym dl "s2n_connection_get_master_secret"
    s2n_connection_tls_exporter <- mk_s2n_connection_tls_exporter <$> loadSym dl "s2n_connection_tls_exporter"
    s2n_connection_get_cipher_iana_value <- mk_s2n_connection_get_cipher_iana_value <$> loadSym dl "s2n_connection_get_cipher_iana_value"
    s2n_connection_is_valid_for_cipher_preferences <- mk_s2n_connection_is_valid_for_cipher_preferences <$> loadSym dl "s2n_connection_is_valid_for_cipher_preferences"
    s2n_connection_get_curve <- mk_s2n_connection_get_curve <$> loadSym dl "s2n_connection_get_curve"
    s2n_connection_get_kem_name <- mk_s2n_connection_get_kem_name <$> loadSym dl "s2n_connection_get_kem_name"
    s2n_connection_get_kem_group_name <- mk_s2n_connection_get_kem_group_name <$> loadSym dl "s2n_connection_get_kem_group_name"
    s2n_connection_get_key_exchange_group <- mk_s2n_connection_get_key_exchange_group <$> loadSym dl "s2n_connection_get_key_exchange_group"
    s2n_connection_get_alert <- mk_s2n_connection_get_alert <$> loadSym dl "s2n_connection_get_alert"
    s2n_connection_get_handshake_type_name <- mk_s2n_connection_get_handshake_type_name <$> loadSym dl "s2n_connection_get_handshake_type_name"
    s2n_connection_get_last_message_name <- mk_s2n_connection_get_last_message_name <$> loadSym dl "s2n_connection_get_last_message_name"

    -- Async Private Key Operations
    s2n_async_pkey_op_perform <- mk_s2n_async_pkey_op_perform <$> loadSym dl "s2n_async_pkey_op_perform"
    s2n_async_pkey_op_apply <- mk_s2n_async_pkey_op_apply <$> loadSym dl "s2n_async_pkey_op_apply"
    s2n_async_pkey_op_free <- mk_s2n_async_pkey_op_free <$> loadSym dl "s2n_async_pkey_op_free"
    s2n_async_pkey_op_get_op_type <- mk_s2n_async_pkey_op_get_op_type <$> loadSym dl "s2n_async_pkey_op_get_op_type"
    s2n_async_pkey_op_get_input_size <- mk_s2n_async_pkey_op_get_input_size <$> loadSym dl "s2n_async_pkey_op_get_input_size"
    s2n_async_pkey_op_get_input <- mk_s2n_async_pkey_op_get_input <$> loadSym dl "s2n_async_pkey_op_get_input"
    s2n_async_pkey_op_set_output <- mk_s2n_async_pkey_op_set_output <$> loadSym dl "s2n_async_pkey_op_set_output"

    -- Early Data
    s2n_connection_set_server_max_early_data_size <- mk_s2n_connection_set_server_max_early_data_size <$> loadSym dl "s2n_connection_set_server_max_early_data_size"
    s2n_connection_set_server_early_data_context <- mk_s2n_connection_set_server_early_data_context <$> loadSym dl "s2n_connection_set_server_early_data_context"
    s2n_connection_get_early_data_status <- mk_s2n_connection_get_early_data_status <$> loadSym dl "s2n_connection_get_early_data_status"
    s2n_connection_get_remaining_early_data_size <- mk_s2n_connection_get_remaining_early_data_size <$> loadSym dl "s2n_connection_get_remaining_early_data_size"
    s2n_connection_get_max_early_data_size <- mk_s2n_connection_get_max_early_data_size <$> loadSym dl "s2n_connection_get_max_early_data_size"
    s2n_send_early_data <- mk_s2n_send_early_data <$> loadSym dl "s2n_send_early_data"
    s2n_recv_early_data <- mk_s2n_recv_early_data <$> loadSym dl "s2n_recv_early_data"
    s2n_offered_early_data_get_context_length <- mk_s2n_offered_early_data_get_context_length <$> loadSym dl "s2n_offered_early_data_get_context_length"
    s2n_offered_early_data_get_context <- mk_s2n_offered_early_data_get_context <$> loadSym dl "s2n_offered_early_data_get_context"
    s2n_offered_early_data_reject <- mk_s2n_offered_early_data_reject <$> loadSym dl "s2n_offered_early_data_reject"
    s2n_offered_early_data_accept <- mk_s2n_offered_early_data_accept <$> loadSym dl "s2n_offered_early_data_accept"

    -- Connection Serialization
    s2n_connection_serialization_length <- mk_s2n_connection_serialization_length <$> loadSym dl "s2n_connection_serialization_length"
    s2n_connection_serialize <- mk_s2n_connection_serialize <$> loadSym dl "s2n_connection_serialize"
    s2n_connection_deserialize <- mk_s2n_connection_deserialize <$> loadSym dl "s2n_connection_deserialize"

    pure S2nTlsSys{..}

--------------------------------------------------------------------------------
-- Foreign Import Dynamic Declarations
--------------------------------------------------------------------------------

-- Initialization & Cleanup
foreign import ccall "dynamic" mk_s2n_init :: FunPtr S2nInit -> S2nInit
foreign import ccall "dynamic" mk_s2n_cleanup :: FunPtr S2nCleanup -> S2nCleanup
foreign import ccall "dynamic" mk_s2n_cleanup_final :: FunPtr S2nCleanupFinal -> S2nCleanupFinal
foreign import ccall "dynamic" mk_s2n_crypto_disable_init :: FunPtr S2nCryptoDisableInit -> S2nCryptoDisableInit
foreign import ccall "dynamic" mk_s2n_disable_atexit :: FunPtr S2nDisableAtexit -> S2nDisableAtexit
foreign import ccall "dynamic" mk_s2n_get_openssl_version :: FunPtr S2nGetOpensslVersion -> S2nGetOpensslVersion
foreign import ccall "dynamic" mk_s2n_get_fips_mode :: FunPtr S2nGetFipsMode -> S2nGetFipsMode

-- Error Handling
foreign import ccall "dynamic" mk_s2n_errno_location :: FunPtr S2nErrnoLocation -> S2nErrnoLocation
foreign import ccall "dynamic" mk_s2n_error_get_type :: FunPtr S2nErrorGetType -> S2nErrorGetType
foreign import ccall "dynamic" mk_s2n_strerror :: FunPtr S2nStrerror -> S2nStrerror
foreign import ccall "dynamic" mk_s2n_strerror_debug :: FunPtr S2nStrerrorDebug -> S2nStrerrorDebug
foreign import ccall "dynamic" mk_s2n_strerror_name :: FunPtr S2nStrerrorName -> S2nStrerrorName
foreign import ccall "dynamic" mk_s2n_strerror_source :: FunPtr S2nStrerrorSource -> S2nStrerrorSource

-- Stack Traces
foreign import ccall "dynamic" mk_s2n_stack_traces_enabled :: FunPtr S2nStackTracesEnabled -> S2nStackTracesEnabled
foreign import ccall "dynamic" mk_s2n_stack_traces_enabled_set :: FunPtr S2nStackTracesEnabledSet -> S2nStackTracesEnabledSet
foreign import ccall "dynamic" mk_s2n_calculate_stacktrace :: FunPtr S2nCalculateStacktrace -> S2nCalculateStacktrace
foreign import ccall "dynamic" mk_s2n_free_stacktrace :: FunPtr S2nFreeStacktrace -> S2nFreeStacktrace
foreign import ccall "dynamic" mk_s2n_get_stacktrace :: FunPtr S2nGetStacktrace -> S2nGetStacktrace

-- Config Management
foreign import ccall "dynamic" mk_s2n_config_new :: FunPtr S2nConfigNew -> S2nConfigNew
foreign import ccall "dynamic" mk_s2n_config_new_minimal :: FunPtr S2nConfigNewMinimal -> S2nConfigNewMinimal
foreign import ccall "dynamic" mk_s2n_config_free :: FunPtr S2nConfigFree -> S2nConfigFree
foreign import ccall "dynamic" mk_s2n_config_free_dhparams :: FunPtr S2nConfigFreeDhparams -> S2nConfigFreeDhparams
foreign import ccall "dynamic" mk_s2n_config_free_cert_chain_and_key :: FunPtr S2nConfigFreeCertChainAndKey -> S2nConfigFreeCertChainAndKey
foreign import ccall "dynamic" mk_s2n_config_set_wall_clock :: FunPtr S2nConfigSetWallClock -> S2nConfigSetWallClock
foreign import ccall "dynamic" mk_s2n_config_set_monotonic_clock :: FunPtr S2nConfigSetMonotonicClock -> S2nConfigSetMonotonicClock

-- Cache Callbacks
foreign import ccall "dynamic" mk_s2n_config_set_cache_store_callback :: FunPtr S2nConfigSetCacheStoreCallback -> S2nConfigSetCacheStoreCallback
foreign import ccall "dynamic" mk_s2n_config_set_cache_retrieve_callback :: FunPtr S2nConfigSetCacheRetrieveCallback -> S2nConfigSetCacheRetrieveCallback
foreign import ccall "dynamic" mk_s2n_config_set_cache_delete_callback :: FunPtr S2nConfigSetCacheDeleteCallback -> S2nConfigSetCacheDeleteCallback

-- Memory & Random Callbacks
foreign import ccall "dynamic" mk_s2n_mem_set_callbacks :: FunPtr S2nMemSetCallbacks -> S2nMemSetCallbacks
foreign import ccall "dynamic" mk_s2n_rand_set_callbacks :: FunPtr S2nRandSetCallbacks -> S2nRandSetCallbacks

-- Certificate Chain Management
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_new :: FunPtr S2nCertChainAndKeyNew -> S2nCertChainAndKeyNew
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_load_pem :: FunPtr S2nCertChainAndKeyLoadPem -> S2nCertChainAndKeyLoadPem
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_load_pem_bytes :: FunPtr S2nCertChainAndKeyLoadPemBytes -> S2nCertChainAndKeyLoadPemBytes
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_load_public_pem_bytes :: FunPtr S2nCertChainAndKeyLoadPublicPemBytes -> S2nCertChainAndKeyLoadPublicPemBytes
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_free :: FunPtr S2nCertChainAndKeyFree -> S2nCertChainAndKeyFree
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_set_ctx :: FunPtr S2nCertChainAndKeySetCtx -> S2nCertChainAndKeySetCtx
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_get_ctx :: FunPtr S2nCertChainAndKeyGetCtx -> S2nCertChainAndKeyGetCtx
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_get_private_key :: FunPtr S2nCertChainAndKeyGetPrivateKey -> S2nCertChainAndKeyGetPrivateKey
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_set_ocsp_data :: FunPtr S2nCertChainAndKeySetOcspData -> S2nCertChainAndKeySetOcspData
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_set_sct_list :: FunPtr S2nCertChainAndKeySetSctList -> S2nCertChainAndKeySetSctList
foreign import ccall "dynamic" mk_s2n_config_set_cert_tiebreak_callback :: FunPtr S2nConfigSetCertTiebreakCallback -> S2nConfigSetCertTiebreakCallback
foreign import ccall "dynamic" mk_s2n_config_add_cert_chain_and_key :: FunPtr S2nConfigAddCertChainAndKey -> S2nConfigAddCertChainAndKey
foreign import ccall "dynamic" mk_s2n_config_add_cert_chain_and_key_to_store :: FunPtr S2nConfigAddCertChainAndKeyToStore -> S2nConfigAddCertChainAndKeyToStore
foreign import ccall "dynamic" mk_s2n_config_set_cert_chain_and_key_defaults :: FunPtr S2nConfigSetCertChainAndKeyDefaults -> S2nConfigSetCertChainAndKeyDefaults

-- Trust Store
foreign import ccall "dynamic" mk_s2n_config_set_verification_ca_location :: FunPtr S2nConfigSetVerificationCaLocation -> S2nConfigSetVerificationCaLocation
foreign import ccall "dynamic" mk_s2n_config_add_pem_to_trust_store :: FunPtr S2nConfigAddPemToTrustStore -> S2nConfigAddPemToTrustStore
foreign import ccall "dynamic" mk_s2n_config_wipe_trust_store :: FunPtr S2nConfigWipeTrustStore -> S2nConfigWipeTrustStore
foreign import ccall "dynamic" mk_s2n_config_load_system_certs :: FunPtr S2nConfigLoadSystemCerts -> S2nConfigLoadSystemCerts
foreign import ccall "dynamic" mk_s2n_config_set_cert_authorities_from_trust_store :: FunPtr S2nConfigSetCertAuthoritiesFromTrustStore -> S2nConfigSetCertAuthoritiesFromTrustStore

-- Verification & Validation
foreign import ccall "dynamic" mk_s2n_config_set_verify_after_sign :: FunPtr S2nConfigSetVerifyAfterSign -> S2nConfigSetVerifyAfterSign
foreign import ccall "dynamic" mk_s2n_config_set_check_stapled_ocsp_response :: FunPtr S2nConfigSetCheckStapledOcspResponse -> S2nConfigSetCheckStapledOcspResponse
foreign import ccall "dynamic" mk_s2n_config_disable_x509_time_verification :: FunPtr S2nConfigDisableX509TimeVerification -> S2nConfigDisableX509TimeVerification
foreign import ccall "dynamic" mk_s2n_config_disable_x509_intent_verification :: FunPtr S2nConfigDisableX509IntentVerification -> S2nConfigDisableX509IntentVerification
foreign import ccall "dynamic" mk_s2n_config_disable_x509_verification :: FunPtr S2nConfigDisableX509Verification -> S2nConfigDisableX509Verification
foreign import ccall "dynamic" mk_s2n_config_set_max_cert_chain_depth :: FunPtr S2nConfigSetMaxCertChainDepth -> S2nConfigSetMaxCertChainDepth
foreign import ccall "dynamic" mk_s2n_config_set_verify_host_callback :: FunPtr S2nConfigSetVerifyHostCallback -> S2nConfigSetVerifyHostCallback

-- DH Parameters
foreign import ccall "dynamic" mk_s2n_config_add_dhparams :: FunPtr S2nConfigAddDhparams -> S2nConfigAddDhparams

-- Security Policies & Preferences
foreign import ccall "dynamic" mk_s2n_config_set_cipher_preferences :: FunPtr S2nConfigSetCipherPreferences -> S2nConfigSetCipherPreferences
foreign import ccall "dynamic" mk_s2n_config_append_protocol_preference :: FunPtr S2nConfigAppendProtocolPreference -> S2nConfigAppendProtocolPreference
foreign import ccall "dynamic" mk_s2n_config_set_protocol_preferences :: FunPtr S2nConfigSetProtocolPreferences -> S2nConfigSetProtocolPreferences
foreign import ccall "dynamic" mk_s2n_config_set_status_request_type :: FunPtr S2nConfigSetStatusRequestType -> S2nConfigSetStatusRequestType
foreign import ccall "dynamic" mk_s2n_config_set_ct_support_level :: FunPtr S2nConfigSetCtSupportLevel -> S2nConfigSetCtSupportLevel
foreign import ccall "dynamic" mk_s2n_config_set_alert_behavior :: FunPtr S2nConfigSetAlertBehavior -> S2nConfigSetAlertBehavior

-- Extension Data
foreign import ccall "dynamic" mk_s2n_config_set_extension_data :: FunPtr S2nConfigSetExtensionData -> S2nConfigSetExtensionData
foreign import ccall "dynamic" mk_s2n_config_send_max_fragment_length :: FunPtr S2nConfigSendMaxFragmentLength -> S2nConfigSendMaxFragmentLength
foreign import ccall "dynamic" mk_s2n_config_accept_max_fragment_length :: FunPtr S2nConfigAcceptMaxFragmentLength -> S2nConfigAcceptMaxFragmentLength

-- Session & Ticket Configuration
foreign import ccall "dynamic" mk_s2n_config_set_session_state_lifetime :: FunPtr S2nConfigSetSessionStateLifetime -> S2nConfigSetSessionStateLifetime
foreign import ccall "dynamic" mk_s2n_config_set_session_tickets_onoff :: FunPtr S2nConfigSetSessionTicketsOnoff -> S2nConfigSetSessionTicketsOnoff
foreign import ccall "dynamic" mk_s2n_config_set_session_cache_onoff :: FunPtr S2nConfigSetSessionCacheOnoff -> S2nConfigSetSessionCacheOnoff
foreign import ccall "dynamic" mk_s2n_config_set_ticket_encrypt_decrypt_key_lifetime :: FunPtr S2nConfigSetTicketEncryptDecryptKeyLifetime -> S2nConfigSetTicketEncryptDecryptKeyLifetime
foreign import ccall "dynamic" mk_s2n_config_set_ticket_decrypt_key_lifetime :: FunPtr S2nConfigSetTicketDecryptKeyLifetime -> S2nConfigSetTicketDecryptKeyLifetime
foreign import ccall "dynamic" mk_s2n_config_add_ticket_crypto_key :: FunPtr S2nConfigAddTicketCryptoKey -> S2nConfigAddTicketCryptoKey
foreign import ccall "dynamic" mk_s2n_config_require_ticket_forward_secrecy :: FunPtr S2nConfigRequireTicketForwardSecrecy -> S2nConfigRequireTicketForwardSecrecy

-- Buffer & I/O Configuration
foreign import ccall "dynamic" mk_s2n_config_set_send_buffer_size :: FunPtr S2nConfigSetSendBufferSize -> S2nConfigSetSendBufferSize
foreign import ccall "dynamic" mk_s2n_config_set_recv_multi_record :: FunPtr S2nConfigSetRecvMultiRecord -> S2nConfigSetRecvMultiRecord

-- Miscellaneous Config
foreign import ccall "dynamic" mk_s2n_config_set_ctx :: FunPtr S2nConfigSetCtx -> S2nConfigSetCtx
foreign import ccall "dynamic" mk_s2n_config_get_ctx :: FunPtr S2nConfigGetCtx -> S2nConfigGetCtx
foreign import ccall "dynamic" mk_s2n_config_set_client_hello_cb :: FunPtr S2nConfigSetClientHelloCb -> S2nConfigSetClientHelloCb
foreign import ccall "dynamic" mk_s2n_config_set_client_hello_cb_mode :: FunPtr S2nConfigSetClientHelloCbMode -> S2nConfigSetClientHelloCbMode
foreign import ccall "dynamic" mk_s2n_config_set_max_blinding_delay :: FunPtr S2nConfigSetMaxBlindingDelay -> S2nConfigSetMaxBlindingDelay
foreign import ccall "dynamic" mk_s2n_config_get_client_auth_type :: FunPtr S2nConfigGetClientAuthType -> S2nConfigGetClientAuthType
foreign import ccall "dynamic" mk_s2n_config_set_client_auth_type :: FunPtr S2nConfigSetClientAuthType -> S2nConfigSetClientAuthType
foreign import ccall "dynamic" mk_s2n_config_set_initial_ticket_count :: FunPtr S2nConfigSetInitialTicketCount -> S2nConfigSetInitialTicketCount
foreign import ccall "dynamic" mk_s2n_config_set_psk_mode :: FunPtr S2nConfigSetPskMode -> S2nConfigSetPskMode
foreign import ccall "dynamic" mk_s2n_config_set_psk_selection_callback :: FunPtr S2nConfigSetPskSelectionCallback -> S2nConfigSetPskSelectionCallback
foreign import ccall "dynamic" mk_s2n_config_set_async_pkey_callback :: FunPtr S2nConfigSetAsyncPkeyCallback -> S2nConfigSetAsyncPkeyCallback
foreign import ccall "dynamic" mk_s2n_config_set_async_pkey_validation_mode :: FunPtr S2nConfigSetAsyncPkeyValidationMode -> S2nConfigSetAsyncPkeyValidationMode
foreign import ccall "dynamic" mk_s2n_config_set_session_ticket_cb :: FunPtr S2nConfigSetSessionTicketCb -> S2nConfigSetSessionTicketCb
foreign import ccall "dynamic" mk_s2n_config_set_key_log_cb :: FunPtr S2nConfigSetKeyLogCb -> S2nConfigSetKeyLogCb
foreign import ccall "dynamic" mk_s2n_config_enable_cert_req_dss_legacy_compat :: FunPtr S2nConfigEnableCertReqDssLegacyCompat -> S2nConfigEnableCertReqDssLegacyCompat
foreign import ccall "dynamic" mk_s2n_config_set_server_max_early_data_size :: FunPtr S2nConfigSetServerMaxEarlyDataSize -> S2nConfigSetServerMaxEarlyDataSize
foreign import ccall "dynamic" mk_s2n_config_set_early_data_cb :: FunPtr S2nConfigSetEarlyDataCb -> S2nConfigSetEarlyDataCb
foreign import ccall "dynamic" mk_s2n_config_get_supported_groups :: FunPtr S2nConfigGetSupportedGroups -> S2nConfigGetSupportedGroups
foreign import ccall "dynamic" mk_s2n_config_set_serialization_version :: FunPtr S2nConfigSetSerializationVersion -> S2nConfigSetSerializationVersion

-- Connection Creation & Management
foreign import ccall "dynamic" mk_s2n_connection_new :: FunPtr S2nConnectionNew -> S2nConnectionNew
foreign import ccall "dynamic" mk_s2n_connection_set_config :: FunPtr S2nConnectionSetConfig -> S2nConnectionSetConfig
foreign import ccall "dynamic" mk_s2n_connection_set_ctx :: FunPtr S2nConnectionSetCtx -> S2nConnectionSetCtx
foreign import ccall "dynamic" mk_s2n_connection_get_ctx :: FunPtr S2nConnectionGetCtx -> S2nConnectionGetCtx
foreign import ccall "dynamic" mk_s2n_client_hello_cb_done :: FunPtr S2nClientHelloCbDone -> S2nClientHelloCbDone
foreign import ccall "dynamic" mk_s2n_connection_server_name_extension_used :: FunPtr S2nConnectionServerNameExtensionUsed -> S2nConnectionServerNameExtensionUsed

-- Client Hello Access
foreign import ccall "dynamic" mk_s2n_connection_get_client_hello :: FunPtr S2nConnectionGetClientHello -> S2nConnectionGetClientHello
foreign import ccall "dynamic" mk_s2n_client_hello_parse_message :: FunPtr S2nClientHelloParseMessage -> S2nClientHelloParseMessage
foreign import ccall "dynamic" mk_s2n_client_hello_free :: FunPtr S2nClientHelloFree -> S2nClientHelloFree
foreign import ccall "dynamic" mk_s2n_client_hello_get_raw_message_length :: FunPtr S2nClientHelloGetRawMessageLength -> S2nClientHelloGetRawMessageLength
foreign import ccall "dynamic" mk_s2n_client_hello_get_raw_message :: FunPtr S2nClientHelloGetRawMessage -> S2nClientHelloGetRawMessage
foreign import ccall "dynamic" mk_s2n_client_hello_get_cipher_suites_length :: FunPtr S2nClientHelloGetCipherSuitesLength -> S2nClientHelloGetCipherSuitesLength
foreign import ccall "dynamic" mk_s2n_client_hello_get_cipher_suites :: FunPtr S2nClientHelloGetCipherSuites -> S2nClientHelloGetCipherSuites
foreign import ccall "dynamic" mk_s2n_client_hello_get_extensions_length :: FunPtr S2nClientHelloGetExtensionsLength -> S2nClientHelloGetExtensionsLength
foreign import ccall "dynamic" mk_s2n_client_hello_get_extensions :: FunPtr S2nClientHelloGetExtensions -> S2nClientHelloGetExtensions
foreign import ccall "dynamic" mk_s2n_client_hello_get_extension_length :: FunPtr S2nClientHelloGetExtensionLength -> S2nClientHelloGetExtensionLength
foreign import ccall "dynamic" mk_s2n_client_hello_get_extension_by_id :: FunPtr S2nClientHelloGetExtensionById -> S2nClientHelloGetExtensionById
foreign import ccall "dynamic" mk_s2n_client_hello_has_extension :: FunPtr S2nClientHelloHasExtension -> S2nClientHelloHasExtension
foreign import ccall "dynamic" mk_s2n_client_hello_get_session_id_length :: FunPtr S2nClientHelloGetSessionIdLength -> S2nClientHelloGetSessionIdLength
foreign import ccall "dynamic" mk_s2n_client_hello_get_session_id :: FunPtr S2nClientHelloGetSessionId -> S2nClientHelloGetSessionId
foreign import ccall "dynamic" mk_s2n_client_hello_get_compression_methods_length :: FunPtr S2nClientHelloGetCompressionMethodsLength -> S2nClientHelloGetCompressionMethodsLength
foreign import ccall "dynamic" mk_s2n_client_hello_get_compression_methods :: FunPtr S2nClientHelloGetCompressionMethods -> S2nClientHelloGetCompressionMethods
foreign import ccall "dynamic" mk_s2n_client_hello_get_legacy_protocol_version :: FunPtr S2nClientHelloGetLegacyProtocolVersion -> S2nClientHelloGetLegacyProtocolVersion
foreign import ccall "dynamic" mk_s2n_client_hello_get_random :: FunPtr S2nClientHelloGetRandom -> S2nClientHelloGetRandom
foreign import ccall "dynamic" mk_s2n_client_hello_get_supported_groups :: FunPtr S2nClientHelloGetSupportedGroups -> S2nClientHelloGetSupportedGroups
foreign import ccall "dynamic" mk_s2n_client_hello_get_server_name_length :: FunPtr S2nClientHelloGetServerNameLength -> S2nClientHelloGetServerNameLength
foreign import ccall "dynamic" mk_s2n_client_hello_get_server_name :: FunPtr S2nClientHelloGetServerName -> S2nClientHelloGetServerName
foreign import ccall "dynamic" mk_s2n_client_hello_get_legacy_record_version :: FunPtr S2nClientHelloGetLegacyRecordVersion -> S2nClientHelloGetLegacyRecordVersion

-- File Descriptor & I/O
foreign import ccall "dynamic" mk_s2n_connection_set_fd :: FunPtr S2nConnectionSetFd -> S2nConnectionSetFd
foreign import ccall "dynamic" mk_s2n_connection_set_read_fd :: FunPtr S2nConnectionSetReadFd -> S2nConnectionSetReadFd
foreign import ccall "dynamic" mk_s2n_connection_set_write_fd :: FunPtr S2nConnectionSetWriteFd -> S2nConnectionSetWriteFd
foreign import ccall "dynamic" mk_s2n_connection_get_read_fd :: FunPtr S2nConnectionGetReadFd -> S2nConnectionGetReadFd
foreign import ccall "dynamic" mk_s2n_connection_get_write_fd :: FunPtr S2nConnectionGetWriteFd -> S2nConnectionGetWriteFd
foreign import ccall "dynamic" mk_s2n_connection_use_corked_io :: FunPtr S2nConnectionUseCorkedIo -> S2nConnectionUseCorkedIo
foreign import ccall "dynamic" mk_s2n_connection_set_recv_ctx :: FunPtr S2nConnectionSetRecvCtx -> S2nConnectionSetRecvCtx
foreign import ccall "dynamic" mk_s2n_connection_set_send_ctx :: FunPtr S2nConnectionSetSendCtx -> S2nConnectionSetSendCtx
foreign import ccall "dynamic" mk_s2n_connection_set_recv_cb :: FunPtr S2nConnectionSetRecvCb -> S2nConnectionSetRecvCb
foreign import ccall "dynamic" mk_s2n_connection_set_send_cb :: FunPtr S2nConnectionSetSendCb -> S2nConnectionSetSendCb

-- Connection Preferences
foreign import ccall "dynamic" mk_s2n_connection_prefer_throughput :: FunPtr S2nConnectionPreferThroughput -> S2nConnectionPreferThroughput
foreign import ccall "dynamic" mk_s2n_connection_prefer_low_latency :: FunPtr S2nConnectionPreferLowLatency -> S2nConnectionPreferLowLatency
foreign import ccall "dynamic" mk_s2n_connection_set_recv_buffering :: FunPtr S2nConnectionSetRecvBuffering -> S2nConnectionSetRecvBuffering
foreign import ccall "dynamic" mk_s2n_peek_buffered :: FunPtr S2nPeekBuffered -> S2nPeekBuffered
foreign import ccall "dynamic" mk_s2n_connection_set_dynamic_buffers :: FunPtr S2nConnectionSetDynamicBuffers -> S2nConnectionSetDynamicBuffers
foreign import ccall "dynamic" mk_s2n_connection_set_dynamic_record_threshold :: FunPtr S2nConnectionSetDynamicRecordThreshold -> S2nConnectionSetDynamicRecordThreshold

-- Host Verification
foreign import ccall "dynamic" mk_s2n_connection_set_verify_host_callback :: FunPtr S2nConnectionSetVerifyHostCallback -> S2nConnectionSetVerifyHostCallback

-- Blinding & Security
foreign import ccall "dynamic" mk_s2n_connection_set_blinding :: FunPtr S2nConnectionSetBlinding -> S2nConnectionSetBlinding
foreign import ccall "dynamic" mk_s2n_connection_get_delay :: FunPtr S2nConnectionGetDelay -> S2nConnectionGetDelay

-- Cipher & Protocol Configuration
foreign import ccall "dynamic" mk_s2n_connection_set_cipher_preferences :: FunPtr S2nConnectionSetCipherPreferences -> S2nConnectionSetCipherPreferences
foreign import ccall "dynamic" mk_s2n_connection_request_key_update :: FunPtr S2nConnectionRequestKeyUpdate -> S2nConnectionRequestKeyUpdate
foreign import ccall "dynamic" mk_s2n_connection_append_protocol_preference :: FunPtr S2nConnectionAppendProtocolPreference -> S2nConnectionAppendProtocolPreference
foreign import ccall "dynamic" mk_s2n_connection_set_protocol_preferences :: FunPtr S2nConnectionSetProtocolPreferences -> S2nConnectionSetProtocolPreferences

-- Server Name (SNI)
foreign import ccall "dynamic" mk_s2n_set_server_name :: FunPtr S2nSetServerName -> S2nSetServerName
foreign import ccall "dynamic" mk_s2n_get_server_name :: FunPtr S2nGetServerName -> S2nGetServerName

-- Application Protocol (ALPN)
foreign import ccall "dynamic" mk_s2n_get_application_protocol :: FunPtr S2nGetApplicationProtocol -> S2nGetApplicationProtocol

-- OCSP & Certificate Transparency
foreign import ccall "dynamic" mk_s2n_connection_get_ocsp_response :: FunPtr S2nConnectionGetOcspResponse -> S2nConnectionGetOcspResponse
foreign import ccall "dynamic" mk_s2n_connection_get_sct_list :: FunPtr S2nConnectionGetSctList -> S2nConnectionGetSctList

-- Handshake & TLS Operations
foreign import ccall "dynamic" mk_s2n_negotiate :: FunPtr S2nNegotiate -> S2nNegotiate
foreign import ccall "dynamic" mk_s2n_send :: FunPtr S2nSend -> S2nSend
foreign import ccall "dynamic" mk_s2n_recv :: FunPtr S2nRecv -> S2nRecv
foreign import ccall "dynamic" mk_s2n_peek :: FunPtr S2nPeek -> S2nPeek
foreign import ccall "dynamic" mk_s2n_connection_free_handshake :: FunPtr S2nConnectionFreeHandshake -> S2nConnectionFreeHandshake
foreign import ccall "dynamic" mk_s2n_connection_release_buffers :: FunPtr S2nConnectionReleaseBuffers -> S2nConnectionReleaseBuffers
foreign import ccall "dynamic" mk_s2n_connection_wipe :: FunPtr S2nConnectionWipe -> S2nConnectionWipe
foreign import ccall "dynamic" mk_s2n_connection_free :: FunPtr S2nConnectionFree -> S2nConnectionFree
foreign import ccall "dynamic" mk_s2n_shutdown :: FunPtr S2nShutdown -> S2nShutdown
foreign import ccall "dynamic" mk_s2n_shutdown_send :: FunPtr S2nShutdownSend -> S2nShutdownSend

-- Client Authentication
foreign import ccall "dynamic" mk_s2n_connection_get_client_auth_type :: FunPtr S2nConnectionGetClientAuthType -> S2nConnectionGetClientAuthType
foreign import ccall "dynamic" mk_s2n_connection_set_client_auth_type :: FunPtr S2nConnectionSetClientAuthType -> S2nConnectionSetClientAuthType
foreign import ccall "dynamic" mk_s2n_connection_get_client_cert_chain :: FunPtr S2nConnectionGetClientCertChain -> S2nConnectionGetClientCertChain
foreign import ccall "dynamic" mk_s2n_connection_client_cert_used :: FunPtr S2nConnectionClientCertUsed -> S2nConnectionClientCertUsed

-- Session Management
foreign import ccall "dynamic" mk_s2n_connection_add_new_tickets_to_send :: FunPtr S2nConnectionAddNewTicketsToSend -> S2nConnectionAddNewTicketsToSend
foreign import ccall "dynamic" mk_s2n_connection_get_tickets_sent :: FunPtr S2nConnectionGetTicketsSent -> S2nConnectionGetTicketsSent
foreign import ccall "dynamic" mk_s2n_connection_set_server_keying_material_lifetime :: FunPtr S2nConnectionSetServerKeyingMaterialLifetime -> S2nConnectionSetServerKeyingMaterialLifetime
foreign import ccall "dynamic" mk_s2n_session_ticket_get_data_len :: FunPtr S2nSessionTicketGetDataLen -> S2nSessionTicketGetDataLen
foreign import ccall "dynamic" mk_s2n_session_ticket_get_data :: FunPtr S2nSessionTicketGetData -> S2nSessionTicketGetData
foreign import ccall "dynamic" mk_s2n_session_ticket_get_lifetime :: FunPtr S2nSessionTicketGetLifetime -> S2nSessionTicketGetLifetime
foreign import ccall "dynamic" mk_s2n_connection_set_session :: FunPtr S2nConnectionSetSession -> S2nConnectionSetSession
foreign import ccall "dynamic" mk_s2n_connection_get_session :: FunPtr S2nConnectionGetSession -> S2nConnectionGetSession
foreign import ccall "dynamic" mk_s2n_connection_get_session_ticket_lifetime_hint :: FunPtr S2nConnectionGetSessionTicketLifetimeHint -> S2nConnectionGetSessionTicketLifetimeHint
foreign import ccall "dynamic" mk_s2n_connection_get_session_length :: FunPtr S2nConnectionGetSessionLength -> S2nConnectionGetSessionLength
foreign import ccall "dynamic" mk_s2n_connection_get_session_id_length :: FunPtr S2nConnectionGetSessionIdLength -> S2nConnectionGetSessionIdLength
foreign import ccall "dynamic" mk_s2n_connection_get_session_id :: FunPtr S2nConnectionGetSessionId -> S2nConnectionGetSessionId
foreign import ccall "dynamic" mk_s2n_connection_is_session_resumed :: FunPtr S2nConnectionIsSessionResumed -> S2nConnectionIsSessionResumed

-- Certificate Information
foreign import ccall "dynamic" mk_s2n_connection_is_ocsp_stapled :: FunPtr S2nConnectionIsOcspStapled -> S2nConnectionIsOcspStapled
foreign import ccall "dynamic" mk_s2n_connection_get_selected_signature_algorithm :: FunPtr S2nConnectionGetSelectedSignatureAlgorithm -> S2nConnectionGetSelectedSignatureAlgorithm
foreign import ccall "dynamic" mk_s2n_connection_get_selected_digest_algorithm :: FunPtr S2nConnectionGetSelectedDigestAlgorithm -> S2nConnectionGetSelectedDigestAlgorithm
foreign import ccall "dynamic" mk_s2n_connection_get_selected_client_cert_signature_algorithm :: FunPtr S2nConnectionGetSelectedClientCertSignatureAlgorithm -> S2nConnectionGetSelectedClientCertSignatureAlgorithm
foreign import ccall "dynamic" mk_s2n_connection_get_selected_client_cert_digest_algorithm :: FunPtr S2nConnectionGetSelectedClientCertDigestAlgorithm -> S2nConnectionGetSelectedClientCertDigestAlgorithm
foreign import ccall "dynamic" mk_s2n_connection_get_signature_scheme :: FunPtr S2nConnectionGetSignatureScheme -> S2nConnectionGetSignatureScheme
foreign import ccall "dynamic" mk_s2n_connection_get_selected_cert :: FunPtr S2nConnectionGetSelectedCert -> S2nConnectionGetSelectedCert
foreign import ccall "dynamic" mk_s2n_cert_chain_get_length :: FunPtr S2nCertChainGetLength -> S2nCertChainGetLength
foreign import ccall "dynamic" mk_s2n_cert_chain_get_cert :: FunPtr S2nCertChainGetCert -> S2nCertChainGetCert
foreign import ccall "dynamic" mk_s2n_cert_get_der :: FunPtr S2nCertGetDer -> S2nCertGetDer
foreign import ccall "dynamic" mk_s2n_connection_get_peer_cert_chain :: FunPtr S2nConnectionGetPeerCertChain -> S2nConnectionGetPeerCertChain
foreign import ccall "dynamic" mk_s2n_cert_get_x509_extension_value_length :: FunPtr S2nCertGetX509ExtensionValueLength -> S2nCertGetX509ExtensionValueLength
foreign import ccall "dynamic" mk_s2n_cert_get_x509_extension_value :: FunPtr S2nCertGetX509ExtensionValue -> S2nCertGetX509ExtensionValue
foreign import ccall "dynamic" mk_s2n_cert_get_utf8_string_from_extension_data_length :: FunPtr S2nCertGetUtf8StringFromExtensionDataLength -> S2nCertGetUtf8StringFromExtensionDataLength
foreign import ccall "dynamic" mk_s2n_cert_get_utf8_string_from_extension_data :: FunPtr S2nCertGetUtf8StringFromExtensionData -> S2nCertGetUtf8StringFromExtensionData

-- Pre-Shared Keys (PSK)
foreign import ccall "dynamic" mk_s2n_external_psk_new :: FunPtr S2nExternalPskNew -> S2nExternalPskNew
foreign import ccall "dynamic" mk_s2n_psk_free :: FunPtr S2nPskFree -> S2nPskFree
foreign import ccall "dynamic" mk_s2n_psk_set_identity :: FunPtr S2nPskSetIdentity -> S2nPskSetIdentity
foreign import ccall "dynamic" mk_s2n_psk_set_secret :: FunPtr S2nPskSetSecret -> S2nPskSetSecret
foreign import ccall "dynamic" mk_s2n_psk_set_hmac :: FunPtr S2nPskSetHmac -> S2nPskSetHmac
foreign import ccall "dynamic" mk_s2n_connection_append_psk :: FunPtr S2nConnectionAppendPsk -> S2nConnectionAppendPsk
foreign import ccall "dynamic" mk_s2n_connection_set_psk_mode :: FunPtr S2nConnectionSetPskMode -> S2nConnectionSetPskMode
foreign import ccall "dynamic" mk_s2n_connection_get_negotiated_psk_identity_length :: FunPtr S2nConnectionGetNegotiatedPskIdentityLength -> S2nConnectionGetNegotiatedPskIdentityLength
foreign import ccall "dynamic" mk_s2n_connection_get_negotiated_psk_identity :: FunPtr S2nConnectionGetNegotiatedPskIdentity -> S2nConnectionGetNegotiatedPskIdentity
foreign import ccall "dynamic" mk_s2n_offered_psk_new :: FunPtr S2nOfferedPskNew -> S2nOfferedPskNew
foreign import ccall "dynamic" mk_s2n_offered_psk_free :: FunPtr S2nOfferedPskFree -> S2nOfferedPskFree
foreign import ccall "dynamic" mk_s2n_offered_psk_get_identity :: FunPtr S2nOfferedPskGetIdentity -> S2nOfferedPskGetIdentity
foreign import ccall "dynamic" mk_s2n_offered_psk_list_has_next :: FunPtr S2nOfferedPskListHasNext -> S2nOfferedPskListHasNext
foreign import ccall "dynamic" mk_s2n_offered_psk_list_next :: FunPtr S2nOfferedPskListNext -> S2nOfferedPskListNext
foreign import ccall "dynamic" mk_s2n_offered_psk_list_reread :: FunPtr S2nOfferedPskListReread -> S2nOfferedPskListReread
foreign import ccall "dynamic" mk_s2n_offered_psk_list_choose_psk :: FunPtr S2nOfferedPskListChoosePsk -> S2nOfferedPskListChoosePsk
foreign import ccall "dynamic" mk_s2n_psk_configure_early_data :: FunPtr S2nPskConfigureEarlyData -> S2nPskConfigureEarlyData
foreign import ccall "dynamic" mk_s2n_psk_set_application_protocol :: FunPtr S2nPskSetApplicationProtocol -> S2nPskSetApplicationProtocol
foreign import ccall "dynamic" mk_s2n_psk_set_early_data_context :: FunPtr S2nPskSetEarlyDataContext -> S2nPskSetEarlyDataContext

-- Connection Statistics
foreign import ccall "dynamic" mk_s2n_connection_get_wire_bytes_in :: FunPtr S2nConnectionGetWireBytesIn -> S2nConnectionGetWireBytesIn
foreign import ccall "dynamic" mk_s2n_connection_get_wire_bytes_out :: FunPtr S2nConnectionGetWireBytesOut -> S2nConnectionGetWireBytesOut

-- Protocol Version Information
foreign import ccall "dynamic" mk_s2n_connection_get_client_protocol_version :: FunPtr S2nConnectionGetClientProtocolVersion -> S2nConnectionGetClientProtocolVersion
foreign import ccall "dynamic" mk_s2n_connection_get_server_protocol_version :: FunPtr S2nConnectionGetServerProtocolVersion -> S2nConnectionGetServerProtocolVersion
foreign import ccall "dynamic" mk_s2n_connection_get_actual_protocol_version :: FunPtr S2nConnectionGetActualProtocolVersion -> S2nConnectionGetActualProtocolVersion
foreign import ccall "dynamic" mk_s2n_connection_get_client_hello_version :: FunPtr S2nConnectionGetClientHelloVersion -> S2nConnectionGetClientHelloVersion

-- Cipher & Security Information
foreign import ccall "dynamic" mk_s2n_connection_get_cipher :: FunPtr S2nConnectionGetCipher -> S2nConnectionGetCipher
foreign import ccall "dynamic" mk_s2n_connection_get_certificate_match :: FunPtr S2nConnectionGetCertificateMatch -> S2nConnectionGetCertificateMatch
foreign import ccall "dynamic" mk_s2n_connection_get_master_secret :: FunPtr S2nConnectionGetMasterSecret -> S2nConnectionGetMasterSecret
foreign import ccall "dynamic" mk_s2n_connection_tls_exporter :: FunPtr S2nConnectionTlsExporter -> S2nConnectionTlsExporter
foreign import ccall "dynamic" mk_s2n_connection_get_cipher_iana_value :: FunPtr S2nConnectionGetCipherIanaValue -> S2nConnectionGetCipherIanaValue
foreign import ccall "dynamic" mk_s2n_connection_is_valid_for_cipher_preferences :: FunPtr S2nConnectionIsValidForCipherPreferences -> S2nConnectionIsValidForCipherPreferences
foreign import ccall "dynamic" mk_s2n_connection_get_curve :: FunPtr S2nConnectionGetCurve -> S2nConnectionGetCurve
foreign import ccall "dynamic" mk_s2n_connection_get_kem_name :: FunPtr S2nConnectionGetKemName -> S2nConnectionGetKemName
foreign import ccall "dynamic" mk_s2n_connection_get_kem_group_name :: FunPtr S2nConnectionGetKemGroupName -> S2nConnectionGetKemGroupName
foreign import ccall "dynamic" mk_s2n_connection_get_key_exchange_group :: FunPtr S2nConnectionGetKeyExchangeGroup -> S2nConnectionGetKeyExchangeGroup
foreign import ccall "dynamic" mk_s2n_connection_get_alert :: FunPtr S2nConnectionGetAlert -> S2nConnectionGetAlert
foreign import ccall "dynamic" mk_s2n_connection_get_handshake_type_name :: FunPtr S2nConnectionGetHandshakeTypeName -> S2nConnectionGetHandshakeTypeName
foreign import ccall "dynamic" mk_s2n_connection_get_last_message_name :: FunPtr S2nConnectionGetLastMessageName -> S2nConnectionGetLastMessageName

-- Async Private Key Operations
foreign import ccall "dynamic" mk_s2n_async_pkey_op_perform :: FunPtr S2nAsyncPkeyOpPerform -> S2nAsyncPkeyOpPerform
foreign import ccall "dynamic" mk_s2n_async_pkey_op_apply :: FunPtr S2nAsyncPkeyOpApply -> S2nAsyncPkeyOpApply
foreign import ccall "dynamic" mk_s2n_async_pkey_op_free :: FunPtr S2nAsyncPkeyOpFree -> S2nAsyncPkeyOpFree
foreign import ccall "dynamic" mk_s2n_async_pkey_op_get_op_type :: FunPtr S2nAsyncPkeyOpGetOpType -> S2nAsyncPkeyOpGetOpType
foreign import ccall "dynamic" mk_s2n_async_pkey_op_get_input_size :: FunPtr S2nAsyncPkeyOpGetInputSize -> S2nAsyncPkeyOpGetInputSize
foreign import ccall "dynamic" mk_s2n_async_pkey_op_get_input :: FunPtr S2nAsyncPkeyOpGetInput -> S2nAsyncPkeyOpGetInput
foreign import ccall "dynamic" mk_s2n_async_pkey_op_set_output :: FunPtr S2nAsyncPkeyOpSetOutput -> S2nAsyncPkeyOpSetOutput

-- Early Data
foreign import ccall "dynamic" mk_s2n_connection_set_server_max_early_data_size :: FunPtr S2nConnectionSetServerMaxEarlyDataSize -> S2nConnectionSetServerMaxEarlyDataSize
foreign import ccall "dynamic" mk_s2n_connection_set_server_early_data_context :: FunPtr S2nConnectionSetServerEarlyDataContext -> S2nConnectionSetServerEarlyDataContext
foreign import ccall "dynamic" mk_s2n_connection_get_early_data_status :: FunPtr S2nConnectionGetEarlyDataStatus -> S2nConnectionGetEarlyDataStatus
foreign import ccall "dynamic" mk_s2n_connection_get_remaining_early_data_size :: FunPtr S2nConnectionGetRemainingEarlyDataSize -> S2nConnectionGetRemainingEarlyDataSize
foreign import ccall "dynamic" mk_s2n_connection_get_max_early_data_size :: FunPtr S2nConnectionGetMaxEarlyDataSize -> S2nConnectionGetMaxEarlyDataSize
foreign import ccall "dynamic" mk_s2n_send_early_data :: FunPtr S2nSendEarlyData -> S2nSendEarlyData
foreign import ccall "dynamic" mk_s2n_recv_early_data :: FunPtr S2nRecvEarlyData -> S2nRecvEarlyData
foreign import ccall "dynamic" mk_s2n_offered_early_data_get_context_length :: FunPtr S2nOfferedEarlyDataGetContextLength -> S2nOfferedEarlyDataGetContextLength
foreign import ccall "dynamic" mk_s2n_offered_early_data_get_context :: FunPtr S2nOfferedEarlyDataGetContext -> S2nOfferedEarlyDataGetContext
foreign import ccall "dynamic" mk_s2n_offered_early_data_reject :: FunPtr S2nOfferedEarlyDataReject -> S2nOfferedEarlyDataReject
foreign import ccall "dynamic" mk_s2n_offered_early_data_accept :: FunPtr S2nOfferedEarlyDataAccept -> S2nOfferedEarlyDataAccept

-- Connection Serialization
foreign import ccall "dynamic" mk_s2n_connection_serialization_length :: FunPtr S2nConnectionSerializationLength -> S2nConnectionSerializationLength
foreign import ccall "dynamic" mk_s2n_connection_serialize :: FunPtr S2nConnectionSerialize -> S2nConnectionSerialize
foreign import ccall "dynamic" mk_s2n_connection_deserialize :: FunPtr S2nConnectionDeserialize -> S2nConnectionDeserialize
