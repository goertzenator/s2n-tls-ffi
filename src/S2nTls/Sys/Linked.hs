{- |
Module      : S2nTls.Sys.Linked
Description : Linked symbol bindings to s2n-tls
License     : BSD-3-Clause

This module provides s2n-tls bindings via statically linked symbols.
It is only available when the package is built with the @linked@ flag.

Use 'getLinkedTlsSys' to obtain a 'S2nTlsSys' record populated with
function pointers from the linked library.
-}
module S2nTls.Sys.Linked (
  getLinkedTlsSys,
) where

import Foreign.C.Types
import S2nTls.Sys.Types
import System.Posix.Types

{- | Obtain the 'S2nTlsSys' record populated with function pointers
from the linked s2n-tls library.

This function is pure because the linked symbols are resolved at
load time and do not change.
-}
getLinkedTlsSys :: S2nTlsSys
getLinkedTlsSys =
  S2nTlsSys
    { -- Initialization & Cleanup
      s2n_init = c_s2n_init
    , s2n_cleanup = c_s2n_cleanup
    , s2n_cleanup_final = c_s2n_cleanup_final
    , s2n_crypto_disable_init = c_s2n_crypto_disable_init
    , s2n_disable_atexit = c_s2n_disable_atexit
    , s2n_get_openssl_version = c_s2n_get_openssl_version
    , s2n_get_fips_mode = c_s2n_get_fips_mode
    , -- Error Handling
      s2n_errno_location = c_s2n_errno_location
    , s2n_error_get_type = c_s2n_error_get_type
    , s2n_strerror = c_s2n_strerror
    , s2n_strerror_debug = c_s2n_strerror_debug
    , s2n_strerror_name = c_s2n_strerror_name
    , s2n_strerror_source = c_s2n_strerror_source
    , -- Stack Traces
      s2n_stack_traces_enabled = c_s2n_stack_traces_enabled
    , s2n_stack_traces_enabled_set = c_s2n_stack_traces_enabled_set
    , s2n_calculate_stacktrace = c_s2n_calculate_stacktrace
    , s2n_free_stacktrace = c_s2n_free_stacktrace
    , s2n_get_stacktrace = c_s2n_get_stacktrace
    , -- Config Management
      s2n_config_new = c_s2n_config_new
    , s2n_config_new_minimal = c_s2n_config_new_minimal
    , s2n_config_free = c_s2n_config_free
    , s2n_config_free_dhparams = c_s2n_config_free_dhparams
    , s2n_config_free_cert_chain_and_key = c_s2n_config_free_cert_chain_and_key
    , s2n_config_set_wall_clock = c_s2n_config_set_wall_clock
    , s2n_config_set_monotonic_clock = c_s2n_config_set_monotonic_clock
    , -- Cache Callbacks
      s2n_config_set_cache_store_callback = c_s2n_config_set_cache_store_callback
    , s2n_config_set_cache_retrieve_callback = c_s2n_config_set_cache_retrieve_callback
    , s2n_config_set_cache_delete_callback = c_s2n_config_set_cache_delete_callback
    , -- Memory & Random Callbacks
      s2n_mem_set_callbacks = c_s2n_mem_set_callbacks
    , s2n_rand_set_callbacks = c_s2n_rand_set_callbacks
    , -- Certificate Chain Management
      s2n_cert_chain_and_key_new = c_s2n_cert_chain_and_key_new
    , s2n_cert_chain_and_key_load_pem = c_s2n_cert_chain_and_key_load_pem
    , s2n_cert_chain_and_key_load_pem_bytes = c_s2n_cert_chain_and_key_load_pem_bytes
    , s2n_cert_chain_and_key_load_public_pem_bytes = c_s2n_cert_chain_and_key_load_public_pem_bytes
    , s2n_cert_chain_and_key_free = c_s2n_cert_chain_and_key_free
    , s2n_cert_chain_and_key_set_ctx = c_s2n_cert_chain_and_key_set_ctx
    , s2n_cert_chain_and_key_get_ctx = c_s2n_cert_chain_and_key_get_ctx
    , s2n_cert_chain_and_key_get_private_key = c_s2n_cert_chain_and_key_get_private_key
    , s2n_cert_chain_and_key_set_ocsp_data = c_s2n_cert_chain_and_key_set_ocsp_data
    , s2n_cert_chain_and_key_set_sct_list = c_s2n_cert_chain_and_key_set_sct_list
    , s2n_config_set_cert_tiebreak_callback = c_s2n_config_set_cert_tiebreak_callback
    , s2n_config_add_cert_chain_and_key = c_s2n_config_add_cert_chain_and_key
    , s2n_config_add_cert_chain_and_key_to_store = c_s2n_config_add_cert_chain_and_key_to_store
    , s2n_config_set_cert_chain_and_key_defaults = c_s2n_config_set_cert_chain_and_key_defaults
    , -- Trust Store
      s2n_config_set_verification_ca_location = c_s2n_config_set_verification_ca_location
    , s2n_config_add_pem_to_trust_store = c_s2n_config_add_pem_to_trust_store
    , s2n_config_wipe_trust_store = c_s2n_config_wipe_trust_store
    , s2n_config_load_system_certs = c_s2n_config_load_system_certs
    , s2n_config_set_cert_authorities_from_trust_store = c_s2n_config_set_cert_authorities_from_trust_store
    , -- Verification & Validation
      s2n_config_set_verify_after_sign = c_s2n_config_set_verify_after_sign
    , s2n_config_set_check_stapled_ocsp_response = c_s2n_config_set_check_stapled_ocsp_response
    , s2n_config_disable_x509_time_verification = c_s2n_config_disable_x509_time_verification
    , s2n_config_disable_x509_intent_verification = c_s2n_config_disable_x509_intent_verification
    , s2n_config_disable_x509_verification = c_s2n_config_disable_x509_verification
    , s2n_config_set_max_cert_chain_depth = c_s2n_config_set_max_cert_chain_depth
    , s2n_config_set_verify_host_callback = c_s2n_config_set_verify_host_callback
    , -- DH Parameters
      s2n_config_add_dhparams = c_s2n_config_add_dhparams
    , -- Security Policies & Preferences
      s2n_config_set_cipher_preferences = c_s2n_config_set_cipher_preferences
    , s2n_config_append_protocol_preference = c_s2n_config_append_protocol_preference
    , s2n_config_set_protocol_preferences = c_s2n_config_set_protocol_preferences
    , s2n_config_set_status_request_type = c_s2n_config_set_status_request_type
    , s2n_config_set_ct_support_level = c_s2n_config_set_ct_support_level
    , s2n_config_set_alert_behavior = c_s2n_config_set_alert_behavior
    , -- Extension Data
      s2n_config_set_extension_data = c_s2n_config_set_extension_data
    , s2n_config_send_max_fragment_length = c_s2n_config_send_max_fragment_length
    , s2n_config_accept_max_fragment_length = c_s2n_config_accept_max_fragment_length
    , -- Session & Ticket Configuration
      s2n_config_set_session_state_lifetime = c_s2n_config_set_session_state_lifetime
    , s2n_config_set_session_tickets_onoff = c_s2n_config_set_session_tickets_onoff
    , s2n_config_set_session_cache_onoff = c_s2n_config_set_session_cache_onoff
    , s2n_config_set_ticket_encrypt_decrypt_key_lifetime = c_s2n_config_set_ticket_encrypt_decrypt_key_lifetime
    , s2n_config_set_ticket_decrypt_key_lifetime = c_s2n_config_set_ticket_decrypt_key_lifetime
    , s2n_config_add_ticket_crypto_key = c_s2n_config_add_ticket_crypto_key
    , s2n_config_require_ticket_forward_secrecy = c_s2n_config_require_ticket_forward_secrecy
    , -- Buffer & I/O Configuration
      s2n_config_set_send_buffer_size = c_s2n_config_set_send_buffer_size
    , s2n_config_set_recv_multi_record = c_s2n_config_set_recv_multi_record
    , -- Miscellaneous Config
      s2n_config_set_ctx = c_s2n_config_set_ctx
    , s2n_config_get_ctx = c_s2n_config_get_ctx
    , s2n_config_set_client_hello_cb = c_s2n_config_set_client_hello_cb
    , s2n_config_set_client_hello_cb_mode = c_s2n_config_set_client_hello_cb_mode
    , s2n_config_set_max_blinding_delay = c_s2n_config_set_max_blinding_delay
    , s2n_config_get_client_auth_type = c_s2n_config_get_client_auth_type
    , s2n_config_set_client_auth_type = c_s2n_config_set_client_auth_type
    , s2n_config_set_initial_ticket_count = c_s2n_config_set_initial_ticket_count
    , s2n_config_set_psk_mode = c_s2n_config_set_psk_mode
    , s2n_config_set_psk_selection_callback = c_s2n_config_set_psk_selection_callback
    , s2n_config_set_async_pkey_callback = c_s2n_config_set_async_pkey_callback
    , s2n_config_set_async_pkey_validation_mode = c_s2n_config_set_async_pkey_validation_mode
    , s2n_config_set_session_ticket_cb = c_s2n_config_set_session_ticket_cb
    , s2n_config_set_key_log_cb = c_s2n_config_set_key_log_cb
    , s2n_config_enable_cert_req_dss_legacy_compat = c_s2n_config_enable_cert_req_dss_legacy_compat
    , s2n_config_set_server_max_early_data_size = c_s2n_config_set_server_max_early_data_size
    , s2n_config_set_early_data_cb = c_s2n_config_set_early_data_cb
    , s2n_config_get_supported_groups = c_s2n_config_get_supported_groups
    , s2n_config_set_serialization_version = c_s2n_config_set_serialization_version
    , -- Connection Creation & Management
      s2n_connection_new = c_s2n_connection_new
    , s2n_connection_set_config = c_s2n_connection_set_config
    , s2n_connection_set_ctx = c_s2n_connection_set_ctx
    , s2n_connection_get_ctx = c_s2n_connection_get_ctx
    , s2n_client_hello_cb_done = c_s2n_client_hello_cb_done
    , s2n_connection_server_name_extension_used = c_s2n_connection_server_name_extension_used
    , -- Client Hello Access
      s2n_connection_get_client_hello = c_s2n_connection_get_client_hello
    , s2n_client_hello_parse_message = c_s2n_client_hello_parse_message
    , s2n_client_hello_free = c_s2n_client_hello_free
    , s2n_client_hello_get_raw_message_length = c_s2n_client_hello_get_raw_message_length
    , s2n_client_hello_get_raw_message = c_s2n_client_hello_get_raw_message
    , s2n_client_hello_get_cipher_suites_length = c_s2n_client_hello_get_cipher_suites_length
    , s2n_client_hello_get_cipher_suites = c_s2n_client_hello_get_cipher_suites
    , s2n_client_hello_get_extensions_length = c_s2n_client_hello_get_extensions_length
    , s2n_client_hello_get_extensions = c_s2n_client_hello_get_extensions
    , s2n_client_hello_get_extension_length = c_s2n_client_hello_get_extension_length
    , s2n_client_hello_get_extension_by_id = c_s2n_client_hello_get_extension_by_id
    , s2n_client_hello_has_extension = c_s2n_client_hello_has_extension
    , s2n_client_hello_get_session_id_length = c_s2n_client_hello_get_session_id_length
    , s2n_client_hello_get_session_id = c_s2n_client_hello_get_session_id
    , s2n_client_hello_get_compression_methods_length = c_s2n_client_hello_get_compression_methods_length
    , s2n_client_hello_get_compression_methods = c_s2n_client_hello_get_compression_methods
    , s2n_client_hello_get_legacy_protocol_version = c_s2n_client_hello_get_legacy_protocol_version
    , s2n_client_hello_get_random = c_s2n_client_hello_get_random
    , s2n_client_hello_get_supported_groups = c_s2n_client_hello_get_supported_groups
    , s2n_client_hello_get_server_name_length = c_s2n_client_hello_get_server_name_length
    , s2n_client_hello_get_server_name = c_s2n_client_hello_get_server_name
    , s2n_client_hello_get_legacy_record_version = c_s2n_client_hello_get_legacy_record_version
    , -- File Descriptor & I/O
      s2n_connection_set_fd = c_s2n_connection_set_fd
    , s2n_connection_set_read_fd = c_s2n_connection_set_read_fd
    , s2n_connection_set_write_fd = c_s2n_connection_set_write_fd
    , s2n_connection_get_read_fd = c_s2n_connection_get_read_fd
    , s2n_connection_get_write_fd = c_s2n_connection_get_write_fd
    , s2n_connection_use_corked_io = c_s2n_connection_use_corked_io
    , s2n_connection_set_recv_ctx = c_s2n_connection_set_recv_ctx
    , s2n_connection_set_send_ctx = c_s2n_connection_set_send_ctx
    , s2n_connection_set_recv_cb = c_s2n_connection_set_recv_cb
    , s2n_connection_set_send_cb = c_s2n_connection_set_send_cb
    , -- Connection Preferences
      s2n_connection_prefer_throughput = c_s2n_connection_prefer_throughput
    , s2n_connection_prefer_low_latency = c_s2n_connection_prefer_low_latency
    , s2n_connection_set_recv_buffering = c_s2n_connection_set_recv_buffering
    , s2n_peek_buffered = c_s2n_peek_buffered
    , s2n_connection_set_dynamic_buffers = c_s2n_connection_set_dynamic_buffers
    , s2n_connection_set_dynamic_record_threshold = c_s2n_connection_set_dynamic_record_threshold
    , -- Host Verification
      s2n_connection_set_verify_host_callback = c_s2n_connection_set_verify_host_callback
    , -- Blinding & Security
      s2n_connection_set_blinding = c_s2n_connection_set_blinding
    , s2n_connection_get_delay = c_s2n_connection_get_delay
    , -- Cipher & Protocol Configuration
      s2n_connection_set_cipher_preferences = c_s2n_connection_set_cipher_preferences
    , s2n_connection_request_key_update = c_s2n_connection_request_key_update
    , s2n_connection_append_protocol_preference = c_s2n_connection_append_protocol_preference
    , s2n_connection_set_protocol_preferences = c_s2n_connection_set_protocol_preferences
    , -- Server Name (SNI)
      s2n_set_server_name = c_s2n_set_server_name
    , s2n_get_server_name = c_s2n_get_server_name
    , -- Application Protocol (ALPN)
      s2n_get_application_protocol = c_s2n_get_application_protocol
    , -- OCSP & Certificate Transparency
      s2n_connection_get_ocsp_response = c_s2n_connection_get_ocsp_response
    , s2n_connection_get_sct_list = c_s2n_connection_get_sct_list
    , -- Handshake & TLS Operations
      s2n_negotiate = c_s2n_negotiate
    , s2n_send = c_s2n_send
    , s2n_recv = c_s2n_recv
    , s2n_peek = c_s2n_peek
    , s2n_connection_free_handshake = c_s2n_connection_free_handshake
    , s2n_connection_release_buffers = c_s2n_connection_release_buffers
    , s2n_connection_wipe = c_s2n_connection_wipe
    , s2n_connection_free = c_s2n_connection_free
    , s2n_shutdown = c_s2n_shutdown
    , s2n_shutdown_send = c_s2n_shutdown_send
    , -- Client Authentication
      s2n_connection_get_client_auth_type = c_s2n_connection_get_client_auth_type
    , s2n_connection_set_client_auth_type = c_s2n_connection_set_client_auth_type
    , s2n_connection_get_client_cert_chain = c_s2n_connection_get_client_cert_chain
    , s2n_connection_client_cert_used = c_s2n_connection_client_cert_used
    , -- Session Management
      s2n_connection_add_new_tickets_to_send = c_s2n_connection_add_new_tickets_to_send
    , s2n_connection_get_tickets_sent = c_s2n_connection_get_tickets_sent
    , s2n_connection_set_server_keying_material_lifetime = c_s2n_connection_set_server_keying_material_lifetime
    , s2n_session_ticket_get_data_len = c_s2n_session_ticket_get_data_len
    , s2n_session_ticket_get_data = c_s2n_session_ticket_get_data
    , s2n_session_ticket_get_lifetime = c_s2n_session_ticket_get_lifetime
    , s2n_connection_set_session = c_s2n_connection_set_session
    , s2n_connection_get_session = c_s2n_connection_get_session
    , s2n_connection_get_session_ticket_lifetime_hint = c_s2n_connection_get_session_ticket_lifetime_hint
    , s2n_connection_get_session_length = c_s2n_connection_get_session_length
    , s2n_connection_get_session_id_length = c_s2n_connection_get_session_id_length
    , s2n_connection_get_session_id = c_s2n_connection_get_session_id
    , s2n_connection_is_session_resumed = c_s2n_connection_is_session_resumed
    , -- Certificate Information
      s2n_connection_is_ocsp_stapled = c_s2n_connection_is_ocsp_stapled
    , s2n_connection_get_selected_signature_algorithm = c_s2n_connection_get_selected_signature_algorithm
    , s2n_connection_get_selected_digest_algorithm = c_s2n_connection_get_selected_digest_algorithm
    , s2n_connection_get_selected_client_cert_signature_algorithm = c_s2n_connection_get_selected_client_cert_signature_algorithm
    , s2n_connection_get_selected_client_cert_digest_algorithm = c_s2n_connection_get_selected_client_cert_digest_algorithm
    , s2n_connection_get_signature_scheme = c_s2n_connection_get_signature_scheme
    , s2n_connection_get_selected_cert = c_s2n_connection_get_selected_cert
    , s2n_cert_chain_get_length = c_s2n_cert_chain_get_length
    , s2n_cert_chain_get_cert = c_s2n_cert_chain_get_cert
    , s2n_cert_get_der = c_s2n_cert_get_der
    , s2n_connection_get_peer_cert_chain = c_s2n_connection_get_peer_cert_chain
    , s2n_cert_get_x509_extension_value_length = c_s2n_cert_get_x509_extension_value_length
    , s2n_cert_get_x509_extension_value = c_s2n_cert_get_x509_extension_value
    , s2n_cert_get_utf8_string_from_extension_data_length = c_s2n_cert_get_utf8_string_from_extension_data_length
    , s2n_cert_get_utf8_string_from_extension_data = c_s2n_cert_get_utf8_string_from_extension_data
    , -- Pre-Shared Keys (PSK)
      s2n_external_psk_new = c_s2n_external_psk_new
    , s2n_psk_free = c_s2n_psk_free
    , s2n_psk_set_identity = c_s2n_psk_set_identity
    , s2n_psk_set_secret = c_s2n_psk_set_secret
    , s2n_psk_set_hmac = c_s2n_psk_set_hmac
    , s2n_connection_append_psk = c_s2n_connection_append_psk
    , s2n_connection_set_psk_mode = c_s2n_connection_set_psk_mode
    , s2n_connection_get_negotiated_psk_identity_length = c_s2n_connection_get_negotiated_psk_identity_length
    , s2n_connection_get_negotiated_psk_identity = c_s2n_connection_get_negotiated_psk_identity
    , s2n_offered_psk_new = c_s2n_offered_psk_new
    , s2n_offered_psk_free = c_s2n_offered_psk_free
    , s2n_offered_psk_get_identity = c_s2n_offered_psk_get_identity
    , s2n_offered_psk_list_has_next = c_s2n_offered_psk_list_has_next
    , s2n_offered_psk_list_next = c_s2n_offered_psk_list_next
    , s2n_offered_psk_list_reread = c_s2n_offered_psk_list_reread
    , s2n_offered_psk_list_choose_psk = c_s2n_offered_psk_list_choose_psk
    , s2n_psk_configure_early_data = c_s2n_psk_configure_early_data
    , s2n_psk_set_application_protocol = c_s2n_psk_set_application_protocol
    , s2n_psk_set_early_data_context = c_s2n_psk_set_early_data_context
    , -- Connection Statistics
      s2n_connection_get_wire_bytes_in = c_s2n_connection_get_wire_bytes_in
    , s2n_connection_get_wire_bytes_out = c_s2n_connection_get_wire_bytes_out
    , -- Protocol Version Information
      s2n_connection_get_client_protocol_version = c_s2n_connection_get_client_protocol_version
    , s2n_connection_get_server_protocol_version = c_s2n_connection_get_server_protocol_version
    , s2n_connection_get_actual_protocol_version = c_s2n_connection_get_actual_protocol_version
    , s2n_connection_get_client_hello_version = c_s2n_connection_get_client_hello_version
    , -- Cipher & Security Information
      s2n_connection_get_cipher = c_s2n_connection_get_cipher
    , s2n_connection_get_certificate_match = c_s2n_connection_get_certificate_match
    , s2n_connection_get_master_secret = c_s2n_connection_get_master_secret
    , s2n_connection_tls_exporter = c_s2n_connection_tls_exporter
    , s2n_connection_get_cipher_iana_value = c_s2n_connection_get_cipher_iana_value
    , s2n_connection_is_valid_for_cipher_preferences = c_s2n_connection_is_valid_for_cipher_preferences
    , s2n_connection_get_curve = c_s2n_connection_get_curve
    , s2n_connection_get_kem_name = c_s2n_connection_get_kem_name
    , s2n_connection_get_kem_group_name = c_s2n_connection_get_kem_group_name
    , s2n_connection_get_key_exchange_group = c_s2n_connection_get_key_exchange_group
    , s2n_connection_get_alert = c_s2n_connection_get_alert
    , s2n_connection_get_handshake_type_name = c_s2n_connection_get_handshake_type_name
    , s2n_connection_get_last_message_name = c_s2n_connection_get_last_message_name
    , -- Async Private Key Operations
      s2n_async_pkey_op_perform = c_s2n_async_pkey_op_perform
    , s2n_async_pkey_op_apply = c_s2n_async_pkey_op_apply
    , s2n_async_pkey_op_free = c_s2n_async_pkey_op_free
    , s2n_async_pkey_op_get_op_type = c_s2n_async_pkey_op_get_op_type
    , s2n_async_pkey_op_get_input_size = c_s2n_async_pkey_op_get_input_size
    , s2n_async_pkey_op_get_input = c_s2n_async_pkey_op_get_input
    , s2n_async_pkey_op_set_output = c_s2n_async_pkey_op_set_output
    , -- Early Data
      s2n_connection_set_server_max_early_data_size = c_s2n_connection_set_server_max_early_data_size
    , s2n_connection_set_server_early_data_context = c_s2n_connection_set_server_early_data_context
    , s2n_connection_get_early_data_status = c_s2n_connection_get_early_data_status
    , s2n_connection_get_remaining_early_data_size = c_s2n_connection_get_remaining_early_data_size
    , s2n_connection_get_max_early_data_size = c_s2n_connection_get_max_early_data_size
    , s2n_send_early_data = c_s2n_send_early_data
    , s2n_recv_early_data = c_s2n_recv_early_data
    , s2n_offered_early_data_get_context_length = c_s2n_offered_early_data_get_context_length
    , s2n_offered_early_data_get_context = c_s2n_offered_early_data_get_context
    , s2n_offered_early_data_reject = c_s2n_offered_early_data_reject
    , s2n_offered_early_data_accept = c_s2n_offered_early_data_accept
    , -- Connection Serialization
      s2n_connection_serialization_length = c_s2n_connection_serialization_length
    , s2n_connection_serialize = c_s2n_connection_serialize
    , s2n_connection_deserialize = c_s2n_connection_deserialize
    }

--------------------------------------------------------------------------------
-- Foreign Imports (using type aliases from Types.hs)
--------------------------------------------------------------------------------

-- Initialization & Cleanup
foreign import ccall "s2n_init" c_s2n_init :: S2nInit
foreign import ccall "s2n_cleanup" c_s2n_cleanup :: S2nCleanup
foreign import ccall "s2n_cleanup_final" c_s2n_cleanup_final :: S2nCleanupFinal
foreign import ccall "s2n_crypto_disable_init" c_s2n_crypto_disable_init :: S2nCryptoDisableInit
foreign import ccall "s2n_disable_atexit" c_s2n_disable_atexit :: S2nDisableAtexit
foreign import ccall "s2n_get_openssl_version" c_s2n_get_openssl_version :: S2nGetOpensslVersion
foreign import ccall "s2n_get_fips_mode" c_s2n_get_fips_mode :: S2nGetFipsMode

-- Error Handling
foreign import ccall "s2n_errno_location" c_s2n_errno_location :: S2nErrnoLocation
foreign import ccall "s2n_error_get_type" c_s2n_error_get_type :: S2nErrorGetType
foreign import ccall "s2n_strerror" c_s2n_strerror :: S2nStrerror
foreign import ccall "s2n_strerror_debug" c_s2n_strerror_debug :: S2nStrerrorDebug
foreign import ccall "s2n_strerror_name" c_s2n_strerror_name :: S2nStrerrorName
foreign import ccall "s2n_strerror_source" c_s2n_strerror_source :: S2nStrerrorSource

-- Stack Traces
foreign import ccall "s2n_stack_traces_enabled" c_s2n_stack_traces_enabled :: S2nStackTracesEnabled
foreign import ccall "s2n_stack_traces_enabled_set" c_s2n_stack_traces_enabled_set :: S2nStackTracesEnabledSet
foreign import ccall "s2n_calculate_stacktrace" c_s2n_calculate_stacktrace :: S2nCalculateStacktrace
foreign import ccall "s2n_free_stacktrace" c_s2n_free_stacktrace :: S2nFreeStacktrace
foreign import ccall "s2n_get_stacktrace" c_s2n_get_stacktrace :: S2nGetStacktrace

-- Config Management
foreign import ccall "s2n_config_new" c_s2n_config_new :: S2nConfigNew
foreign import ccall "s2n_config_new_minimal" c_s2n_config_new_minimal :: S2nConfigNewMinimal
foreign import ccall "s2n_config_free" c_s2n_config_free :: S2nConfigFree
foreign import ccall "s2n_config_free_dhparams" c_s2n_config_free_dhparams :: S2nConfigFreeDhparams
foreign import ccall "s2n_config_free_cert_chain_and_key" c_s2n_config_free_cert_chain_and_key :: S2nConfigFreeCertChainAndKey
foreign import ccall "s2n_config_set_wall_clock" c_s2n_config_set_wall_clock :: S2nConfigSetWallClock
foreign import ccall "s2n_config_set_monotonic_clock" c_s2n_config_set_monotonic_clock :: S2nConfigSetMonotonicClock

-- Cache Callbacks
foreign import ccall "s2n_config_set_cache_store_callback" c_s2n_config_set_cache_store_callback :: S2nConfigSetCacheStoreCallback
foreign import ccall "s2n_config_set_cache_retrieve_callback" c_s2n_config_set_cache_retrieve_callback :: S2nConfigSetCacheRetrieveCallback
foreign import ccall "s2n_config_set_cache_delete_callback" c_s2n_config_set_cache_delete_callback :: S2nConfigSetCacheDeleteCallback

-- Memory & Random Callbacks
foreign import ccall "s2n_mem_set_callbacks" c_s2n_mem_set_callbacks :: S2nMemSetCallbacks
foreign import ccall "s2n_rand_set_callbacks" c_s2n_rand_set_callbacks :: S2nRandSetCallbacks

-- Certificate Chain Management
foreign import ccall "s2n_cert_chain_and_key_new" c_s2n_cert_chain_and_key_new :: S2nCertChainAndKeyNew
foreign import ccall "s2n_cert_chain_and_key_load_pem" c_s2n_cert_chain_and_key_load_pem :: S2nCertChainAndKeyLoadPem
foreign import ccall "s2n_cert_chain_and_key_load_pem_bytes" c_s2n_cert_chain_and_key_load_pem_bytes :: S2nCertChainAndKeyLoadPemBytes
foreign import ccall "s2n_cert_chain_and_key_load_public_pem_bytes" c_s2n_cert_chain_and_key_load_public_pem_bytes :: S2nCertChainAndKeyLoadPublicPemBytes
foreign import ccall "s2n_cert_chain_and_key_free" c_s2n_cert_chain_and_key_free :: S2nCertChainAndKeyFree
foreign import ccall "s2n_cert_chain_and_key_set_ctx" c_s2n_cert_chain_and_key_set_ctx :: S2nCertChainAndKeySetCtx
foreign import ccall "s2n_cert_chain_and_key_get_ctx" c_s2n_cert_chain_and_key_get_ctx :: S2nCertChainAndKeyGetCtx
foreign import ccall "s2n_cert_chain_and_key_get_private_key" c_s2n_cert_chain_and_key_get_private_key :: S2nCertChainAndKeyGetPrivateKey
foreign import ccall "s2n_cert_chain_and_key_set_ocsp_data" c_s2n_cert_chain_and_key_set_ocsp_data :: S2nCertChainAndKeySetOcspData
foreign import ccall "s2n_cert_chain_and_key_set_sct_list" c_s2n_cert_chain_and_key_set_sct_list :: S2nCertChainAndKeySetSctList
foreign import ccall "s2n_config_set_cert_tiebreak_callback" c_s2n_config_set_cert_tiebreak_callback :: S2nConfigSetCertTiebreakCallback
foreign import ccall "s2n_config_add_cert_chain_and_key" c_s2n_config_add_cert_chain_and_key :: S2nConfigAddCertChainAndKey
foreign import ccall "s2n_config_add_cert_chain_and_key_to_store" c_s2n_config_add_cert_chain_and_key_to_store :: S2nConfigAddCertChainAndKeyToStore
foreign import ccall "s2n_config_set_cert_chain_and_key_defaults" c_s2n_config_set_cert_chain_and_key_defaults :: S2nConfigSetCertChainAndKeyDefaults

-- Trust Store
foreign import ccall "s2n_config_set_verification_ca_location" c_s2n_config_set_verification_ca_location :: S2nConfigSetVerificationCaLocation
foreign import ccall "s2n_config_add_pem_to_trust_store" c_s2n_config_add_pem_to_trust_store :: S2nConfigAddPemToTrustStore
foreign import ccall "s2n_config_wipe_trust_store" c_s2n_config_wipe_trust_store :: S2nConfigWipeTrustStore
foreign import ccall "s2n_config_load_system_certs" c_s2n_config_load_system_certs :: S2nConfigLoadSystemCerts
foreign import ccall "s2n_config_set_cert_authorities_from_trust_store" c_s2n_config_set_cert_authorities_from_trust_store :: S2nConfigSetCertAuthoritiesFromTrustStore

-- Verification & Validation
foreign import ccall "s2n_config_set_verify_after_sign" c_s2n_config_set_verify_after_sign :: S2nConfigSetVerifyAfterSign
foreign import ccall "s2n_config_set_check_stapled_ocsp_response" c_s2n_config_set_check_stapled_ocsp_response :: S2nConfigSetCheckStapledOcspResponse
foreign import ccall "s2n_config_disable_x509_time_verification" c_s2n_config_disable_x509_time_verification :: S2nConfigDisableX509TimeVerification
foreign import ccall "s2n_config_disable_x509_intent_verification" c_s2n_config_disable_x509_intent_verification :: S2nConfigDisableX509IntentVerification
foreign import ccall "s2n_config_disable_x509_verification" c_s2n_config_disable_x509_verification :: S2nConfigDisableX509Verification
foreign import ccall "s2n_config_set_max_cert_chain_depth" c_s2n_config_set_max_cert_chain_depth :: S2nConfigSetMaxCertChainDepth
foreign import ccall "s2n_config_set_verify_host_callback" c_s2n_config_set_verify_host_callback :: S2nConfigSetVerifyHostCallback

-- DH Parameters
foreign import ccall "s2n_config_add_dhparams" c_s2n_config_add_dhparams :: S2nConfigAddDhparams

-- Security Policies & Preferences
foreign import ccall "s2n_config_set_cipher_preferences" c_s2n_config_set_cipher_preferences :: S2nConfigSetCipherPreferences
foreign import ccall "s2n_config_append_protocol_preference" c_s2n_config_append_protocol_preference :: S2nConfigAppendProtocolPreference
foreign import ccall "s2n_config_set_protocol_preferences" c_s2n_config_set_protocol_preferences :: S2nConfigSetProtocolPreferences
foreign import ccall "s2n_config_set_status_request_type" c_s2n_config_set_status_request_type :: S2nConfigSetStatusRequestType
foreign import ccall "s2n_config_set_ct_support_level" c_s2n_config_set_ct_support_level :: S2nConfigSetCtSupportLevel
foreign import ccall "s2n_config_set_alert_behavior" c_s2n_config_set_alert_behavior :: S2nConfigSetAlertBehavior

-- Extension Data
foreign import ccall "s2n_config_set_extension_data" c_s2n_config_set_extension_data :: S2nConfigSetExtensionData
foreign import ccall "s2n_config_send_max_fragment_length" c_s2n_config_send_max_fragment_length :: S2nConfigSendMaxFragmentLength
foreign import ccall "s2n_config_accept_max_fragment_length" c_s2n_config_accept_max_fragment_length :: S2nConfigAcceptMaxFragmentLength

-- Session & Ticket Configuration
foreign import ccall "s2n_config_set_session_state_lifetime" c_s2n_config_set_session_state_lifetime :: S2nConfigSetSessionStateLifetime
foreign import ccall "s2n_config_set_session_tickets_onoff" c_s2n_config_set_session_tickets_onoff :: S2nConfigSetSessionTicketsOnoff
foreign import ccall "s2n_config_set_session_cache_onoff" c_s2n_config_set_session_cache_onoff :: S2nConfigSetSessionCacheOnoff
foreign import ccall "s2n_config_set_ticket_encrypt_decrypt_key_lifetime" c_s2n_config_set_ticket_encrypt_decrypt_key_lifetime :: S2nConfigSetTicketEncryptDecryptKeyLifetime
foreign import ccall "s2n_config_set_ticket_decrypt_key_lifetime" c_s2n_config_set_ticket_decrypt_key_lifetime :: S2nConfigSetTicketDecryptKeyLifetime
foreign import ccall "s2n_config_add_ticket_crypto_key" c_s2n_config_add_ticket_crypto_key :: S2nConfigAddTicketCryptoKey
foreign import ccall "s2n_config_require_ticket_forward_secrecy" c_s2n_config_require_ticket_forward_secrecy :: S2nConfigRequireTicketForwardSecrecy

-- Buffer & I/O Configuration
foreign import ccall "s2n_config_set_send_buffer_size" c_s2n_config_set_send_buffer_size :: S2nConfigSetSendBufferSize
foreign import ccall "s2n_config_set_recv_multi_record" c_s2n_config_set_recv_multi_record :: S2nConfigSetRecvMultiRecord

-- Miscellaneous Config
foreign import ccall "s2n_config_set_ctx" c_s2n_config_set_ctx :: S2nConfigSetCtx
foreign import ccall "s2n_config_get_ctx" c_s2n_config_get_ctx :: S2nConfigGetCtx
foreign import ccall "s2n_config_set_client_hello_cb" c_s2n_config_set_client_hello_cb :: S2nConfigSetClientHelloCb
foreign import ccall "s2n_config_set_client_hello_cb_mode" c_s2n_config_set_client_hello_cb_mode :: S2nConfigSetClientHelloCbMode
foreign import ccall "s2n_config_set_max_blinding_delay" c_s2n_config_set_max_blinding_delay :: S2nConfigSetMaxBlindingDelay
foreign import ccall "s2n_config_get_client_auth_type" c_s2n_config_get_client_auth_type :: S2nConfigGetClientAuthType
foreign import ccall "s2n_config_set_client_auth_type" c_s2n_config_set_client_auth_type :: S2nConfigSetClientAuthType
foreign import ccall "s2n_config_set_initial_ticket_count" c_s2n_config_set_initial_ticket_count :: S2nConfigSetInitialTicketCount
foreign import ccall "s2n_config_set_psk_mode" c_s2n_config_set_psk_mode :: S2nConfigSetPskMode
foreign import ccall "s2n_config_set_psk_selection_callback" c_s2n_config_set_psk_selection_callback :: S2nConfigSetPskSelectionCallback
foreign import ccall "s2n_config_set_async_pkey_callback" c_s2n_config_set_async_pkey_callback :: S2nConfigSetAsyncPkeyCallback
foreign import ccall "s2n_config_set_async_pkey_validation_mode" c_s2n_config_set_async_pkey_validation_mode :: S2nConfigSetAsyncPkeyValidationMode
foreign import ccall "s2n_config_set_session_ticket_cb" c_s2n_config_set_session_ticket_cb :: S2nConfigSetSessionTicketCb
foreign import ccall "s2n_config_set_key_log_cb" c_s2n_config_set_key_log_cb :: S2nConfigSetKeyLogCb
foreign import ccall "s2n_config_enable_cert_req_dss_legacy_compat" c_s2n_config_enable_cert_req_dss_legacy_compat :: S2nConfigEnableCertReqDssLegacyCompat
foreign import ccall "s2n_config_set_server_max_early_data_size" c_s2n_config_set_server_max_early_data_size :: S2nConfigSetServerMaxEarlyDataSize
foreign import ccall "s2n_config_set_early_data_cb" c_s2n_config_set_early_data_cb :: S2nConfigSetEarlyDataCb
foreign import ccall "s2n_config_get_supported_groups" c_s2n_config_get_supported_groups :: S2nConfigGetSupportedGroups
foreign import ccall "s2n_config_set_serialization_version" c_s2n_config_set_serialization_version :: S2nConfigSetSerializationVersion

-- Connection Creation & Management
foreign import ccall "s2n_connection_new" c_s2n_connection_new :: S2nConnectionNew
foreign import ccall "s2n_connection_set_config" c_s2n_connection_set_config :: S2nConnectionSetConfig
foreign import ccall "s2n_connection_set_ctx" c_s2n_connection_set_ctx :: S2nConnectionSetCtx
foreign import ccall "s2n_connection_get_ctx" c_s2n_connection_get_ctx :: S2nConnectionGetCtx
foreign import ccall "s2n_client_hello_cb_done" c_s2n_client_hello_cb_done :: S2nClientHelloCbDone
foreign import ccall "s2n_connection_server_name_extension_used" c_s2n_connection_server_name_extension_used :: S2nConnectionServerNameExtensionUsed

-- Client Hello Access
foreign import ccall "s2n_connection_get_client_hello" c_s2n_connection_get_client_hello :: S2nConnectionGetClientHello
foreign import ccall "s2n_client_hello_parse_message" c_s2n_client_hello_parse_message :: S2nClientHelloParseMessage
foreign import ccall "s2n_client_hello_free" c_s2n_client_hello_free :: S2nClientHelloFree
foreign import ccall "s2n_client_hello_get_raw_message_length" c_s2n_client_hello_get_raw_message_length :: S2nClientHelloGetRawMessageLength
foreign import ccall "s2n_client_hello_get_raw_message" c_s2n_client_hello_get_raw_message :: S2nClientHelloGetRawMessage
foreign import ccall "s2n_client_hello_get_cipher_suites_length" c_s2n_client_hello_get_cipher_suites_length :: S2nClientHelloGetCipherSuitesLength
foreign import ccall "s2n_client_hello_get_cipher_suites" c_s2n_client_hello_get_cipher_suites :: S2nClientHelloGetCipherSuites
foreign import ccall "s2n_client_hello_get_extensions_length" c_s2n_client_hello_get_extensions_length :: S2nClientHelloGetExtensionsLength
foreign import ccall "s2n_client_hello_get_extensions" c_s2n_client_hello_get_extensions :: S2nClientHelloGetExtensions
foreign import ccall "s2n_client_hello_get_extension_length" c_s2n_client_hello_get_extension_length :: S2nClientHelloGetExtensionLength
foreign import ccall "s2n_client_hello_get_extension_by_id" c_s2n_client_hello_get_extension_by_id :: S2nClientHelloGetExtensionById
foreign import ccall "s2n_client_hello_has_extension" c_s2n_client_hello_has_extension :: S2nClientHelloHasExtension
foreign import ccall "s2n_client_hello_get_session_id_length" c_s2n_client_hello_get_session_id_length :: S2nClientHelloGetSessionIdLength
foreign import ccall "s2n_client_hello_get_session_id" c_s2n_client_hello_get_session_id :: S2nClientHelloGetSessionId
foreign import ccall "s2n_client_hello_get_compression_methods_length" c_s2n_client_hello_get_compression_methods_length :: S2nClientHelloGetCompressionMethodsLength
foreign import ccall "s2n_client_hello_get_compression_methods" c_s2n_client_hello_get_compression_methods :: S2nClientHelloGetCompressionMethods
foreign import ccall "s2n_client_hello_get_legacy_protocol_version" c_s2n_client_hello_get_legacy_protocol_version :: S2nClientHelloGetLegacyProtocolVersion
foreign import ccall "s2n_client_hello_get_random" c_s2n_client_hello_get_random :: S2nClientHelloGetRandom
foreign import ccall "s2n_client_hello_get_supported_groups" c_s2n_client_hello_get_supported_groups :: S2nClientHelloGetSupportedGroups
foreign import ccall "s2n_client_hello_get_server_name_length" c_s2n_client_hello_get_server_name_length :: S2nClientHelloGetServerNameLength
foreign import ccall "s2n_client_hello_get_server_name" c_s2n_client_hello_get_server_name :: S2nClientHelloGetServerName
foreign import ccall "s2n_client_hello_get_legacy_record_version" c_s2n_client_hello_get_legacy_record_version :: S2nClientHelloGetLegacyRecordVersion

-- File Descriptor & I/O
foreign import ccall "s2n_connection_set_fd" c_s2n_connection_set_fd :: S2nConnectionSetFd
foreign import ccall "s2n_connection_set_read_fd" c_s2n_connection_set_read_fd :: S2nConnectionSetReadFd
foreign import ccall "s2n_connection_set_write_fd" c_s2n_connection_set_write_fd :: S2nConnectionSetWriteFd
foreign import ccall "s2n_connection_get_read_fd" c_s2n_connection_get_read_fd :: S2nConnectionGetReadFd
foreign import ccall "s2n_connection_get_write_fd" c_s2n_connection_get_write_fd :: S2nConnectionGetWriteFd
foreign import ccall "s2n_connection_use_corked_io" c_s2n_connection_use_corked_io :: S2nConnectionUseCorkedIo
foreign import ccall "s2n_connection_set_recv_ctx" c_s2n_connection_set_recv_ctx :: S2nConnectionSetRecvCtx
foreign import ccall "s2n_connection_set_send_ctx" c_s2n_connection_set_send_ctx :: S2nConnectionSetSendCtx
foreign import ccall "s2n_connection_set_recv_cb" c_s2n_connection_set_recv_cb :: S2nConnectionSetRecvCb
foreign import ccall "s2n_connection_set_send_cb" c_s2n_connection_set_send_cb :: S2nConnectionSetSendCb

-- Connection Preferences
foreign import ccall "s2n_connection_prefer_throughput" c_s2n_connection_prefer_throughput :: S2nConnectionPreferThroughput
foreign import ccall "s2n_connection_prefer_low_latency" c_s2n_connection_prefer_low_latency :: S2nConnectionPreferLowLatency
foreign import ccall "s2n_connection_set_recv_buffering" c_s2n_connection_set_recv_buffering :: S2nConnectionSetRecvBuffering
foreign import ccall "s2n_peek_buffered" c_s2n_peek_buffered :: S2nPeekBuffered
foreign import ccall "s2n_connection_set_dynamic_buffers" c_s2n_connection_set_dynamic_buffers :: S2nConnectionSetDynamicBuffers
foreign import ccall "s2n_connection_set_dynamic_record_threshold" c_s2n_connection_set_dynamic_record_threshold :: S2nConnectionSetDynamicRecordThreshold

-- Host Verification
foreign import ccall "s2n_connection_set_verify_host_callback" c_s2n_connection_set_verify_host_callback :: S2nConnectionSetVerifyHostCallback

-- Blinding & Security
foreign import ccall "s2n_connection_set_blinding" c_s2n_connection_set_blinding :: S2nConnectionSetBlinding
foreign import ccall "s2n_connection_get_delay" c_s2n_connection_get_delay :: S2nConnectionGetDelay

-- Cipher & Protocol Configuration
foreign import ccall "s2n_connection_set_cipher_preferences" c_s2n_connection_set_cipher_preferences :: S2nConnectionSetCipherPreferences
foreign import ccall "s2n_connection_request_key_update" c_s2n_connection_request_key_update :: S2nConnectionRequestKeyUpdate
foreign import ccall "s2n_connection_append_protocol_preference" c_s2n_connection_append_protocol_preference :: S2nConnectionAppendProtocolPreference
foreign import ccall "s2n_connection_set_protocol_preferences" c_s2n_connection_set_protocol_preferences :: S2nConnectionSetProtocolPreferences

-- Server Name (SNI)
foreign import ccall "s2n_set_server_name" c_s2n_set_server_name :: S2nSetServerName
foreign import ccall "s2n_get_server_name" c_s2n_get_server_name :: S2nGetServerName

-- Application Protocol (ALPN)
foreign import ccall "s2n_get_application_protocol" c_s2n_get_application_protocol :: S2nGetApplicationProtocol

-- OCSP & Certificate Transparency
foreign import ccall "s2n_connection_get_ocsp_response" c_s2n_connection_get_ocsp_response :: S2nConnectionGetOcspResponse
foreign import ccall "s2n_connection_get_sct_list" c_s2n_connection_get_sct_list :: S2nConnectionGetSctList

-- Handshake & TLS Operations
foreign import ccall "s2n_negotiate" c_s2n_negotiate :: S2nNegotiate
foreign import ccall "s2n_send" c_s2n_send :: S2nSend
foreign import ccall "s2n_recv" c_s2n_recv :: S2nRecv
foreign import ccall "s2n_peek" c_s2n_peek :: S2nPeek
foreign import ccall "s2n_connection_free_handshake" c_s2n_connection_free_handshake :: S2nConnectionFreeHandshake
foreign import ccall "s2n_connection_release_buffers" c_s2n_connection_release_buffers :: S2nConnectionReleaseBuffers
foreign import ccall "s2n_connection_wipe" c_s2n_connection_wipe :: S2nConnectionWipe
foreign import ccall "s2n_connection_free" c_s2n_connection_free :: S2nConnectionFree
foreign import ccall "s2n_shutdown" c_s2n_shutdown :: S2nShutdown
foreign import ccall "s2n_shutdown_send" c_s2n_shutdown_send :: S2nShutdownSend

-- Client Authentication
foreign import ccall "s2n_connection_get_client_auth_type" c_s2n_connection_get_client_auth_type :: S2nConnectionGetClientAuthType
foreign import ccall "s2n_connection_set_client_auth_type" c_s2n_connection_set_client_auth_type :: S2nConnectionSetClientAuthType
foreign import ccall "s2n_connection_get_client_cert_chain" c_s2n_connection_get_client_cert_chain :: S2nConnectionGetClientCertChain
foreign import ccall "s2n_connection_client_cert_used" c_s2n_connection_client_cert_used :: S2nConnectionClientCertUsed

-- Session Management
foreign import ccall "s2n_connection_add_new_tickets_to_send" c_s2n_connection_add_new_tickets_to_send :: S2nConnectionAddNewTicketsToSend
foreign import ccall "s2n_connection_get_tickets_sent" c_s2n_connection_get_tickets_sent :: S2nConnectionGetTicketsSent
foreign import ccall "s2n_connection_set_server_keying_material_lifetime" c_s2n_connection_set_server_keying_material_lifetime :: S2nConnectionSetServerKeyingMaterialLifetime
foreign import ccall "s2n_session_ticket_get_data_len" c_s2n_session_ticket_get_data_len :: S2nSessionTicketGetDataLen
foreign import ccall "s2n_session_ticket_get_data" c_s2n_session_ticket_get_data :: S2nSessionTicketGetData
foreign import ccall "s2n_session_ticket_get_lifetime" c_s2n_session_ticket_get_lifetime :: S2nSessionTicketGetLifetime
foreign import ccall "s2n_connection_set_session" c_s2n_connection_set_session :: S2nConnectionSetSession
foreign import ccall "s2n_connection_get_session" c_s2n_connection_get_session :: S2nConnectionGetSession
foreign import ccall "s2n_connection_get_session_ticket_lifetime_hint" c_s2n_connection_get_session_ticket_lifetime_hint :: S2nConnectionGetSessionTicketLifetimeHint
foreign import ccall "s2n_connection_get_session_length" c_s2n_connection_get_session_length :: S2nConnectionGetSessionLength
foreign import ccall "s2n_connection_get_session_id_length" c_s2n_connection_get_session_id_length :: S2nConnectionGetSessionIdLength
foreign import ccall "s2n_connection_get_session_id" c_s2n_connection_get_session_id :: S2nConnectionGetSessionId
foreign import ccall "s2n_connection_is_session_resumed" c_s2n_connection_is_session_resumed :: S2nConnectionIsSessionResumed

-- Certificate Information
foreign import ccall "s2n_connection_is_ocsp_stapled" c_s2n_connection_is_ocsp_stapled :: S2nConnectionIsOcspStapled
foreign import ccall "s2n_connection_get_selected_signature_algorithm" c_s2n_connection_get_selected_signature_algorithm :: S2nConnectionGetSelectedSignatureAlgorithm
foreign import ccall "s2n_connection_get_selected_digest_algorithm" c_s2n_connection_get_selected_digest_algorithm :: S2nConnectionGetSelectedDigestAlgorithm
foreign import ccall "s2n_connection_get_selected_client_cert_signature_algorithm" c_s2n_connection_get_selected_client_cert_signature_algorithm :: S2nConnectionGetSelectedClientCertSignatureAlgorithm
foreign import ccall "s2n_connection_get_selected_client_cert_digest_algorithm" c_s2n_connection_get_selected_client_cert_digest_algorithm :: S2nConnectionGetSelectedClientCertDigestAlgorithm
foreign import ccall "s2n_connection_get_signature_scheme" c_s2n_connection_get_signature_scheme :: S2nConnectionGetSignatureScheme
foreign import ccall "s2n_connection_get_selected_cert" c_s2n_connection_get_selected_cert :: S2nConnectionGetSelectedCert
foreign import ccall "s2n_cert_chain_get_length" c_s2n_cert_chain_get_length :: S2nCertChainGetLength
foreign import ccall "s2n_cert_chain_get_cert" c_s2n_cert_chain_get_cert :: S2nCertChainGetCert
foreign import ccall "s2n_cert_get_der" c_s2n_cert_get_der :: S2nCertGetDer
foreign import ccall "s2n_connection_get_peer_cert_chain" c_s2n_connection_get_peer_cert_chain :: S2nConnectionGetPeerCertChain
foreign import ccall "s2n_cert_get_x509_extension_value_length" c_s2n_cert_get_x509_extension_value_length :: S2nCertGetX509ExtensionValueLength
foreign import ccall "s2n_cert_get_x509_extension_value" c_s2n_cert_get_x509_extension_value :: S2nCertGetX509ExtensionValue
foreign import ccall "s2n_cert_get_utf8_string_from_extension_data_length" c_s2n_cert_get_utf8_string_from_extension_data_length :: S2nCertGetUtf8StringFromExtensionDataLength
foreign import ccall "s2n_cert_get_utf8_string_from_extension_data" c_s2n_cert_get_utf8_string_from_extension_data :: S2nCertGetUtf8StringFromExtensionData

-- Pre-Shared Keys (PSK)
foreign import ccall "s2n_external_psk_new" c_s2n_external_psk_new :: S2nExternalPskNew
foreign import ccall "s2n_psk_free" c_s2n_psk_free :: S2nPskFree
foreign import ccall "s2n_psk_set_identity" c_s2n_psk_set_identity :: S2nPskSetIdentity
foreign import ccall "s2n_psk_set_secret" c_s2n_psk_set_secret :: S2nPskSetSecret
foreign import ccall "s2n_psk_set_hmac" c_s2n_psk_set_hmac :: S2nPskSetHmac
foreign import ccall "s2n_connection_append_psk" c_s2n_connection_append_psk :: S2nConnectionAppendPsk
foreign import ccall "s2n_connection_set_psk_mode" c_s2n_connection_set_psk_mode :: S2nConnectionSetPskMode
foreign import ccall "s2n_connection_get_negotiated_psk_identity_length" c_s2n_connection_get_negotiated_psk_identity_length :: S2nConnectionGetNegotiatedPskIdentityLength
foreign import ccall "s2n_connection_get_negotiated_psk_identity" c_s2n_connection_get_negotiated_psk_identity :: S2nConnectionGetNegotiatedPskIdentity
foreign import ccall "s2n_offered_psk_new" c_s2n_offered_psk_new :: S2nOfferedPskNew
foreign import ccall "s2n_offered_psk_free" c_s2n_offered_psk_free :: S2nOfferedPskFree
foreign import ccall "s2n_offered_psk_get_identity" c_s2n_offered_psk_get_identity :: S2nOfferedPskGetIdentity
foreign import ccall "s2n_offered_psk_list_has_next" c_s2n_offered_psk_list_has_next :: S2nOfferedPskListHasNext
foreign import ccall "s2n_offered_psk_list_next" c_s2n_offered_psk_list_next :: S2nOfferedPskListNext
foreign import ccall "s2n_offered_psk_list_reread" c_s2n_offered_psk_list_reread :: S2nOfferedPskListReread
foreign import ccall "s2n_offered_psk_list_choose_psk" c_s2n_offered_psk_list_choose_psk :: S2nOfferedPskListChoosePsk
foreign import ccall "s2n_psk_configure_early_data" c_s2n_psk_configure_early_data :: S2nPskConfigureEarlyData
foreign import ccall "s2n_psk_set_application_protocol" c_s2n_psk_set_application_protocol :: S2nPskSetApplicationProtocol
foreign import ccall "s2n_psk_set_early_data_context" c_s2n_psk_set_early_data_context :: S2nPskSetEarlyDataContext

-- Connection Statistics
foreign import ccall "s2n_connection_get_wire_bytes_in" c_s2n_connection_get_wire_bytes_in :: S2nConnectionGetWireBytesIn
foreign import ccall "s2n_connection_get_wire_bytes_out" c_s2n_connection_get_wire_bytes_out :: S2nConnectionGetWireBytesOut

-- Protocol Version Information
foreign import ccall "s2n_connection_get_client_protocol_version" c_s2n_connection_get_client_protocol_version :: S2nConnectionGetClientProtocolVersion
foreign import ccall "s2n_connection_get_server_protocol_version" c_s2n_connection_get_server_protocol_version :: S2nConnectionGetServerProtocolVersion
foreign import ccall "s2n_connection_get_actual_protocol_version" c_s2n_connection_get_actual_protocol_version :: S2nConnectionGetActualProtocolVersion
foreign import ccall "s2n_connection_get_client_hello_version" c_s2n_connection_get_client_hello_version :: S2nConnectionGetClientHelloVersion

-- Cipher & Security Information
foreign import ccall "s2n_connection_get_cipher" c_s2n_connection_get_cipher :: S2nConnectionGetCipher
foreign import ccall "s2n_connection_get_certificate_match" c_s2n_connection_get_certificate_match :: S2nConnectionGetCertificateMatch
foreign import ccall "s2n_connection_get_master_secret" c_s2n_connection_get_master_secret :: S2nConnectionGetMasterSecret
foreign import ccall "s2n_connection_tls_exporter" c_s2n_connection_tls_exporter :: S2nConnectionTlsExporter
foreign import ccall "s2n_connection_get_cipher_iana_value" c_s2n_connection_get_cipher_iana_value :: S2nConnectionGetCipherIanaValue
foreign import ccall "s2n_connection_is_valid_for_cipher_preferences" c_s2n_connection_is_valid_for_cipher_preferences :: S2nConnectionIsValidForCipherPreferences
foreign import ccall "s2n_connection_get_curve" c_s2n_connection_get_curve :: S2nConnectionGetCurve
foreign import ccall "s2n_connection_get_kem_name" c_s2n_connection_get_kem_name :: S2nConnectionGetKemName
foreign import ccall "s2n_connection_get_kem_group_name" c_s2n_connection_get_kem_group_name :: S2nConnectionGetKemGroupName
foreign import ccall "s2n_connection_get_key_exchange_group" c_s2n_connection_get_key_exchange_group :: S2nConnectionGetKeyExchangeGroup
foreign import ccall "s2n_connection_get_alert" c_s2n_connection_get_alert :: S2nConnectionGetAlert
foreign import ccall "s2n_connection_get_handshake_type_name" c_s2n_connection_get_handshake_type_name :: S2nConnectionGetHandshakeTypeName
foreign import ccall "s2n_connection_get_last_message_name" c_s2n_connection_get_last_message_name :: S2nConnectionGetLastMessageName

-- Async Private Key Operations
foreign import ccall "s2n_async_pkey_op_perform" c_s2n_async_pkey_op_perform :: S2nAsyncPkeyOpPerform
foreign import ccall "s2n_async_pkey_op_apply" c_s2n_async_pkey_op_apply :: S2nAsyncPkeyOpApply
foreign import ccall "s2n_async_pkey_op_free" c_s2n_async_pkey_op_free :: S2nAsyncPkeyOpFree
foreign import ccall "s2n_async_pkey_op_get_op_type" c_s2n_async_pkey_op_get_op_type :: S2nAsyncPkeyOpGetOpType
foreign import ccall "s2n_async_pkey_op_get_input_size" c_s2n_async_pkey_op_get_input_size :: S2nAsyncPkeyOpGetInputSize
foreign import ccall "s2n_async_pkey_op_get_input" c_s2n_async_pkey_op_get_input :: S2nAsyncPkeyOpGetInput
foreign import ccall "s2n_async_pkey_op_set_output" c_s2n_async_pkey_op_set_output :: S2nAsyncPkeyOpSetOutput

-- Early Data
foreign import ccall "s2n_connection_set_server_max_early_data_size" c_s2n_connection_set_server_max_early_data_size :: S2nConnectionSetServerMaxEarlyDataSize
foreign import ccall "s2n_connection_set_server_early_data_context" c_s2n_connection_set_server_early_data_context :: S2nConnectionSetServerEarlyDataContext
foreign import ccall "s2n_connection_get_early_data_status" c_s2n_connection_get_early_data_status :: S2nConnectionGetEarlyDataStatus
foreign import ccall "s2n_connection_get_remaining_early_data_size" c_s2n_connection_get_remaining_early_data_size :: S2nConnectionGetRemainingEarlyDataSize
foreign import ccall "s2n_connection_get_max_early_data_size" c_s2n_connection_get_max_early_data_size :: S2nConnectionGetMaxEarlyDataSize
foreign import ccall "s2n_send_early_data" c_s2n_send_early_data :: S2nSendEarlyData
foreign import ccall "s2n_recv_early_data" c_s2n_recv_early_data :: S2nRecvEarlyData
foreign import ccall "s2n_offered_early_data_get_context_length" c_s2n_offered_early_data_get_context_length :: S2nOfferedEarlyDataGetContextLength
foreign import ccall "s2n_offered_early_data_get_context" c_s2n_offered_early_data_get_context :: S2nOfferedEarlyDataGetContext
foreign import ccall "s2n_offered_early_data_reject" c_s2n_offered_early_data_reject :: S2nOfferedEarlyDataReject
foreign import ccall "s2n_offered_early_data_accept" c_s2n_offered_early_data_accept :: S2nOfferedEarlyDataAccept

-- Connection Serialization
foreign import ccall "s2n_connection_serialization_length" c_s2n_connection_serialization_length :: S2nConnectionSerializationLength
foreign import ccall "s2n_connection_serialize" c_s2n_connection_serialize :: S2nConnectionSerialize
foreign import ccall "s2n_connection_deserialize" c_s2n_connection_deserialize :: S2nConnectionDeserialize
