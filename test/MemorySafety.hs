{-# LANGUAGE NumericUnderscores #-}

{- |
Module      : Main
Description : Memory safety tests for s2n-tls FFI bindings

This test invokes all FFI functions to check for segfaults and memory errors.
Each function name is printed before invocation so crashes can be identified.
-}
module Main where

import Control.Exception (SomeException, catch)
import Control.Monad (void)
import Data.Word (Word16, Word32, Word8)
import Foreign.C.String (withCString)
import Foreign.C.Types (CInt (..))
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Marshal.Array (allocaArray, pokeArray)
import Foreign.Ptr (Ptr, nullFunPtr, nullPtr)
import Foreign.Storable (poke)
import System.IO (hFlush, stdout)

import S2nTls.Ffi
import S2nTls.Ffi.Types

-- | Print function name and flush, then invoke it. Catches exceptions (only segfaults crash).
invoke :: String -> IO a -> IO ()
invoke name action = do
    putStrLn $ "  " ++ name
    hFlush stdout
    result <- (Right <$> action) `catch` \(e :: SomeException) -> pure (Left e)
    case result of
        Right _ -> pure ()
        Left _ -> pure () -- Exceptions are OK, we only care about segfaults

main :: IO ()
main = withS2nTlsFfi Linked $ \ffi -> do
    putStrLn "=== s2n-tls Memory Safety Tests ==="
    hFlush stdout

    runInitTests ffi
    runErrorTests ffi
    runStackTraceTests ffi
    runConfigTests ffi
    runCertChainTests ffi
    runConnectionTests ffi
    runPskTests ffi
    runCleanupTests ffi

    putStrLn "=== All tests completed ==="
    hFlush stdout

--------------------------------------------------------------------------------
-- Initialization Tests
--------------------------------------------------------------------------------

runInitTests :: S2nTlsFfi -> IO ()
runInitTests ffi = do
    putStrLn "\n[Initialization]"
    hFlush stdout
    invoke "s2n_init" $ s2n_init ffi
    invoke "s2n_crypto_disable_init" $ s2n_crypto_disable_init ffi
    invoke "s2n_disable_atexit" $ s2n_disable_atexit ffi
    invoke "s2n_get_openssl_version" $ s2n_get_openssl_version ffi
    alloca $ \ptr ->
        invoke "s2n_get_fips_mode" $ s2n_get_fips_mode ffi ptr

--------------------------------------------------------------------------------
-- Error Handling Tests
--------------------------------------------------------------------------------

runErrorTests :: S2nTlsFfi -> IO ()
runErrorTests ffi = do
    putStrLn "\n[Error Handling]"
    hFlush stdout
    invoke "s2n_errno_location" $ s2n_errno_location ffi
    invoke "s2n_error_get_type" $ s2n_error_get_type ffi 0
    withCString "EN" $ \lang -> do
        invoke "s2n_strerror" $ s2n_strerror ffi 0 lang
        invoke "s2n_strerror_debug" $ s2n_strerror_debug ffi 0 lang
    invoke "s2n_strerror_name" $ s2n_strerror_name ffi 0
    invoke "s2n_strerror_source" $ s2n_strerror_source ffi 0

--------------------------------------------------------------------------------
-- Stack Trace Tests
--------------------------------------------------------------------------------

runStackTraceTests :: S2nTlsFfi -> IO ()
runStackTraceTests ffi = do
    putStrLn "\n[Stack Traces]"
    hFlush stdout
    invoke "s2n_stack_traces_enabled" $ s2n_stack_traces_enabled ffi
    invoke "s2n_stack_traces_enabled_set" $ s2n_stack_traces_enabled_set ffi 0
    invoke "s2n_calculate_stacktrace" $ s2n_calculate_stacktrace ffi
    allocaBytes 8 $ \ptr ->
        invoke "s2n_get_stacktrace" $ s2n_get_stacktrace ffi ptr
    invoke "s2n_free_stacktrace" $ s2n_free_stacktrace ffi

--------------------------------------------------------------------------------
-- Config Tests
--------------------------------------------------------------------------------

runConfigTests :: S2nTlsFfi -> IO ()
runConfigTests ffi = do
    putStrLn "\n[Config]"
    hFlush stdout
    invoke "s2n_config_new" $ s2n_config_new ffi
    invoke "s2n_config_new_minimal" $ s2n_config_new_minimal ffi

    -- Run config operation tests with a fresh config
    withConfig ffi $ \cfg -> do
        putStrLn "\n[Config Operations]"
        hFlush stdout
        invoke "s2n_config_set_wall_clock" $ s2n_config_set_wall_clock ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_set_monotonic_clock" $ s2n_config_set_monotonic_clock ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_set_cache_store_callback" $ s2n_config_set_cache_store_callback ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_set_cache_retrieve_callback" $ s2n_config_set_cache_retrieve_callback ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_set_cache_delete_callback" $ s2n_config_set_cache_delete_callback ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_wipe_trust_store" $ s2n_config_wipe_trust_store ffi cfg
        invoke "s2n_config_load_system_certs" $ s2n_config_load_system_certs ffi cfg
        withCString "/nonexistent" $ \path ->
            invoke "s2n_config_set_verification_ca_location" $ s2n_config_set_verification_ca_location ffi cfg path nullPtr
        withCString "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----" $ \pem ->
            invoke "s2n_config_add_pem_to_trust_store" $ s2n_config_add_pem_to_trust_store ffi cfg pem
        invoke "s2n_config_set_cert_authorities_from_trust_store" $ s2n_config_set_cert_authorities_from_trust_store ffi cfg
        invoke "s2n_config_set_verify_after_sign" $ s2n_config_set_verify_after_sign ffi cfg (S2nVerifyAfterSign 0)
        invoke "s2n_config_set_check_stapled_ocsp_response" $ s2n_config_set_check_stapled_ocsp_response ffi cfg 0
        invoke "s2n_config_disable_x509_time_verification" $ s2n_config_disable_x509_time_verification ffi cfg
        invoke "s2n_config_disable_x509_verification" $ s2n_config_disable_x509_verification ffi cfg
        invoke "s2n_config_set_max_cert_chain_depth" $ s2n_config_set_max_cert_chain_depth ffi cfg 10
        invoke "s2n_config_set_verify_host_callback" $ s2n_config_set_verify_host_callback ffi cfg nullFunPtr nullPtr
        withCString "-----BEGIN DH PARAMETERS-----\ntest\n-----END DH PARAMETERS-----" $ \dh ->
            invoke "s2n_config_add_dhparams" $ s2n_config_add_dhparams ffi cfg dh
        withCString "default_tls13" $ \policy ->
            invoke "s2n_config_set_cipher_preferences" $ s2n_config_set_cipher_preferences ffi cfg policy
        allocaArray 10 $ \protoPtr ->
            invoke "s2n_config_append_protocol_preference" $ s2n_config_append_protocol_preference ffi cfg protoPtr 5
        withCString "h2" $ \proto1 ->
            allocaArray 1 $ \protos -> do
                pokeArray protos [proto1]
                invoke "s2n_config_set_protocol_preferences" $ s2n_config_set_protocol_preferences ffi cfg protos 1
        invoke "s2n_config_set_status_request_type" $ s2n_config_set_status_request_type ffi cfg (S2nStatusRequestType 0)
        invoke "s2n_config_set_ct_support_level" $ s2n_config_set_ct_support_level ffi cfg (S2nCtSupportLevel 0)
        invoke "s2n_config_set_alert_behavior" $ s2n_config_set_alert_behavior ffi cfg (S2nAlertBehavior 0)
        allocaBytes 16 $ \buf ->
            invoke "s2n_config_set_extension_data" $ s2n_config_set_extension_data ffi cfg (S2nTlsExtensionType 0) buf 16
        invoke "s2n_config_send_max_fragment_length" $ s2n_config_send_max_fragment_length ffi cfg (S2nMaxFragLen 1)
        invoke "s2n_config_accept_max_fragment_length" $ s2n_config_accept_max_fragment_length ffi cfg
        invoke "s2n_config_set_session_state_lifetime" $ s2n_config_set_session_state_lifetime ffi cfg 3600
        invoke "s2n_config_set_session_tickets_onoff" $ s2n_config_set_session_tickets_onoff ffi cfg 1
        invoke "s2n_config_set_session_cache_onoff" $ s2n_config_set_session_cache_onoff ffi cfg 1
        invoke "s2n_config_set_ticket_encrypt_decrypt_key_lifetime" $ s2n_config_set_ticket_encrypt_decrypt_key_lifetime ffi cfg 3600
        invoke "s2n_config_set_ticket_decrypt_key_lifetime" $ s2n_config_set_ticket_decrypt_key_lifetime ffi cfg 7200
        allocaBytes 16 $ \keyName -> allocaBytes 32 $ \keyData ->
            invoke "s2n_config_add_ticket_crypto_key" $ s2n_config_add_ticket_crypto_key ffi cfg keyName 16 keyData 32 0
        invoke "s2n_config_require_ticket_forward_secrecy" $ s2n_config_require_ticket_forward_secrecy ffi cfg 1
        invoke "s2n_config_set_send_buffer_size" $ s2n_config_set_send_buffer_size ffi cfg 16384
        invoke "s2n_config_set_recv_multi_record" $ s2n_config_set_recv_multi_record ffi cfg 1
        invoke "s2n_config_set_client_hello_cb" $ s2n_config_set_client_hello_cb ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_set_client_hello_cb_mode" $ s2n_config_set_client_hello_cb_mode ffi cfg (S2nClientHelloCbMode 0)
        invoke "s2n_config_set_max_blinding_delay" $ s2n_config_set_max_blinding_delay ffi cfg 30
        alloca $ \authType ->
            invoke "s2n_config_get_client_auth_type" $ s2n_config_get_client_auth_type ffi cfg authType
        invoke "s2n_config_set_client_auth_type" $ s2n_config_set_client_auth_type ffi cfg (S2nCertAuthType 0)
        invoke "s2n_config_set_initial_ticket_count" $ s2n_config_set_initial_ticket_count ffi cfg 2
        invoke "s2n_config_set_psk_mode" $ s2n_config_set_psk_mode ffi cfg (S2nPskMode 0)
        invoke "s2n_config_set_psk_selection_callback" $ s2n_config_set_psk_selection_callback ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_set_async_pkey_callback" $ s2n_config_set_async_pkey_callback ffi cfg nullFunPtr
        invoke "s2n_config_set_async_pkey_validation_mode" $ s2n_config_set_async_pkey_validation_mode ffi cfg (S2nAsyncPkeyValidationMode 0)
        invoke "s2n_config_set_session_ticket_cb" $ s2n_config_set_session_ticket_cb ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_set_key_log_cb" $ s2n_config_set_key_log_cb ffi cfg nullFunPtr nullPtr
        invoke "s2n_config_enable_cert_req_dss_legacy_compat" $ s2n_config_enable_cert_req_dss_legacy_compat ffi cfg
        invoke "s2n_config_set_server_max_early_data_size" $ s2n_config_set_server_max_early_data_size ffi cfg 16384
        invoke "s2n_config_set_early_data_cb" $ s2n_config_set_early_data_cb ffi cfg nullFunPtr
        invoke "s2n_config_set_ctx" $ s2n_config_set_ctx ffi cfg nullPtr
        alloca $ \ctxPtr ->
            invoke "s2n_config_get_ctx" $ s2n_config_get_ctx ffi cfg ctxPtr
        allocaArray 10 $ \groups -> alloca $ \count ->
            invoke "s2n_config_get_supported_groups" $ s2n_config_get_supported_groups ffi cfg groups 10 count
        invoke "s2n_config_set_serialization_version" $ s2n_config_set_serialization_version ffi cfg (S2nSerializationVersion 0)
        invoke "s2n_config_set_cert_tiebreak_callback" $ s2n_config_set_cert_tiebreak_callback ffi cfg nullFunPtr
        withCString "" $ \emptyPath ->
            invoke "s2n_config_add_cert_chain_and_key" $ s2n_config_add_cert_chain_and_key ffi cfg emptyPath emptyPath
        invoke "s2n_config_free_dhparams" $ s2n_config_free_dhparams ffi cfg
        invoke "s2n_config_free_cert_chain_and_key" $ s2n_config_free_cert_chain_and_key ffi cfg

    -- Test s2n_config_free separately
    result <- s2n_config_new ffi
    case result of
        Left _ -> pure ()
        Right cfg -> invoke "s2n_config_free" $ s2n_config_free ffi cfg

-- | Helper to run tests with a fresh config
withConfig :: S2nTlsFfi -> (Ptr S2nConfig -> IO ()) -> IO ()
withConfig ffi action = do
    result <- s2n_config_new ffi
    case result of
        Left _ -> putStrLn "  [skipped - config creation failed]"
        Right cfg -> do
            action cfg
            void $ s2n_config_free ffi cfg

--------------------------------------------------------------------------------
-- Certificate Chain Tests
--------------------------------------------------------------------------------

runCertChainTests :: S2nTlsFfi -> IO ()
runCertChainTests ffi = do
    putStrLn "\n[Certificate Chain]"
    hFlush stdout
    invoke "s2n_cert_chain_and_key_new" $ s2n_cert_chain_and_key_new ffi

    withCertChain ffi $ \cert -> do
        withCString "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----" $ \pemCert ->
            withCString "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----" $ \pemKey ->
                invoke "s2n_cert_chain_and_key_load_pem" $ s2n_cert_chain_and_key_load_pem ffi cert pemCert pemKey
        allocaBytes 100 $ \certBuf -> allocaBytes 100 $ \keyBuf ->
            invoke "s2n_cert_chain_and_key_load_pem_bytes" $ s2n_cert_chain_and_key_load_pem_bytes ffi cert certBuf 100 keyBuf 100
        allocaBytes 100 $ \buf ->
            invoke "s2n_cert_chain_and_key_load_public_pem_bytes" $ s2n_cert_chain_and_key_load_public_pem_bytes ffi cert buf 100
        invoke "s2n_cert_chain_and_key_set_ctx" $ s2n_cert_chain_and_key_set_ctx ffi cert nullPtr
        invoke "s2n_cert_chain_and_key_get_ctx" $ s2n_cert_chain_and_key_get_ctx ffi cert
        invoke "s2n_cert_chain_and_key_get_private_key" $ s2n_cert_chain_and_key_get_private_key ffi cert
        allocaBytes 100 $ \buf ->
            invoke "s2n_cert_chain_and_key_set_ocsp_data" $ s2n_cert_chain_and_key_set_ocsp_data ffi cert buf 100
        allocaBytes 100 $ \buf ->
            invoke "s2n_cert_chain_and_key_set_sct_list" $ s2n_cert_chain_and_key_set_sct_list ffi cert buf 100
        alloca $ \lengthPtr ->
            invoke "s2n_cert_chain_get_length" $ s2n_cert_chain_get_length ffi cert lengthPtr
        alloca $ \certPtr ->
            invoke "s2n_cert_chain_get_cert" $ s2n_cert_chain_get_cert ffi cert certPtr 0

    -- Test s2n_cert_chain_and_key_free separately
    result <- s2n_cert_chain_and_key_new ffi
    case result of
        Left _ -> pure ()
        Right cert -> invoke "s2n_cert_chain_and_key_free" $ s2n_cert_chain_and_key_free ffi cert

-- | Helper to run tests with a fresh cert chain
withCertChain :: S2nTlsFfi -> (Ptr S2nCertChainAndKey -> IO ()) -> IO ()
withCertChain ffi action = do
    result <- s2n_cert_chain_and_key_new ffi
    case result of
        Left _ -> putStrLn "  [skipped - cert chain creation failed]"
        Right cert -> do
            action cert
            void $ s2n_cert_chain_and_key_free ffi cert

--------------------------------------------------------------------------------
-- Connection Tests
--------------------------------------------------------------------------------

runConnectionTests :: S2nTlsFfi -> IO ()
runConnectionTests ffi = do
    putStrLn "\n[Connection]"
    hFlush stdout
    invoke "s2n_connection_new (client)" $ s2n_connection_new ffi S2N_CLIENT
    invoke "s2n_connection_new (server)" $ s2n_connection_new ffi S2N_SERVER

    withConnection ffi $ \conn -> do
        putStrLn "\n[Connection Operations]"
        hFlush stdout

        -- Config assignment
        cfgResult <- s2n_config_new ffi
        case cfgResult of
            Left _ -> pure ()
            Right cfg -> do
                invoke "s2n_connection_set_config" $ s2n_connection_set_config ffi conn cfg
                void $ s2n_config_free ffi cfg

        invoke "s2n_connection_set_ctx" $ s2n_connection_set_ctx ffi conn nullPtr
        invoke "s2n_connection_get_ctx" $ s2n_connection_get_ctx ffi conn
        invoke "s2n_client_hello_cb_done" $ s2n_client_hello_cb_done ffi conn
        invoke "s2n_connection_server_name_extension_used" $ s2n_connection_server_name_extension_used ffi conn
        invoke "s2n_connection_get_client_hello" $ s2n_connection_get_client_hello ffi conn
        allocaBytes 100 $ \buf ->
            invoke "s2n_client_hello_parse_message" $ s2n_client_hello_parse_message ffi buf 100
        invoke "s2n_connection_set_fd" $ s2n_connection_set_fd ffi conn (-1)
        invoke "s2n_connection_set_read_fd" $ s2n_connection_set_read_fd ffi conn (-1)
        invoke "s2n_connection_set_write_fd" $ s2n_connection_set_write_fd ffi conn (-1)
        alloca $ \fdPtr -> do
            invoke "s2n_connection_get_read_fd" $ s2n_connection_get_read_fd ffi conn fdPtr
            invoke "s2n_connection_get_write_fd" $ s2n_connection_get_write_fd ffi conn fdPtr
        invoke "s2n_connection_use_corked_io" $ s2n_connection_use_corked_io ffi conn
        invoke "s2n_connection_set_recv_ctx" $ s2n_connection_set_recv_ctx ffi conn nullPtr
        invoke "s2n_connection_set_send_ctx" $ s2n_connection_set_send_ctx ffi conn nullPtr
        invoke "s2n_connection_set_recv_cb" $ s2n_connection_set_recv_cb ffi conn nullFunPtr
        invoke "s2n_connection_set_send_cb" $ s2n_connection_set_send_cb ffi conn nullFunPtr
        invoke "s2n_connection_prefer_throughput" $ s2n_connection_prefer_throughput ffi conn
        invoke "s2n_connection_prefer_low_latency" $ s2n_connection_prefer_low_latency ffi conn
        invoke "s2n_connection_set_recv_buffering" $ s2n_connection_set_recv_buffering ffi conn 1
        invoke "s2n_peek_buffered" $ s2n_peek_buffered ffi conn
        invoke "s2n_connection_set_dynamic_buffers" $ s2n_connection_set_dynamic_buffers ffi conn 1
        invoke "s2n_connection_set_dynamic_record_threshold" $ s2n_connection_set_dynamic_record_threshold ffi conn 1400 100
        invoke "s2n_connection_set_verify_host_callback" $ s2n_connection_set_verify_host_callback ffi conn nullFunPtr nullPtr
        invoke "s2n_connection_set_blinding" $ s2n_connection_set_blinding ffi conn S2N_SELF_SERVICE_BLINDING
        invoke "s2n_connection_get_delay" $ s2n_connection_get_delay ffi conn
        withCString "default_tls13" $ \policy ->
            invoke "s2n_connection_set_cipher_preferences" $ s2n_connection_set_cipher_preferences ffi conn policy
        invoke "s2n_connection_request_key_update" $ s2n_connection_request_key_update ffi conn (S2nPeerKeyUpdate 0)
        allocaBytes 10 $ \proto ->
            invoke "s2n_connection_append_protocol_preference" $ s2n_connection_append_protocol_preference ffi conn proto 5
        withCString "h2" $ \proto1 ->
            allocaArray 1 $ \protos -> do
                pokeArray protos [proto1]
                invoke "s2n_connection_set_protocol_preferences" $ s2n_connection_set_protocol_preferences ffi conn protos 1
        withCString "example.com" $ \name ->
            invoke "s2n_set_server_name" $ s2n_set_server_name ffi conn name
        invoke "s2n_get_server_name" $ s2n_get_server_name ffi conn
        invoke "s2n_get_application_protocol" $ s2n_get_application_protocol ffi conn
        alloca $ \lenPtr -> do
            invoke "s2n_connection_get_ocsp_response" $ s2n_connection_get_ocsp_response ffi conn lenPtr
            invoke "s2n_connection_get_sct_list" $ s2n_connection_get_sct_list ffi conn lenPtr
        alloca $ \blocked -> do
            invoke "s2n_negotiate" $ s2n_negotiate ffi conn blocked
            allocaBytes 100 $ \buf -> do
                invoke "s2n_send" $ s2n_send ffi conn buf 100 blocked
                invoke "s2n_recv" $ s2n_recv ffi conn buf 100 blocked
            invoke "s2n_shutdown" $ s2n_shutdown ffi conn blocked
            invoke "s2n_shutdown_send" $ s2n_shutdown_send ffi conn blocked
        invoke "s2n_peek" $ s2n_peek ffi conn
        alloca $ \authType ->
            invoke "s2n_connection_get_client_auth_type" $ s2n_connection_get_client_auth_type ffi conn authType
        invoke "s2n_connection_set_client_auth_type" $ s2n_connection_set_client_auth_type ffi conn (S2nCertAuthType 0)
        alloca $ \certPtr -> alloca $ \lenPtr ->
            invoke "s2n_connection_get_client_cert_chain" $ s2n_connection_get_client_cert_chain ffi conn certPtr lenPtr
        invoke "s2n_connection_client_cert_used" $ s2n_connection_client_cert_used ffi conn
        invoke "s2n_connection_add_new_tickets_to_send" $ s2n_connection_add_new_tickets_to_send ffi conn 1
        alloca $ \ticketsPtr ->
            invoke "s2n_connection_get_tickets_sent" $ s2n_connection_get_tickets_sent ffi conn ticketsPtr
        invoke "s2n_connection_set_server_keying_material_lifetime" $ s2n_connection_set_server_keying_material_lifetime ffi conn 86400
        allocaBytes 256 $ \buf -> do
            invoke "s2n_connection_set_session" $ s2n_connection_set_session ffi conn buf 256
            invoke "s2n_connection_get_session" $ s2n_connection_get_session ffi conn buf 256
        invoke "s2n_connection_get_session_ticket_lifetime_hint" $ s2n_connection_get_session_ticket_lifetime_hint ffi conn
        invoke "s2n_connection_get_session_length" $ s2n_connection_get_session_length ffi conn
        invoke "s2n_connection_get_session_id_length" $ s2n_connection_get_session_id_length ffi conn
        allocaBytes 32 $ \buf ->
            invoke "s2n_connection_get_session_id" $ s2n_connection_get_session_id ffi conn buf 32
        invoke "s2n_connection_is_session_resumed" $ s2n_connection_is_session_resumed ffi conn
        invoke "s2n_connection_is_ocsp_stapled" $ s2n_connection_is_ocsp_stapled ffi conn
        alloca $ \sigAlg -> do
            invoke "s2n_connection_get_selected_signature_algorithm" $ s2n_connection_get_selected_signature_algorithm ffi conn sigAlg
            invoke "s2n_connection_get_selected_client_cert_signature_algorithm" $ s2n_connection_get_selected_client_cert_signature_algorithm ffi conn sigAlg
        alloca $ \hashAlg -> do
            invoke "s2n_connection_get_selected_digest_algorithm" $ s2n_connection_get_selected_digest_algorithm ffi conn hashAlg
            invoke "s2n_connection_get_selected_client_cert_digest_algorithm" $ s2n_connection_get_selected_client_cert_digest_algorithm ffi conn hashAlg
        invoke "s2n_connection_get_selected_cert" $ s2n_connection_get_selected_cert ffi conn
        certResult <- s2n_cert_chain_and_key_new ffi
        case certResult of
            Left _ -> pure ()
            Right peerCert -> do
                invoke "s2n_connection_get_peer_cert_chain" $ s2n_connection_get_peer_cert_chain ffi conn peerCert
                void $ s2n_cert_chain_and_key_free ffi peerCert
        invoke "s2n_connection_get_wire_bytes_in" $ s2n_connection_get_wire_bytes_in ffi conn
        invoke "s2n_connection_get_wire_bytes_out" $ s2n_connection_get_wire_bytes_out ffi conn
        invoke "s2n_connection_get_client_protocol_version" $ s2n_connection_get_client_protocol_version ffi conn
        invoke "s2n_connection_get_server_protocol_version" $ s2n_connection_get_server_protocol_version ffi conn
        invoke "s2n_connection_get_actual_protocol_version" $ s2n_connection_get_actual_protocol_version ffi conn
        invoke "s2n_connection_get_client_hello_version" $ s2n_connection_get_client_hello_version ffi conn
        invoke "s2n_connection_get_cipher" $ s2n_connection_get_cipher ffi conn
        alloca $ \sniMatch ->
            invoke "s2n_connection_get_certificate_match" $ s2n_connection_get_certificate_match ffi conn sniMatch
        allocaBytes 48 $ \buf ->
            invoke "s2n_connection_get_master_secret" $ s2n_connection_get_master_secret ffi conn buf 48
        allocaBytes 32 $ \label -> allocaBytes 32 $ \context -> allocaBytes 32 $ \output ->
            invoke "s2n_connection_tls_exporter" $ s2n_connection_tls_exporter ffi conn label 32 context 32 output 32
        alloca $ \first -> alloca $ \second ->
            invoke "s2n_connection_get_cipher_iana_value" $ s2n_connection_get_cipher_iana_value ffi conn first second
        withCString "default_tls13" $ \policy ->
            invoke "s2n_connection_is_valid_for_cipher_preferences" $ s2n_connection_is_valid_for_cipher_preferences ffi conn policy
        invoke "s2n_connection_get_curve" $ s2n_connection_get_curve ffi conn
        invoke "s2n_connection_get_kem_name" $ s2n_connection_get_kem_name ffi conn
        invoke "s2n_connection_get_kem_group_name" $ s2n_connection_get_kem_group_name ffi conn
        alloca $ \groupName ->
            invoke "s2n_connection_get_key_exchange_group" $ s2n_connection_get_key_exchange_group ffi conn groupName
        invoke "s2n_connection_get_alert" $ s2n_connection_get_alert ffi conn
        invoke "s2n_connection_get_handshake_type_name" $ s2n_connection_get_handshake_type_name ffi conn
        invoke "s2n_connection_get_last_message_name" $ s2n_connection_get_last_message_name ffi conn
        invoke "s2n_connection_set_psk_mode" $ s2n_connection_set_psk_mode ffi conn (S2nPskMode 0)
        alloca $ \lenPtr ->
            invoke "s2n_connection_get_negotiated_psk_identity_length" $ s2n_connection_get_negotiated_psk_identity_length ffi conn lenPtr
        allocaBytes 32 $ \buf ->
            invoke "s2n_connection_get_negotiated_psk_identity" $ s2n_connection_get_negotiated_psk_identity ffi conn buf 32
        invoke "s2n_connection_set_server_max_early_data_size" $ s2n_connection_set_server_max_early_data_size ffi conn 16384
        allocaBytes 100 $ \ctx ->
            invoke "s2n_connection_set_server_early_data_context" $ s2n_connection_set_server_early_data_context ffi conn ctx 100
        alloca $ \status ->
            invoke "s2n_connection_get_early_data_status" $ s2n_connection_get_early_data_status ffi conn status
        alloca $ \remaining ->
            invoke "s2n_connection_get_remaining_early_data_size" $ s2n_connection_get_remaining_early_data_size ffi conn remaining
        alloca $ \maxSize ->
            invoke "s2n_connection_get_max_early_data_size" $ s2n_connection_get_max_early_data_size ffi conn maxSize
        alloca $ \blocked -> allocaBytes 100 $ \buf -> alloca $ \written -> do
            invoke "s2n_send_early_data" $ s2n_send_early_data ffi conn buf 100 written blocked
            invoke "s2n_recv_early_data" $ s2n_recv_early_data ffi conn buf 100 written blocked
        alloca $ \lenPtr ->
            invoke "s2n_connection_serialization_length" $ s2n_connection_serialization_length ffi conn lenPtr
        allocaBytes 1024 $ \buf -> do
            invoke "s2n_connection_serialize" $ s2n_connection_serialize ffi conn buf 1024
            invoke "s2n_connection_deserialize" $ s2n_connection_deserialize ffi conn buf 1024
        invoke "s2n_connection_free_handshake" $ s2n_connection_free_handshake ffi conn
        invoke "s2n_connection_release_buffers" $ s2n_connection_release_buffers ffi conn
        invoke "s2n_connection_wipe" $ s2n_connection_wipe ffi conn

    -- Test s2n_connection_free separately
    result <- s2n_connection_new ffi S2N_CLIENT
    case result of
        Left _ -> pure ()
        Right conn -> invoke "s2n_connection_free" $ s2n_connection_free ffi conn

-- | Helper to run tests with a fresh connection
withConnection :: S2nTlsFfi -> (Ptr S2nConnection -> IO ()) -> IO ()
withConnection ffi action = do
    result <- s2n_connection_new ffi S2N_CLIENT
    case result of
        Left _ -> putStrLn "  [skipped - connection creation failed]"
        Right conn -> do
            action conn
            void $ s2n_connection_free ffi conn

--------------------------------------------------------------------------------
-- PSK Tests
--------------------------------------------------------------------------------

runPskTests :: S2nTlsFfi -> IO ()
runPskTests ffi = do
    putStrLn "\n[PSK]"
    hFlush stdout
    invoke "s2n_external_psk_new" $ s2n_external_psk_new ffi

    withPsk ffi $ \psk -> do
        allocaBytes 32 $ \identity ->
            invoke "s2n_psk_set_identity" $ s2n_psk_set_identity ffi psk identity 32
        allocaBytes 32 $ \secret ->
            invoke "s2n_psk_set_secret" $ s2n_psk_set_secret ffi psk secret 32
        invoke "s2n_psk_set_hmac" $ s2n_psk_set_hmac ffi psk S2N_PSK_HMAC_SHA256
        invoke "s2n_psk_configure_early_data" $ s2n_psk_configure_early_data ffi psk 16384 33 34
        allocaBytes 10 $ \proto ->
            invoke "s2n_psk_set_application_protocol" $ s2n_psk_set_application_protocol ffi psk proto 10
        allocaBytes 32 $ \ctx ->
            invoke "s2n_psk_set_early_data_context" $ s2n_psk_set_early_data_context ffi psk ctx 32

    -- Test s2n_connection_append_psk
    pskResult <- s2n_external_psk_new ffi
    connResult <- s2n_connection_new ffi S2N_CLIENT
    case (pskResult, connResult) of
        (Right psk, Right conn) -> do
            invoke "s2n_connection_append_psk" $ s2n_connection_append_psk ffi conn psk
            void $ s2n_connection_free ffi conn
            alloca $ \pskPtr -> do
                poke pskPtr psk
                void $ s2n_psk_free ffi pskPtr
        _ -> pure ()

    -- Test s2n_psk_free
    pskResult2 <- s2n_external_psk_new ffi
    case pskResult2 of
        Left _ -> pure ()
        Right psk ->
            alloca $ \pskPtr -> do
                poke pskPtr psk
                invoke "s2n_psk_free" $ s2n_psk_free ffi pskPtr

    -- Test offered PSK functions
    invoke "s2n_offered_psk_new" $ s2n_offered_psk_new ffi
    offeredResult <- s2n_offered_psk_new ffi
    case offeredResult of
        Left _ -> pure ()
        Right offered -> do
            alloca $ \identityPtr -> alloca $ \lenPtr ->
                invoke "s2n_offered_psk_get_identity" $ s2n_offered_psk_get_identity ffi offered identityPtr lenPtr
            alloca $ \offeredPtr -> do
                poke offeredPtr offered
                invoke "s2n_offered_psk_free" $ s2n_offered_psk_free ffi offeredPtr

-- | Helper to run tests with a fresh PSK
withPsk :: S2nTlsFfi -> (Ptr S2nPsk -> IO ()) -> IO ()
withPsk ffi action = do
    result <- s2n_external_psk_new ffi
    case result of
        Left _ -> putStrLn "  [skipped - PSK creation failed]"
        Right psk -> do
            action psk
            alloca $ \pskPtr -> do
                poke pskPtr psk
                void $ s2n_psk_free ffi pskPtr

--------------------------------------------------------------------------------
-- Cleanup Tests
--------------------------------------------------------------------------------

runCleanupTests :: S2nTlsFfi -> IO ()
runCleanupTests ffi = do
    putStrLn "\n[Cleanup]"
    hFlush stdout
    invoke "s2n_cleanup" $ s2n_cleanup ffi
    invoke "s2n_cleanup_final" $ s2n_cleanup_final ffi
