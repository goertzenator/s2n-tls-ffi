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

import S2nTls.Sys
import S2nTls.Sys.Types

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
main = withLinkedTlsSys $ \sys -> do
    putStrLn "=== s2n-tls Memory Safety Tests ==="
    hFlush stdout

    runInitTests sys
    runErrorTests sys
    runStackTraceTests sys
    runConfigTests sys
    runCertChainTests sys
    runConnectionTests sys
    runPskTests sys
    runCleanupTests sys

    putStrLn "=== All tests completed ==="
    hFlush stdout

--------------------------------------------------------------------------------
-- Initialization Tests
--------------------------------------------------------------------------------

runInitTests :: S2nTlsSys -> IO ()
runInitTests sys = do
    putStrLn "\n[Initialization]"
    hFlush stdout
    invoke "s2n_init" $ s2n_init sys
    invoke "s2n_crypto_disable_init" $ s2n_crypto_disable_init sys
    invoke "s2n_disable_atexit" $ s2n_disable_atexit sys
    invoke "s2n_get_openssl_version" $ s2n_get_openssl_version sys
    alloca $ \ptr ->
        invoke "s2n_get_fips_mode" $ s2n_get_fips_mode sys ptr

--------------------------------------------------------------------------------
-- Error Handling Tests
--------------------------------------------------------------------------------

runErrorTests :: S2nTlsSys -> IO ()
runErrorTests sys = do
    putStrLn "\n[Error Handling]"
    hFlush stdout
    invoke "s2n_errno_location" $ s2n_errno_location sys
    invoke "s2n_error_get_type" $ s2n_error_get_type sys 0
    withCString "EN" $ \lang -> do
        invoke "s2n_strerror" $ s2n_strerror sys 0 lang
        invoke "s2n_strerror_debug" $ s2n_strerror_debug sys 0 lang
    invoke "s2n_strerror_name" $ s2n_strerror_name sys 0
    invoke "s2n_strerror_source" $ s2n_strerror_source sys 0

--------------------------------------------------------------------------------
-- Stack Trace Tests
--------------------------------------------------------------------------------

runStackTraceTests :: S2nTlsSys -> IO ()
runStackTraceTests sys = do
    putStrLn "\n[Stack Traces]"
    hFlush stdout
    invoke "s2n_stack_traces_enabled" $ s2n_stack_traces_enabled sys
    invoke "s2n_stack_traces_enabled_set" $ s2n_stack_traces_enabled_set sys 0
    invoke "s2n_calculate_stacktrace" $ s2n_calculate_stacktrace sys
    allocaBytes 8 $ \ptr ->
        invoke "s2n_get_stacktrace" $ s2n_get_stacktrace sys ptr
    invoke "s2n_free_stacktrace" $ s2n_free_stacktrace sys

--------------------------------------------------------------------------------
-- Config Tests
--------------------------------------------------------------------------------

runConfigTests :: S2nTlsSys -> IO ()
runConfigTests sys = do
    putStrLn "\n[Config]"
    hFlush stdout
    invoke "s2n_config_new" $ s2n_config_new sys
    invoke "s2n_config_new_minimal" $ s2n_config_new_minimal sys

    -- Run config operation tests with a fresh config
    withConfig sys $ \cfg -> do
        putStrLn "\n[Config Operations]"
        hFlush stdout
        invoke "s2n_config_set_wall_clock" $ s2n_config_set_wall_clock sys cfg nullFunPtr nullPtr
        invoke "s2n_config_set_monotonic_clock" $ s2n_config_set_monotonic_clock sys cfg nullFunPtr nullPtr
        invoke "s2n_config_set_cache_store_callback" $ s2n_config_set_cache_store_callback sys cfg nullFunPtr nullPtr
        invoke "s2n_config_set_cache_retrieve_callback" $ s2n_config_set_cache_retrieve_callback sys cfg nullFunPtr nullPtr
        invoke "s2n_config_set_cache_delete_callback" $ s2n_config_set_cache_delete_callback sys cfg nullFunPtr nullPtr
        invoke "s2n_config_wipe_trust_store" $ s2n_config_wipe_trust_store sys cfg
        invoke "s2n_config_load_system_certs" $ s2n_config_load_system_certs sys cfg
        withCString "/nonexistent" $ \path ->
            invoke "s2n_config_set_verification_ca_location" $ s2n_config_set_verification_ca_location sys cfg path nullPtr
        withCString "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----" $ \pem ->
            invoke "s2n_config_add_pem_to_trust_store" $ s2n_config_add_pem_to_trust_store sys cfg pem
        invoke "s2n_config_set_cert_authorities_from_trust_store" $ s2n_config_set_cert_authorities_from_trust_store sys cfg
        invoke "s2n_config_set_verify_after_sign" $ s2n_config_set_verify_after_sign sys cfg (S2nVerifyAfterSign 0)
        invoke "s2n_config_set_check_stapled_ocsp_response" $ s2n_config_set_check_stapled_ocsp_response sys cfg 0
        invoke "s2n_config_disable_x509_time_verification" $ s2n_config_disable_x509_time_verification sys cfg
        invoke "s2n_config_disable_x509_verification" $ s2n_config_disable_x509_verification sys cfg
        invoke "s2n_config_set_max_cert_chain_depth" $ s2n_config_set_max_cert_chain_depth sys cfg 10
        invoke "s2n_config_set_verify_host_callback" $ s2n_config_set_verify_host_callback sys cfg nullFunPtr nullPtr
        withCString "-----BEGIN DH PARAMETERS-----\ntest\n-----END DH PARAMETERS-----" $ \dh ->
            invoke "s2n_config_add_dhparams" $ s2n_config_add_dhparams sys cfg dh
        withCString "default_tls13" $ \policy ->
            invoke "s2n_config_set_cipher_preferences" $ s2n_config_set_cipher_preferences sys cfg policy
        allocaArray 10 $ \protoPtr ->
            invoke "s2n_config_append_protocol_preference" $ s2n_config_append_protocol_preference sys cfg protoPtr 5
        withCString "h2" $ \proto1 ->
            allocaArray 1 $ \protos -> do
                pokeArray protos [proto1]
                invoke "s2n_config_set_protocol_preferences" $ s2n_config_set_protocol_preferences sys cfg protos 1
        invoke "s2n_config_set_status_request_type" $ s2n_config_set_status_request_type sys cfg (S2nStatusRequestType 0)
        invoke "s2n_config_set_ct_support_level" $ s2n_config_set_ct_support_level sys cfg (S2nCtSupportLevel 0)
        invoke "s2n_config_set_alert_behavior" $ s2n_config_set_alert_behavior sys cfg (S2nAlertBehavior 0)
        allocaBytes 16 $ \buf ->
            invoke "s2n_config_set_extension_data" $ s2n_config_set_extension_data sys cfg (S2nTlsExtensionType 0) buf 16
        invoke "s2n_config_send_max_fragment_length" $ s2n_config_send_max_fragment_length sys cfg (S2nMaxFragLen 1)
        invoke "s2n_config_accept_max_fragment_length" $ s2n_config_accept_max_fragment_length sys cfg
        invoke "s2n_config_set_session_state_lifetime" $ s2n_config_set_session_state_lifetime sys cfg 3600
        invoke "s2n_config_set_session_tickets_onoff" $ s2n_config_set_session_tickets_onoff sys cfg 1
        invoke "s2n_config_set_session_cache_onoff" $ s2n_config_set_session_cache_onoff sys cfg 1
        invoke "s2n_config_set_ticket_encrypt_decrypt_key_lifetime" $ s2n_config_set_ticket_encrypt_decrypt_key_lifetime sys cfg 3600
        invoke "s2n_config_set_ticket_decrypt_key_lifetime" $ s2n_config_set_ticket_decrypt_key_lifetime sys cfg 7200
        allocaBytes 16 $ \keyName -> allocaBytes 32 $ \keyData ->
            invoke "s2n_config_add_ticket_crypto_key" $ s2n_config_add_ticket_crypto_key sys cfg keyName 16 keyData 32 0
        invoke "s2n_config_require_ticket_forward_secrecy" $ s2n_config_require_ticket_forward_secrecy sys cfg 1
        invoke "s2n_config_set_send_buffer_size" $ s2n_config_set_send_buffer_size sys cfg 16384
        invoke "s2n_config_set_recv_multi_record" $ s2n_config_set_recv_multi_record sys cfg 1
        invoke "s2n_config_set_client_hello_cb" $ s2n_config_set_client_hello_cb sys cfg nullFunPtr nullPtr
        invoke "s2n_config_set_client_hello_cb_mode" $ s2n_config_set_client_hello_cb_mode sys cfg (S2nClientHelloCbMode 0)
        invoke "s2n_config_set_max_blinding_delay" $ s2n_config_set_max_blinding_delay sys cfg 30
        alloca $ \authType ->
            invoke "s2n_config_get_client_auth_type" $ s2n_config_get_client_auth_type sys cfg authType
        invoke "s2n_config_set_client_auth_type" $ s2n_config_set_client_auth_type sys cfg (S2nCertAuthType 0)
        invoke "s2n_config_set_initial_ticket_count" $ s2n_config_set_initial_ticket_count sys cfg 2
        invoke "s2n_config_set_psk_mode" $ s2n_config_set_psk_mode sys cfg (S2nPskMode 0)
        invoke "s2n_config_set_psk_selection_callback" $ s2n_config_set_psk_selection_callback sys cfg nullFunPtr nullPtr
        invoke "s2n_config_set_async_pkey_callback" $ s2n_config_set_async_pkey_callback sys cfg nullFunPtr
        invoke "s2n_config_set_async_pkey_validation_mode" $ s2n_config_set_async_pkey_validation_mode sys cfg (S2nAsyncPkeyValidationMode 0)
        invoke "s2n_config_set_session_ticket_cb" $ s2n_config_set_session_ticket_cb sys cfg nullFunPtr nullPtr
        invoke "s2n_config_set_key_log_cb" $ s2n_config_set_key_log_cb sys cfg nullFunPtr nullPtr
        invoke "s2n_config_enable_cert_req_dss_legacy_compat" $ s2n_config_enable_cert_req_dss_legacy_compat sys cfg
        invoke "s2n_config_set_server_max_early_data_size" $ s2n_config_set_server_max_early_data_size sys cfg 16384
        invoke "s2n_config_set_early_data_cb" $ s2n_config_set_early_data_cb sys cfg nullFunPtr
        invoke "s2n_config_set_ctx" $ s2n_config_set_ctx sys cfg nullPtr
        alloca $ \ctxPtr ->
            invoke "s2n_config_get_ctx" $ s2n_config_get_ctx sys cfg ctxPtr
        allocaArray 10 $ \groups -> alloca $ \count ->
            invoke "s2n_config_get_supported_groups" $ s2n_config_get_supported_groups sys cfg groups 10 count
        invoke "s2n_config_set_serialization_version" $ s2n_config_set_serialization_version sys cfg (S2nSerializationVersion 0)
        invoke "s2n_config_set_cert_tiebreak_callback" $ s2n_config_set_cert_tiebreak_callback sys cfg nullFunPtr
        withCString "" $ \emptyPath ->
            invoke "s2n_config_add_cert_chain_and_key" $ s2n_config_add_cert_chain_and_key sys cfg emptyPath emptyPath
        invoke "s2n_config_free_dhparams" $ s2n_config_free_dhparams sys cfg
        invoke "s2n_config_free_cert_chain_and_key" $ s2n_config_free_cert_chain_and_key sys cfg

    -- Test s2n_config_free separately
    result <- s2n_config_new sys
    case result of
        Left _ -> pure ()
        Right cfg -> invoke "s2n_config_free" $ s2n_config_free sys cfg

-- | Helper to run tests with a fresh config
withConfig :: S2nTlsSys -> (Ptr S2nConfig -> IO ()) -> IO ()
withConfig sys action = do
    result <- s2n_config_new sys
    case result of
        Left _ -> putStrLn "  [skipped - config creation failed]"
        Right cfg -> do
            action cfg
            void $ s2n_config_free sys cfg

--------------------------------------------------------------------------------
-- Certificate Chain Tests
--------------------------------------------------------------------------------

runCertChainTests :: S2nTlsSys -> IO ()
runCertChainTests sys = do
    putStrLn "\n[Certificate Chain]"
    hFlush stdout
    invoke "s2n_cert_chain_and_key_new" $ s2n_cert_chain_and_key_new sys

    withCertChain sys $ \cert -> do
        withCString "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----" $ \pemCert ->
            withCString "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----" $ \pemKey ->
                invoke "s2n_cert_chain_and_key_load_pem" $ s2n_cert_chain_and_key_load_pem sys cert pemCert pemKey
        allocaBytes 100 $ \certBuf -> allocaBytes 100 $ \keyBuf ->
            invoke "s2n_cert_chain_and_key_load_pem_bytes" $ s2n_cert_chain_and_key_load_pem_bytes sys cert certBuf 100 keyBuf 100
        allocaBytes 100 $ \buf ->
            invoke "s2n_cert_chain_and_key_load_public_pem_bytes" $ s2n_cert_chain_and_key_load_public_pem_bytes sys cert buf 100
        invoke "s2n_cert_chain_and_key_set_ctx" $ s2n_cert_chain_and_key_set_ctx sys cert nullPtr
        invoke "s2n_cert_chain_and_key_get_ctx" $ s2n_cert_chain_and_key_get_ctx sys cert
        invoke "s2n_cert_chain_and_key_get_private_key" $ s2n_cert_chain_and_key_get_private_key sys cert
        allocaBytes 100 $ \buf ->
            invoke "s2n_cert_chain_and_key_set_ocsp_data" $ s2n_cert_chain_and_key_set_ocsp_data sys cert buf 100
        allocaBytes 100 $ \buf ->
            invoke "s2n_cert_chain_and_key_set_sct_list" $ s2n_cert_chain_and_key_set_sct_list sys cert buf 100
        alloca $ \lengthPtr ->
            invoke "s2n_cert_chain_get_length" $ s2n_cert_chain_get_length sys cert lengthPtr
        alloca $ \certPtr ->
            invoke "s2n_cert_chain_get_cert" $ s2n_cert_chain_get_cert sys cert certPtr 0

    -- Test s2n_cert_chain_and_key_free separately
    result <- s2n_cert_chain_and_key_new sys
    case result of
        Left _ -> pure ()
        Right cert -> invoke "s2n_cert_chain_and_key_free" $ s2n_cert_chain_and_key_free sys cert

-- | Helper to run tests with a fresh cert chain
withCertChain :: S2nTlsSys -> (Ptr S2nCertChainAndKey -> IO ()) -> IO ()
withCertChain sys action = do
    result <- s2n_cert_chain_and_key_new sys
    case result of
        Left _ -> putStrLn "  [skipped - cert chain creation failed]"
        Right cert -> do
            action cert
            void $ s2n_cert_chain_and_key_free sys cert

--------------------------------------------------------------------------------
-- Connection Tests
--------------------------------------------------------------------------------

runConnectionTests :: S2nTlsSys -> IO ()
runConnectionTests sys = do
    putStrLn "\n[Connection]"
    hFlush stdout
    invoke "s2n_connection_new (client)" $ s2n_connection_new sys S2N_CLIENT
    invoke "s2n_connection_new (server)" $ s2n_connection_new sys S2N_SERVER

    withConnection sys $ \conn -> do
        putStrLn "\n[Connection Operations]"
        hFlush stdout

        -- Config assignment
        cfgResult <- s2n_config_new sys
        case cfgResult of
            Left _ -> pure ()
            Right cfg -> do
                invoke "s2n_connection_set_config" $ s2n_connection_set_config sys conn cfg
                void $ s2n_config_free sys cfg

        invoke "s2n_connection_set_ctx" $ s2n_connection_set_ctx sys conn nullPtr
        invoke "s2n_connection_get_ctx" $ s2n_connection_get_ctx sys conn
        invoke "s2n_client_hello_cb_done" $ s2n_client_hello_cb_done sys conn
        invoke "s2n_connection_server_name_extension_used" $ s2n_connection_server_name_extension_used sys conn
        invoke "s2n_connection_get_client_hello" $ s2n_connection_get_client_hello sys conn
        allocaBytes 100 $ \buf ->
            invoke "s2n_client_hello_parse_message" $ s2n_client_hello_parse_message sys buf 100
        invoke "s2n_connection_set_fd" $ s2n_connection_set_fd sys conn (-1)
        invoke "s2n_connection_set_read_fd" $ s2n_connection_set_read_fd sys conn (-1)
        invoke "s2n_connection_set_write_fd" $ s2n_connection_set_write_fd sys conn (-1)
        alloca $ \fdPtr -> do
            invoke "s2n_connection_get_read_fd" $ s2n_connection_get_read_fd sys conn fdPtr
            invoke "s2n_connection_get_write_fd" $ s2n_connection_get_write_fd sys conn fdPtr
        invoke "s2n_connection_use_corked_io" $ s2n_connection_use_corked_io sys conn
        invoke "s2n_connection_set_recv_ctx" $ s2n_connection_set_recv_ctx sys conn nullPtr
        invoke "s2n_connection_set_send_ctx" $ s2n_connection_set_send_ctx sys conn nullPtr
        invoke "s2n_connection_set_recv_cb" $ s2n_connection_set_recv_cb sys conn nullFunPtr
        invoke "s2n_connection_set_send_cb" $ s2n_connection_set_send_cb sys conn nullFunPtr
        invoke "s2n_connection_prefer_throughput" $ s2n_connection_prefer_throughput sys conn
        invoke "s2n_connection_prefer_low_latency" $ s2n_connection_prefer_low_latency sys conn
        invoke "s2n_connection_set_recv_buffering" $ s2n_connection_set_recv_buffering sys conn 1
        invoke "s2n_peek_buffered" $ s2n_peek_buffered sys conn
        invoke "s2n_connection_set_dynamic_buffers" $ s2n_connection_set_dynamic_buffers sys conn 1
        invoke "s2n_connection_set_dynamic_record_threshold" $ s2n_connection_set_dynamic_record_threshold sys conn 1400 100
        invoke "s2n_connection_set_verify_host_callback" $ s2n_connection_set_verify_host_callback sys conn nullFunPtr nullPtr
        invoke "s2n_connection_set_blinding" $ s2n_connection_set_blinding sys conn S2N_SELF_SERVICE_BLINDING
        invoke "s2n_connection_get_delay" $ s2n_connection_get_delay sys conn
        withCString "default_tls13" $ \policy ->
            invoke "s2n_connection_set_cipher_preferences" $ s2n_connection_set_cipher_preferences sys conn policy
        invoke "s2n_connection_request_key_update" $ s2n_connection_request_key_update sys conn (S2nPeerKeyUpdate 0)
        allocaBytes 10 $ \proto ->
            invoke "s2n_connection_append_protocol_preference" $ s2n_connection_append_protocol_preference sys conn proto 5
        withCString "h2" $ \proto1 ->
            allocaArray 1 $ \protos -> do
                pokeArray protos [proto1]
                invoke "s2n_connection_set_protocol_preferences" $ s2n_connection_set_protocol_preferences sys conn protos 1
        withCString "example.com" $ \name ->
            invoke "s2n_set_server_name" $ s2n_set_server_name sys conn name
        invoke "s2n_get_server_name" $ s2n_get_server_name sys conn
        invoke "s2n_get_application_protocol" $ s2n_get_application_protocol sys conn
        alloca $ \lenPtr -> do
            invoke "s2n_connection_get_ocsp_response" $ s2n_connection_get_ocsp_response sys conn lenPtr
            invoke "s2n_connection_get_sct_list" $ s2n_connection_get_sct_list sys conn lenPtr
        alloca $ \blocked -> do
            invoke "s2n_negotiate" $ s2n_negotiate sys conn blocked
            allocaBytes 100 $ \buf -> do
                invoke "s2n_send" $ s2n_send sys conn buf 100 blocked
                invoke "s2n_recv" $ s2n_recv sys conn buf 100 blocked
            invoke "s2n_shutdown" $ s2n_shutdown sys conn blocked
            invoke "s2n_shutdown_send" $ s2n_shutdown_send sys conn blocked
        invoke "s2n_peek" $ s2n_peek sys conn
        alloca $ \authType ->
            invoke "s2n_connection_get_client_auth_type" $ s2n_connection_get_client_auth_type sys conn authType
        invoke "s2n_connection_set_client_auth_type" $ s2n_connection_set_client_auth_type sys conn (S2nCertAuthType 0)
        alloca $ \certPtr -> alloca $ \lenPtr ->
            invoke "s2n_connection_get_client_cert_chain" $ s2n_connection_get_client_cert_chain sys conn certPtr lenPtr
        invoke "s2n_connection_client_cert_used" $ s2n_connection_client_cert_used sys conn
        invoke "s2n_connection_add_new_tickets_to_send" $ s2n_connection_add_new_tickets_to_send sys conn 1
        alloca $ \ticketsPtr ->
            invoke "s2n_connection_get_tickets_sent" $ s2n_connection_get_tickets_sent sys conn ticketsPtr
        invoke "s2n_connection_set_server_keying_material_lifetime" $ s2n_connection_set_server_keying_material_lifetime sys conn 86400
        allocaBytes 256 $ \buf -> do
            invoke "s2n_connection_set_session" $ s2n_connection_set_session sys conn buf 256
            invoke "s2n_connection_get_session" $ s2n_connection_get_session sys conn buf 256
        invoke "s2n_connection_get_session_ticket_lifetime_hint" $ s2n_connection_get_session_ticket_lifetime_hint sys conn
        invoke "s2n_connection_get_session_length" $ s2n_connection_get_session_length sys conn
        invoke "s2n_connection_get_session_id_length" $ s2n_connection_get_session_id_length sys conn
        allocaBytes 32 $ \buf ->
            invoke "s2n_connection_get_session_id" $ s2n_connection_get_session_id sys conn buf 32
        invoke "s2n_connection_is_session_resumed" $ s2n_connection_is_session_resumed sys conn
        invoke "s2n_connection_is_ocsp_stapled" $ s2n_connection_is_ocsp_stapled sys conn
        alloca $ \sigAlg -> do
            invoke "s2n_connection_get_selected_signature_algorithm" $ s2n_connection_get_selected_signature_algorithm sys conn sigAlg
            invoke "s2n_connection_get_selected_client_cert_signature_algorithm" $ s2n_connection_get_selected_client_cert_signature_algorithm sys conn sigAlg
        alloca $ \hashAlg -> do
            invoke "s2n_connection_get_selected_digest_algorithm" $ s2n_connection_get_selected_digest_algorithm sys conn hashAlg
            invoke "s2n_connection_get_selected_client_cert_digest_algorithm" $ s2n_connection_get_selected_client_cert_digest_algorithm sys conn hashAlg
        invoke "s2n_connection_get_selected_cert" $ s2n_connection_get_selected_cert sys conn
        certResult <- s2n_cert_chain_and_key_new sys
        case certResult of
            Left _ -> pure ()
            Right peerCert -> do
                invoke "s2n_connection_get_peer_cert_chain" $ s2n_connection_get_peer_cert_chain sys conn peerCert
                void $ s2n_cert_chain_and_key_free sys peerCert
        invoke "s2n_connection_get_wire_bytes_in" $ s2n_connection_get_wire_bytes_in sys conn
        invoke "s2n_connection_get_wire_bytes_out" $ s2n_connection_get_wire_bytes_out sys conn
        invoke "s2n_connection_get_client_protocol_version" $ s2n_connection_get_client_protocol_version sys conn
        invoke "s2n_connection_get_server_protocol_version" $ s2n_connection_get_server_protocol_version sys conn
        invoke "s2n_connection_get_actual_protocol_version" $ s2n_connection_get_actual_protocol_version sys conn
        invoke "s2n_connection_get_client_hello_version" $ s2n_connection_get_client_hello_version sys conn
        invoke "s2n_connection_get_cipher" $ s2n_connection_get_cipher sys conn
        alloca $ \sniMatch ->
            invoke "s2n_connection_get_certificate_match" $ s2n_connection_get_certificate_match sys conn sniMatch
        allocaBytes 48 $ \buf ->
            invoke "s2n_connection_get_master_secret" $ s2n_connection_get_master_secret sys conn buf 48
        allocaBytes 32 $ \label -> allocaBytes 32 $ \context -> allocaBytes 32 $ \output ->
            invoke "s2n_connection_tls_exporter" $ s2n_connection_tls_exporter sys conn label 32 context 32 output 32
        alloca $ \first -> alloca $ \second ->
            invoke "s2n_connection_get_cipher_iana_value" $ s2n_connection_get_cipher_iana_value sys conn first second
        withCString "default_tls13" $ \policy ->
            invoke "s2n_connection_is_valid_for_cipher_preferences" $ s2n_connection_is_valid_for_cipher_preferences sys conn policy
        invoke "s2n_connection_get_curve" $ s2n_connection_get_curve sys conn
        invoke "s2n_connection_get_kem_name" $ s2n_connection_get_kem_name sys conn
        invoke "s2n_connection_get_kem_group_name" $ s2n_connection_get_kem_group_name sys conn
        alloca $ \groupName ->
            invoke "s2n_connection_get_key_exchange_group" $ s2n_connection_get_key_exchange_group sys conn groupName
        invoke "s2n_connection_get_alert" $ s2n_connection_get_alert sys conn
        invoke "s2n_connection_get_handshake_type_name" $ s2n_connection_get_handshake_type_name sys conn
        invoke "s2n_connection_get_last_message_name" $ s2n_connection_get_last_message_name sys conn
        invoke "s2n_connection_set_psk_mode" $ s2n_connection_set_psk_mode sys conn (S2nPskMode 0)
        alloca $ \lenPtr ->
            invoke "s2n_connection_get_negotiated_psk_identity_length" $ s2n_connection_get_negotiated_psk_identity_length sys conn lenPtr
        allocaBytes 32 $ \buf ->
            invoke "s2n_connection_get_negotiated_psk_identity" $ s2n_connection_get_negotiated_psk_identity sys conn buf 32
        invoke "s2n_connection_set_server_max_early_data_size" $ s2n_connection_set_server_max_early_data_size sys conn 16384
        allocaBytes 100 $ \ctx ->
            invoke "s2n_connection_set_server_early_data_context" $ s2n_connection_set_server_early_data_context sys conn ctx 100
        alloca $ \status ->
            invoke "s2n_connection_get_early_data_status" $ s2n_connection_get_early_data_status sys conn status
        alloca $ \remaining ->
            invoke "s2n_connection_get_remaining_early_data_size" $ s2n_connection_get_remaining_early_data_size sys conn remaining
        alloca $ \maxSize ->
            invoke "s2n_connection_get_max_early_data_size" $ s2n_connection_get_max_early_data_size sys conn maxSize
        alloca $ \blocked -> allocaBytes 100 $ \buf -> alloca $ \written -> do
            invoke "s2n_send_early_data" $ s2n_send_early_data sys conn buf 100 written blocked
            invoke "s2n_recv_early_data" $ s2n_recv_early_data sys conn buf 100 written blocked
        alloca $ \lenPtr ->
            invoke "s2n_connection_serialization_length" $ s2n_connection_serialization_length sys conn lenPtr
        allocaBytes 1024 $ \buf -> do
            invoke "s2n_connection_serialize" $ s2n_connection_serialize sys conn buf 1024
            invoke "s2n_connection_deserialize" $ s2n_connection_deserialize sys conn buf 1024
        invoke "s2n_connection_free_handshake" $ s2n_connection_free_handshake sys conn
        invoke "s2n_connection_release_buffers" $ s2n_connection_release_buffers sys conn
        invoke "s2n_connection_wipe" $ s2n_connection_wipe sys conn

    -- Test s2n_connection_free separately
    result <- s2n_connection_new sys S2N_CLIENT
    case result of
        Left _ -> pure ()
        Right conn -> invoke "s2n_connection_free" $ s2n_connection_free sys conn

-- | Helper to run tests with a fresh connection
withConnection :: S2nTlsSys -> (Ptr S2nConnection -> IO ()) -> IO ()
withConnection sys action = do
    result <- s2n_connection_new sys S2N_CLIENT
    case result of
        Left _ -> putStrLn "  [skipped - connection creation failed]"
        Right conn -> do
            action conn
            void $ s2n_connection_free sys conn

--------------------------------------------------------------------------------
-- PSK Tests
--------------------------------------------------------------------------------

runPskTests :: S2nTlsSys -> IO ()
runPskTests sys = do
    putStrLn "\n[PSK]"
    hFlush stdout
    invoke "s2n_external_psk_new" $ s2n_external_psk_new sys

    withPsk sys $ \psk -> do
        allocaBytes 32 $ \identity ->
            invoke "s2n_psk_set_identity" $ s2n_psk_set_identity sys psk identity 32
        allocaBytes 32 $ \secret ->
            invoke "s2n_psk_set_secret" $ s2n_psk_set_secret sys psk secret 32
        invoke "s2n_psk_set_hmac" $ s2n_psk_set_hmac sys psk S2N_PSK_HMAC_SHA256
        invoke "s2n_psk_configure_early_data" $ s2n_psk_configure_early_data sys psk 16384 33 34
        allocaBytes 10 $ \proto ->
            invoke "s2n_psk_set_application_protocol" $ s2n_psk_set_application_protocol sys psk proto 10
        allocaBytes 32 $ \ctx ->
            invoke "s2n_psk_set_early_data_context" $ s2n_psk_set_early_data_context sys psk ctx 32

    -- Test s2n_connection_append_psk
    pskResult <- s2n_external_psk_new sys
    connResult <- s2n_connection_new sys S2N_CLIENT
    case (pskResult, connResult) of
        (Right psk, Right conn) -> do
            invoke "s2n_connection_append_psk" $ s2n_connection_append_psk sys conn psk
            void $ s2n_connection_free sys conn
            alloca $ \pskPtr -> do
                poke pskPtr psk
                void $ s2n_psk_free sys pskPtr
        _ -> pure ()

    -- Test s2n_psk_free
    pskResult2 <- s2n_external_psk_new sys
    case pskResult2 of
        Left _ -> pure ()
        Right psk ->
            alloca $ \pskPtr -> do
                poke pskPtr psk
                invoke "s2n_psk_free" $ s2n_psk_free sys pskPtr

    -- Test offered PSK functions
    invoke "s2n_offered_psk_new" $ s2n_offered_psk_new sys
    offeredResult <- s2n_offered_psk_new sys
    case offeredResult of
        Left _ -> pure ()
        Right offered -> do
            alloca $ \identityPtr -> alloca $ \lenPtr ->
                invoke "s2n_offered_psk_get_identity" $ s2n_offered_psk_get_identity sys offered identityPtr lenPtr
            alloca $ \offeredPtr -> do
                poke offeredPtr offered
                invoke "s2n_offered_psk_free" $ s2n_offered_psk_free sys offeredPtr

-- | Helper to run tests with a fresh PSK
withPsk :: S2nTlsSys -> (Ptr S2nPsk -> IO ()) -> IO ()
withPsk sys action = do
    result <- s2n_external_psk_new sys
    case result of
        Left _ -> putStrLn "  [skipped - PSK creation failed]"
        Right psk -> do
            action psk
            alloca $ \pskPtr -> do
                poke pskPtr psk
                void $ s2n_psk_free sys pskPtr

--------------------------------------------------------------------------------
-- Cleanup Tests
--------------------------------------------------------------------------------

runCleanupTests :: S2nTlsSys -> IO ()
runCleanupTests sys = do
    putStrLn "\n[Cleanup]"
    hFlush stdout
    invoke "s2n_cleanup" $ s2n_cleanup sys
    invoke "s2n_cleanup_final" $ s2n_cleanup_final sys
