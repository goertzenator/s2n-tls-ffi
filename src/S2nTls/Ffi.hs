{-# LANGUAGE RecordWildCards #-}

{- |
Module      : S2nTls.Ffi
Description : Low-level FFI bindings to the s2n-tls library
Copyright   : (c) 2026 Daniel Goertzen
License     : Apache-2.0
Maintainer  : daniel.goertzen@gmail.com
Stability   : experimental
Portability : non-portable (requires s2n-tls C library)

This module provides low-level FFI bindings to the s2n-tls library.

The core type is 'S2nTlsFfi', a record containing all FFI function
pointers. Use 'withS2nTlsFfi' with a 'Library' to obtain one:

* 'Linked': For executables that link s2n-tls at compile time.
  Uses dlopen(NULL) to load symbols from the running executable.

* @'Dynamic' path@: To load the library at runtime via dlopen.
  Pass the path to libs2n.so.

C wrappers are used to safely capture error information
(including TLS-dependent error strings) in the same C stack frame,
avoiding thread-local storage issues in Haskell FFI.

Symbol loading is forgiving - missing symbols don't cause failure
at load time. Instead, calling a missing symbol throws 'MissingSymbol'.
Check the 'missingSymbols' field to see which symbols weren't found.

= Memory Locking (mlock)

== What is mlock?

s2n-tls uses the Linux @mlock()@ system call to lock memory pages containing
cryptographic secrets (private keys, session keys, etc.) into RAM. This prevents
the operating system from swapping these pages to disk, where they could
potentially be recovered by an attacker after your application terminates.

== The RLIMIT_MEMLOCK Limit

Linux enforces a per-process limit on how much memory can be locked, controlled
by @RLIMIT_MEMLOCK@. On many systems, this defaults to just __64 KB__ (or even
32 KB on some Debian versions). Since s2n-tls locks memory for all TLS
connections and cryptographic operations, this limit can be exhausted quickly
in applications handling multiple connections.

When the limit is exceeded, you'll see errors like:

> Error Message: 'error calling mlock'
> Debug String: 'Error encountered in s2n_mem.c line 106'

== Solutions

__Option 1: Increase the mlock limit (recommended for production)__

Raise the limit for your shell session:

> ulimit -l unlimited

Or set it to a specific value (in KB):

> ulimit -l 65536  # 64 MB

For systemd services, add to your unit file:

> [Service]
> LimitMEMLOCK=infinity

For persistent user limits, add to @\/etc\/security\/limits.conf@:

> youruser  soft  memlock  unlimited
> youruser  hard  memlock  unlimited

__Option 2: Disable mlock (acceptable for development\/testing)__

Set the environment variable to disable memory locking entirely:

> S2N_DONT_MLOCK=1 ./your-application

== Security Considerations

* __With mlock enabled__: Secrets are protected from being written to swap,
  reducing the risk of recovery from disk. This is the recommended setting
  for production deployments handling sensitive data.

* __With mlock disabled__: Secrets may be swapped to disk under memory
  pressure. This is generally acceptable for development, testing, and
  applications where the threat model doesn't include disk forensics.

* __Note__: Even with mlock enabled, laptop suspend\/hibernate modes may
  save RAM contents to disk regardless of memory locks.

== Running Tests

Tests may exhaust the default mlock limit. Use:

> S2N_DONT_MLOCK=1 cabal test
-}
module S2nTls.Ffi (
    -- * Core Types
    S2nTlsFfi (..),

    -- * Library Loading
    Library (..),
    withS2nTlsFfi,
    LoadError (..),

    -- * Error Types
    MissingSymbol (..),
    S2nError (..),
    S2nErrorFuncs (..),
) where

import Control.Exception (Exception, bracket, throwIO)
import Control.Monad (when)
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.Word (Word16, Word32, Word64, Word8)
import Foreign.C.String (CString)
import Foreign.C.Types (CBool (..), CInt (..), CLong (..), CSize (..))
import Foreign.Marshal.Alloc (alloca, free, malloc)
import Foreign.Ptr (FunPtr, Ptr, nullFunPtr, nullPtr)
import Foreign.Storable (peek, poke)
import System.Posix.DynamicLinker (DL, RTLDFlags (RTLD_LAZY, RTLD_LOCAL), dlclose, dlopen, dlsym)
import System.Posix.Types (CSsize (..))

import S2nTls.Ffi.Types

-- | Specifies how to load the s2n-tls library.
data Library
    = -- | Load symbols from the currently linked executable (uses dlopen(NULL))
      Linked
    | -- | Load library dynamically from the given path
      Dynamic String
    deriving (Show, Eq)

-- | Errors that can occur when loading the s2n-tls library.
data LoadError
    = -- | Library file could not be opened
      LibraryNotFound FilePath String
    | -- | A required symbol was not found in the library
      RequiredSymbolNotFound String
    deriving (Show, Eq)

instance Exception LoadError

class TransformError a where
    transformError :: (Ptr S2nError -> IO a) -> IO (Either S2nError a)

instance TransformError CInt where
    transformError action = alloca $ \errInfoPtr -> do
        res <- action errInfoPtr
        if res < 0
            then Left <$> peek errInfoPtr
            else pure $ Right res

instance TransformError CSsize where
    transformError action = alloca $ \errInfoPtr -> do
        res <- action errInfoPtr
        if res < 0
            then Left <$> peek errInfoPtr
            else pure $ Right res

instance TransformError (Ptr a) where
    transformError action = alloca $ \errInfoPtr -> do
        res <- action errInfoPtr
        if res == nullPtr
            then Left <$> peek errInfoPtr
            else pure $ Right res

-- CSize is unsigned, so functions returning CSize typically can't fail
-- They always return a valid size value
instance TransformError CSize where
    transformError action = alloca $ \errInfoPtr -> do
        res <- action errInfoPtr
        pure $ Right res

const2 :: a -> b -> c -> a
const2 x _ _ = x

const3 :: a -> b -> c -> d -> a
const3 x _ _ _ = x

const4 :: a -> b -> c -> d -> e -> a
const4 x _ _ _ _ = x

const5 :: a -> b -> c -> d -> e -> f -> a
const5 x _ _ _ _ _ = x

const6 :: a -> b -> c -> d -> e -> f -> g -> a
const6 x _ _ _ _ _ _ = x

const7 :: a -> b -> c -> d -> e -> f -> g -> h -> a
const7 x _ _ _ _ _ _ _ = x

{- | Load the s2n-tls library and provide a 'S2nTlsFfi' record to the
given callback. The library is automatically unloaded when the callback
returns (or throws an exception).

@
-- Use symbols from the linked executable
withS2nTlsFfi Linked $ \\ffi -> do
    result <- s2n_init ffi
    ...

-- Load library dynamically
withS2nTlsFfi (Dynamic "libs2n.so") $ \\ffi -> do
    print (missingSymbols ffi)  -- see which symbols weren't found
    ...
@
-}
withS2nTlsFfi ::
    -- | How to load the library
    Library ->
    -- | Callback that receives the populated 'S2nTlsFfi' record
    (S2nTlsFfi -> IO a) ->
    IO a
withS2nTlsFfi lib action =
    bracket (openLib (libraryPath lib)) dlclose $ \dl ->
        bracket (malloc :: IO (Ptr S2nErrorFuncs)) free $ \errFuncsPtr -> do
            -- Load error functions first (fatal if missing)
            errFuncs <- loadErrorFuncs dl
            poke errFuncsPtr errFuncs

            -- Load all other symbols (forgiving)
            (ffi, missing) <- loadSymbols dl errFuncsPtr
            action ffi{missingSymbols = missing}

-- | Convert Library to the path string for dlopen
libraryPath :: Library -> FilePath
libraryPath Linked = ""
libraryPath (Dynamic path) = path

-- | Open the library, handling empty path for dlopen(NULL)
openLib :: FilePath -> IO DL
openLib path = dlopen path [RTLD_LAZY, RTLD_LOCAL]

-- | Load the error functions (required for meaningful error reporting)
loadErrorFuncs :: DL -> IO S2nErrorFuncs
loadErrorFuncs dl = do
    el <- dlsym dl "s2n_errno_location"
    sd <- dlsym dl "s2n_strerror_debug"
    et <- dlsym dl "s2n_error_get_type"
    pure $ S2nErrorFuncs el sd et

-- | Create a closure that throws MissingSymbol
throwMissing :: String -> IO a
throwMissing name = throwIO (MissingSymbol name)

-- | Indicate where a symbol is required vs optional
data MethodRequirement = Mandatory | Optional
    deriving (Show, Eq)

{- | Load all s2n-tls symbols from the given dynamic library handle.
Returns the S2nTlsFfi record and list of missing symbol names.
-}
loadSymbols :: DL -> Ptr S2nErrorFuncs -> IO (S2nTlsFfi, [String])
loadSymbols dl errFuncsPtr = do
    missingRef <- newIORef []

    let
        -- Helper to load a symbol with forgiving behavior
        load :: String -> MethodRequirement -> IO (FunPtr a)
        load name req = do
            ptr <- dlsym dl name
            when (ptr == nullFunPtr) $ do
                modifyIORef' missingRef (name :)
            if ptr == nullFunPtr && req == Mandatory
                then do
                    throwMissing name
                else do
                    pure ptr

        mkMethod0Direct :: String -> MethodRequirement -> (FunPtr x -> IO r) -> IO (IO r)
        mkMethod0Direct name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then throwMissing name
                    else action ptr

        mkMethod1Direct :: String -> MethodRequirement -> (FunPtr x -> a -> IO r) -> IO (a -> IO r)
        mkMethod1Direct name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const (throwMissing name)
                    else action ptr

        mkMethod2Direct :: String -> MethodRequirement -> (FunPtr x -> a -> b -> IO r) -> IO (a -> b -> IO r)
        mkMethod2Direct name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const2 (throwMissing name)
                    else action ptr

        -- Note: C wrappers have signature: FunPtr -> args... -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r
        mkMethod0 :: (TransformError r) => String -> MethodRequirement -> (FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r) -> IO (IO (Either S2nError r))
        mkMethod0 name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then throwMissing name
                    else transformError (action ptr errFuncsPtr)

        mkMethod1 :: (TransformError r) => String -> MethodRequirement -> (FunPtr () -> a -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r) -> IO (a -> IO (Either S2nError r))
        mkMethod1 name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const (throwMissing name)
                    else \a -> transformError (action ptr a errFuncsPtr)

        mkMethod2 :: (TransformError r) => String -> MethodRequirement -> (FunPtr () -> a -> b -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r) -> IO (a -> b -> IO (Either S2nError r))
        mkMethod2 name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const2 (throwMissing name)
                    else \a b -> transformError (action ptr a b errFuncsPtr)

        mkMethod3 :: (TransformError r) => String -> MethodRequirement -> (FunPtr () -> a -> b -> c -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r) -> IO (a -> b -> c -> IO (Either S2nError r))
        mkMethod3 name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const3 (throwMissing name)
                    else \a b c -> transformError (action ptr a b c errFuncsPtr)

        mkMethod4 :: (TransformError r) => String -> MethodRequirement -> (FunPtr () -> a -> b -> c -> d -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r) -> IO (a -> b -> c -> d -> IO (Either S2nError r))
        mkMethod4 name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const4 (throwMissing name)
                    else \a b c d -> transformError (action ptr a b c d errFuncsPtr)

        mkMethod5 :: (TransformError r) => String -> MethodRequirement -> (FunPtr () -> a -> b -> c -> d -> e -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r) -> IO (a -> b -> c -> d -> e -> IO (Either S2nError r))
        mkMethod5 name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const5 (throwMissing name)
                    else \a b c d e -> transformError (action ptr a b c d e errFuncsPtr)

        mkMethod6 :: (TransformError r) => String -> MethodRequirement -> (FunPtr () -> a -> b -> c -> d -> e -> f -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r) -> IO (a -> b -> c -> d -> e -> f -> IO (Either S2nError r))
        mkMethod6 name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const6 (throwMissing name)
                    else \a b c d e f -> transformError (action ptr a b c d e f errFuncsPtr)

        mkMethod7 :: (TransformError r) => String -> MethodRequirement -> (FunPtr () -> a -> b -> c -> d -> e -> f -> g -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO r) -> IO (a -> b -> c -> d -> e -> f -> g -> IO (Either S2nError r))
        mkMethod7 name req action = do
            ptr <- load name req
            pure $
                if ptr == nullFunPtr
                    then const7 (throwMissing name)
                    else \a b c d e f g -> transformError (action ptr a b c d e f g errFuncsPtr)

    -- Initialization & Cleanup
    s2n_init <- mkMethod0 "s2n_init" Optional c_wrap_init
    s2n_cleanup <- mkMethod0 "s2n_cleanup" Optional c_wrap_cleanup
    s2n_cleanup_final <- mkMethod0 "s2n_cleanup_final" Optional c_wrap_cleanup_final
    s2n_crypto_disable_init <- mkMethod0 "s2n_crypto_disable_init" Optional c_wrap_crypto_disable_init
    s2n_disable_atexit <- mkMethod0 "s2n_disable_atexit" Optional c_wrap_disable_atexit
    s2n_get_openssl_version <- mkMethod0Direct "s2n_get_openssl_version" Mandatory mk_s2n_get_openssl_version
    s2n_get_fips_mode <- mkMethod1 "s2n_get_fips_mode" Optional c_wrap_get_fips_mode

    -- Error Handling (load function pointers and wrap directly)
    s2n_errno_location <- mkMethod0Direct "s2n_errno_location" Mandatory mk_s2n_errno_location
    s2n_strerror <- mkMethod2Direct "s2n_strerror" Mandatory mk_s2n_strerror
    s2n_strerror_debug <- mkMethod2Direct "s2n_strerror_debug" Mandatory mk_s2n_strerror_debug
    s2n_strerror_source <- mkMethod1Direct "s2n_strerror_source" Mandatory mk_s2n_strerror_source
    s2n_error_get_type <- mkMethod1Direct "s2n_error_get_type" Mandatory mk_s2n_error_get_type
    s2n_strerror_name <- mkMethod1Direct "s2n_strerror_name" Mandatory mk_s2n_strerror_name

    -- Stack Traces
    s2n_stack_traces_enabled <- mkMethod0Direct "s2n_stack_traces_enabled" Optional mk_s2n_stack_traces_enabled
    s2n_stack_traces_enabled_set <- mkMethod1 "s2n_stack_traces_enabled_set" Optional c_wrap_stack_traces_enabled_set
    s2n_calculate_stacktrace <- mkMethod0 "s2n_calculate_stacktrace" Optional c_wrap_calculate_stacktrace
    s2n_free_stacktrace <- mkMethod0 "s2n_free_stacktrace" Optional c_wrap_free_stacktrace
    s2n_get_stacktrace <- mkMethod1 "s2n_get_stacktrace" Optional c_wrap_get_stacktrace

    -- Config Management
    s2n_config_new <- mkMethod0 "s2n_config_new" Optional c_wrap_config_new
    s2n_config_new_minimal <- mkMethod0 "s2n_config_new_minimal" Optional c_wrap_config_new_minimal
    s2n_config_free <- mkMethod1 "s2n_config_free" Optional c_wrap_config_free
    s2n_config_free_dhparams <- mkMethod1 "s2n_config_free_dhparams" Optional c_wrap_config_free_dhparams
    s2n_config_free_cert_chain_and_key <- mkMethod1 "s2n_config_free_cert_chain_and_key" Optional c_wrap_config_free_cert_chain_and_key
    s2n_config_set_wall_clock <- mkMethod3 "s2n_config_set_wall_clock" Optional c_wrap_config_set_wall_clock
    s2n_config_set_monotonic_clock <- mkMethod3 "s2n_config_set_monotonic_clock" Optional c_wrap_config_set_monotonic_clock
    -- Cache Callbacks
    s2n_config_set_cache_store_callback <- mkMethod3 "s2n_config_set_cache_store_callback" Optional c_wrap_config_set_cache_store_callback
    s2n_config_set_cache_retrieve_callback <- mkMethod3 "s2n_config_set_cache_retrieve_callback" Optional c_wrap_config_set_cache_retrieve_callback
    s2n_config_set_cache_delete_callback <- mkMethod3 "s2n_config_set_cache_delete_callback" Optional c_wrap_config_set_cache_delete_callback
    -- Memory & Random Callbacks
    s2n_mem_set_callbacks <- mkMethod4 "s2n_mem_set_callbacks" Optional c_wrap_mem_set_callbacks
    s2n_rand_set_callbacks <- mkMethod4 "s2n_rand_set_callbacks" Optional c_wrap_rand_set_callbacks

    -- Certificate Chain Management
    s2n_cert_chain_and_key_new <- mkMethod0 "s2n_cert_chain_and_key_new" Optional c_wrap_cert_chain_and_key_new
    s2n_cert_chain_and_key_load_pem <- mkMethod3 "s2n_cert_chain_and_key_load_pem" Optional c_wrap_cert_chain_and_key_load_pem
    s2n_cert_chain_and_key_load_pem_bytes <- mkMethod5 "s2n_cert_chain_and_key_load_pem_bytes" Optional c_wrap_cert_chain_and_key_load_pem_bytes
    s2n_cert_chain_and_key_load_public_pem_bytes <- mkMethod3 "s2n_cert_chain_and_key_load_public_pem_bytes" Optional c_wrap_cert_chain_and_key_load_public_pem_bytes
    s2n_cert_chain_and_key_free <- mkMethod1 "s2n_cert_chain_and_key_free" Optional c_wrap_cert_chain_and_key_free
    s2n_cert_chain_and_key_set_ctx <- mkMethod2 "s2n_cert_chain_and_key_set_ctx" Optional c_wrap_cert_chain_and_key_set_ctx
    s2n_cert_chain_and_key_get_ctx <- mkMethod1Direct "s2n_cert_chain_and_key_get_ctx" Mandatory mk_s2n_cert_chain_and_key_get_ctx
    s2n_cert_chain_and_key_get_private_key <- mkMethod1 "s2n_cert_chain_and_key_get_private_key" Optional c_wrap_cert_chain_and_key_get_private_key
    s2n_cert_chain_and_key_set_ocsp_data <- mkMethod3 "s2n_cert_chain_and_key_set_ocsp_data" Optional c_wrap_cert_chain_and_key_set_ocsp_data
    s2n_cert_chain_and_key_set_sct_list <- mkMethod3 "s2n_cert_chain_and_key_set_sct_list" Optional c_wrap_cert_chain_and_key_set_sct_list
    s2n_config_set_cert_tiebreak_callback <- mkMethod2 "s2n_config_set_cert_tiebreak_callback" Optional c_wrap_config_set_cert_tiebreak_callback
    s2n_config_add_cert_chain_and_key <- mkMethod3 "s2n_config_add_cert_chain_and_key" Optional c_wrap_config_add_cert_chain_and_key
    s2n_config_add_cert_chain_and_key_to_store <- mkMethod2 "s2n_config_add_cert_chain_and_key_to_store" Optional c_wrap_config_add_cert_chain_and_key_to_store
    s2n_config_set_cert_chain_and_key_defaults <- mkMethod3 "s2n_config_set_cert_chain_and_key_defaults" Optional c_wrap_config_set_cert_chain_and_key_defaults

    -- Trust Store
    s2n_config_set_verification_ca_location <- mkMethod3 "s2n_config_set_verification_ca_location" Optional c_wrap_config_set_verification_ca_location
    s2n_config_add_pem_to_trust_store <- mkMethod2 "s2n_config_add_pem_to_trust_store" Optional c_wrap_config_add_pem_to_trust_store
    s2n_config_wipe_trust_store <- mkMethod1 "s2n_config_wipe_trust_store" Optional c_wrap_config_wipe_trust_store
    s2n_config_load_system_certs <- mkMethod1 "s2n_config_load_system_certs" Optional c_wrap_config_load_system_certs
    s2n_config_set_cert_authorities_from_trust_store <- mkMethod1 "s2n_config_set_cert_authorities_from_trust_store" Optional c_wrap_config_set_cert_authorities_from_trust_store

    -- Verification & Validation
    s2n_config_set_verify_after_sign <- mkMethod2 "s2n_config_set_verify_after_sign" Optional c_wrap_config_set_verify_after_sign
    s2n_config_set_check_stapled_ocsp_response <- mkMethod2 "s2n_config_set_check_stapled_ocsp_response" Optional c_wrap_config_set_check_stapled_ocsp_response
    s2n_config_disable_x509_time_verification <- mkMethod1 "s2n_config_disable_x509_time_verification" Optional c_wrap_config_disable_x509_time_verification
    s2n_config_disable_x509_verification <- mkMethod1 "s2n_config_disable_x509_verification" Optional c_wrap_config_disable_x509_verification
    s2n_config_set_max_cert_chain_depth <- mkMethod2 "s2n_config_set_max_cert_chain_depth" Optional c_wrap_config_set_max_cert_chain_depth
    s2n_config_set_verify_host_callback <- mkMethod3 "s2n_config_set_verify_host_callback" Optional c_wrap_config_set_verify_host_callback

    -- DH Parameters
    s2n_config_add_dhparams <- mkMethod2 "s2n_config_add_dhparams" Optional c_wrap_config_add_dhparams

    -- Security Policies & Preferences
    s2n_config_set_cipher_preferences <- mkMethod2 "s2n_config_set_cipher_preferences" Optional c_wrap_config_set_cipher_preferences
    s2n_config_append_protocol_preference <- mkMethod3 "s2n_config_append_protocol_preference" Optional c_wrap_config_append_protocol_preference
    s2n_config_set_protocol_preferences <- mkMethod3 "s2n_config_set_protocol_preferences" Optional c_wrap_config_set_protocol_preferences
    s2n_config_set_status_request_type <- mkMethod2 "s2n_config_set_status_request_type" Optional c_wrap_config_set_status_request_type
    s2n_config_set_ct_support_level <- mkMethod2 "s2n_config_set_ct_support_level" Optional c_wrap_config_set_ct_support_level
    s2n_config_set_alert_behavior <- mkMethod2 "s2n_config_set_alert_behavior" Optional c_wrap_config_set_alert_behavior

    -- Extension Data
    s2n_config_set_extension_data <- mkMethod4 "s2n_config_set_extension_data" Optional c_wrap_config_set_extension_data
    s2n_config_send_max_fragment_length <- mkMethod2 "s2n_config_send_max_fragment_length" Optional c_wrap_config_send_max_fragment_length
    s2n_config_accept_max_fragment_length <- mkMethod1 "s2n_config_accept_max_fragment_length" Optional c_wrap_config_accept_max_fragment_length

    -- Session & Ticket Configuration
    s2n_config_set_session_state_lifetime <- mkMethod2 "s2n_config_set_session_state_lifetime" Optional c_wrap_config_set_session_state_lifetime
    s2n_config_set_session_tickets_onoff <- mkMethod2 "s2n_config_set_session_tickets_onoff" Optional c_wrap_config_set_session_tickets_onoff
    s2n_config_set_session_cache_onoff <- mkMethod2 "s2n_config_set_session_cache_onoff" Optional c_wrap_config_set_session_cache_onoff
    s2n_config_set_ticket_encrypt_decrypt_key_lifetime <- mkMethod2 "s2n_config_set_ticket_encrypt_decrypt_key_lifetime" Optional c_wrap_config_set_ticket_encrypt_decrypt_key_lifetime
    s2n_config_set_ticket_decrypt_key_lifetime <- mkMethod2 "s2n_config_set_ticket_decrypt_key_lifetime" Optional c_wrap_config_set_ticket_decrypt_key_lifetime
    s2n_config_add_ticket_crypto_key <- mkMethod6 "s2n_config_add_ticket_crypto_key" Optional c_wrap_config_add_ticket_crypto_key
    s2n_config_require_ticket_forward_secrecy <- mkMethod2 "s2n_config_require_ticket_forward_secrecy" Optional c_wrap_config_require_ticket_forward_secrecy
    -- Buffer & I/O Configuration
    s2n_config_set_send_buffer_size <- mkMethod2 "s2n_config_set_send_buffer_size" Optional c_wrap_config_set_send_buffer_size
    s2n_config_set_recv_multi_record <- mkMethod2 "s2n_config_set_recv_multi_record" Optional c_wrap_config_set_recv_multi_record

    -- Miscellaneous Config
    s2n_config_set_ctx <- mkMethod2 "s2n_config_set_ctx" Optional c_wrap_config_set_ctx
    s2n_config_get_ctx <- mkMethod2 "s2n_config_get_ctx" Optional c_wrap_config_get_ctx
    s2n_config_set_client_hello_cb <- mkMethod3 "s2n_config_set_client_hello_cb" Optional c_wrap_config_set_client_hello_cb
    s2n_config_set_client_hello_cb_mode <- mkMethod2 "s2n_config_set_client_hello_cb_mode" Optional c_wrap_config_set_client_hello_cb_mode
    s2n_config_set_max_blinding_delay <- mkMethod2 "s2n_config_set_max_blinding_delay" Optional c_wrap_config_set_max_blinding_delay
    s2n_config_get_client_auth_type <- mkMethod2 "s2n_config_get_client_auth_type" Optional c_wrap_config_get_client_auth_type
    s2n_config_set_client_auth_type <- mkMethod2 "s2n_config_set_client_auth_type" Optional c_wrap_config_set_client_auth_type
    s2n_config_set_initial_ticket_count <- mkMethod2 "s2n_config_set_initial_ticket_count" Optional c_wrap_config_set_initial_ticket_count
    s2n_config_set_psk_mode <- mkMethod2 "s2n_config_set_psk_mode" Optional c_wrap_config_set_psk_mode
    s2n_config_set_psk_selection_callback <- mkMethod3 "s2n_config_set_psk_selection_callback" Optional c_wrap_config_set_psk_selection_callback
    s2n_config_set_async_pkey_callback <- mkMethod2 "s2n_config_set_async_pkey_callback" Optional c_wrap_config_set_async_pkey_callback
    s2n_config_set_async_pkey_validation_mode <- mkMethod2 "s2n_config_set_async_pkey_validation_mode" Optional c_wrap_config_set_async_pkey_validation_mode
    s2n_config_set_session_ticket_cb <- mkMethod3 "s2n_config_set_session_ticket_cb" Optional c_wrap_config_set_session_ticket_cb
    s2n_config_set_key_log_cb <- mkMethod3 "s2n_config_set_key_log_cb" Optional c_wrap_config_set_key_log_cb
    s2n_config_enable_cert_req_dss_legacy_compat <- mkMethod1 "s2n_config_enable_cert_req_dss_legacy_compat" Optional c_wrap_config_enable_cert_req_dss_legacy_compat
    s2n_config_set_server_max_early_data_size <- mkMethod2 "s2n_config_set_server_max_early_data_size" Optional c_wrap_config_set_server_max_early_data_size
    s2n_config_set_early_data_cb <- mkMethod2 "s2n_config_set_early_data_cb" Optional c_wrap_config_set_early_data_cb
    s2n_config_get_supported_groups <- mkMethod4 "s2n_config_get_supported_groups" Optional c_wrap_config_get_supported_groups
    s2n_config_set_serialization_version <- mkMethod2 "s2n_config_set_serialization_version" Optional c_wrap_config_set_serialization_version

    -- Connection Creation & Management
    s2n_connection_new <- mkMethod1 "s2n_connection_new" Optional c_wrap_connection_new
    s2n_connection_set_config <- mkMethod2 "s2n_connection_set_config" Optional c_wrap_connection_set_config
    s2n_connection_set_ctx <- mkMethod2 "s2n_connection_set_ctx" Optional c_wrap_connection_set_ctx
    s2n_connection_get_ctx <- mkMethod1 "s2n_connection_get_ctx" Optional c_wrap_connection_get_ctx
    s2n_client_hello_cb_done <- mkMethod1 "s2n_client_hello_cb_done" Optional c_wrap_client_hello_cb_done
    s2n_connection_server_name_extension_used <- mkMethod1 "s2n_connection_server_name_extension_used" Optional c_wrap_connection_server_name_extension_used

    -- Client Hello Access
    s2n_connection_get_client_hello <- mkMethod1 "s2n_connection_get_client_hello" Optional c_wrap_connection_get_client_hello
    s2n_client_hello_parse_message <- mkMethod2 "s2n_client_hello_parse_message" Optional c_wrap_client_hello_parse_message
    s2n_client_hello_free <- mkMethod1 "s2n_client_hello_free" Optional c_wrap_client_hello_free
    s2n_client_hello_get_raw_message_length <- mkMethod1 "s2n_client_hello_get_raw_message_length" Optional c_wrap_client_hello_get_raw_message_length
    s2n_client_hello_get_raw_message <- mkMethod3 "s2n_client_hello_get_raw_message" Optional c_wrap_client_hello_get_raw_message
    s2n_client_hello_get_cipher_suites_length <- mkMethod1 "s2n_client_hello_get_cipher_suites_length" Optional c_wrap_client_hello_get_cipher_suites_length
    s2n_client_hello_get_cipher_suites <- mkMethod3 "s2n_client_hello_get_cipher_suites" Optional c_wrap_client_hello_get_cipher_suites
    s2n_client_hello_get_extensions_length <- mkMethod1 "s2n_client_hello_get_extensions_length" Optional c_wrap_client_hello_get_extensions_length
    s2n_client_hello_get_extensions <- mkMethod3 "s2n_client_hello_get_extensions" Optional c_wrap_client_hello_get_extensions
    s2n_client_hello_get_extension_length <- mkMethod2 "s2n_client_hello_get_extension_length" Optional c_wrap_client_hello_get_extension_length
    s2n_client_hello_get_extension_by_id <- mkMethod4 "s2n_client_hello_get_extension_by_id" Optional c_wrap_client_hello_get_extension_by_id
    s2n_client_hello_has_extension <- mkMethod3 "s2n_client_hello_has_extension" Optional c_wrap_client_hello_has_extension
    s2n_client_hello_get_session_id_length <- mkMethod2 "s2n_client_hello_get_session_id_length" Optional c_wrap_client_hello_get_session_id_length
    s2n_client_hello_get_session_id <- mkMethod4 "s2n_client_hello_get_session_id" Optional c_wrap_client_hello_get_session_id
    s2n_client_hello_get_compression_methods_length <- mkMethod2 "s2n_client_hello_get_compression_methods_length" Optional c_wrap_client_hello_get_compression_methods_length
    s2n_client_hello_get_compression_methods <- mkMethod4 "s2n_client_hello_get_compression_methods" Optional c_wrap_client_hello_get_compression_methods
    s2n_client_hello_get_legacy_protocol_version <- mkMethod2 "s2n_client_hello_get_legacy_protocol_version" Optional c_wrap_client_hello_get_legacy_protocol_version
    s2n_client_hello_get_supported_groups <- mkMethod4 "s2n_client_hello_get_supported_groups" Optional c_wrap_client_hello_get_supported_groups
    s2n_client_hello_get_server_name_length <- mkMethod2 "s2n_client_hello_get_server_name_length" Optional c_wrap_client_hello_get_server_name_length
    s2n_client_hello_get_server_name <- mkMethod4 "s2n_client_hello_get_server_name" Optional c_wrap_client_hello_get_server_name
    s2n_client_hello_get_legacy_record_version <- mkMethod2 "s2n_client_hello_get_legacy_record_version" Optional c_wrap_client_hello_get_legacy_record_version

    -- File Descriptor & I/O
    s2n_connection_set_fd <- mkMethod2 "s2n_connection_set_fd" Optional c_wrap_connection_set_fd
    s2n_connection_set_read_fd <- mkMethod2 "s2n_connection_set_read_fd" Optional c_wrap_connection_set_read_fd
    s2n_connection_set_write_fd <- mkMethod2 "s2n_connection_set_write_fd" Optional c_wrap_connection_set_write_fd
    s2n_connection_get_read_fd <- mkMethod2 "s2n_connection_get_read_fd" Optional c_wrap_connection_get_read_fd
    s2n_connection_get_write_fd <- mkMethod2 "s2n_connection_get_write_fd" Optional c_wrap_connection_get_write_fd
    s2n_connection_use_corked_io <- mkMethod1 "s2n_connection_use_corked_io" Optional c_wrap_connection_use_corked_io
    s2n_connection_set_recv_ctx <- mkMethod2 "s2n_connection_set_recv_ctx" Optional c_wrap_connection_set_recv_ctx
    s2n_connection_set_send_ctx <- mkMethod2 "s2n_connection_set_send_ctx" Optional c_wrap_connection_set_send_ctx
    s2n_connection_set_recv_cb <- mkMethod2 "s2n_connection_set_recv_cb" Optional c_wrap_connection_set_recv_cb
    s2n_connection_set_send_cb <- mkMethod2 "s2n_connection_set_send_cb" Optional c_wrap_connection_set_send_cb
    -- Connection Preferences
    s2n_connection_prefer_throughput <- mkMethod1 "s2n_connection_prefer_throughput" Optional c_wrap_connection_prefer_throughput
    s2n_connection_prefer_low_latency <- mkMethod1 "s2n_connection_prefer_low_latency" Optional c_wrap_connection_prefer_low_latency
    s2n_connection_set_recv_buffering <- mkMethod2 "s2n_connection_set_recv_buffering" Optional c_wrap_connection_set_recv_buffering
    s2n_peek_buffered <- mkMethod1Direct "s2n_peek_buffered" Optional mk_s2n_peek_buffered
    s2n_connection_set_dynamic_buffers <- mkMethod2 "s2n_connection_set_dynamic_buffers" Optional c_wrap_connection_set_dynamic_buffers
    s2n_connection_set_dynamic_record_threshold <- mkMethod3 "s2n_connection_set_dynamic_record_threshold" Optional c_wrap_connection_set_dynamic_record_threshold

    -- Host Verification
    s2n_connection_set_verify_host_callback <- mkMethod3 "s2n_connection_set_verify_host_callback" Optional c_wrap_connection_set_verify_host_callback
    -- Blinding & Security
    s2n_connection_set_blinding <- mkMethod2 "s2n_connection_set_blinding" Optional c_wrap_connection_set_blinding
    s2n_connection_get_delay <- mkMethod1Direct "s2n_connection_get_delay" Optional mk_s2n_connection_get_delay
    -- Cipher & Protocol Configuration
    s2n_connection_set_cipher_preferences <- mkMethod2 "s2n_connection_set_cipher_preferences" Optional c_wrap_connection_set_cipher_preferences
    s2n_connection_request_key_update <- mkMethod2 "s2n_connection_request_key_update" Optional c_wrap_connection_request_key_update
    s2n_connection_append_protocol_preference <- mkMethod3 "s2n_connection_append_protocol_preference" Optional c_wrap_connection_append_protocol_preference
    s2n_connection_set_protocol_preferences <- mkMethod3 "s2n_connection_set_protocol_preferences" Optional c_wrap_connection_set_protocol_preferences
    -- Server Name (SNI)
    s2n_set_server_name <- mkMethod2 "s2n_set_server_name" Optional c_wrap_set_server_name
    s2n_get_server_name <- mkMethod1 "s2n_get_server_name" Optional c_wrap_get_server_name
    -- Application Protocol (ALPN)
    s2n_get_application_protocol <- mkMethod1 "s2n_get_application_protocol" Optional c_wrap_get_application_protocol
    -- OCSP & Certificate Transparency
    s2n_connection_get_ocsp_response <- mkMethod2 "s2n_connection_get_ocsp_response" Optional c_wrap_connection_get_ocsp_response
    s2n_connection_get_sct_list <- mkMethod2 "s2n_connection_get_sct_list" Optional c_wrap_connection_get_sct_list
    -- Handshake & TLS Operations
    s2n_negotiate <- mkMethod2 "s2n_negotiate" Optional c_wrap_negotiate
    s2n_send <- mkMethod4 "s2n_send" Optional c_wrap_send
    s2n_recv <- mkMethod4 "s2n_recv" Optional c_wrap_recv
    s2n_peek <- mkMethod1Direct "s2n_peek" Optional mk_s2n_peek
    s2n_connection_free_handshake <- mkMethod1 "s2n_connection_free_handshake" Optional c_wrap_connection_free_handshake
    s2n_connection_release_buffers <- mkMethod1 "s2n_connection_release_buffers" Optional c_wrap_connection_release_buffers
    s2n_connection_wipe <- mkMethod1 "s2n_connection_wipe" Optional c_wrap_connection_wipe
    s2n_connection_free <- mkMethod1 "s2n_connection_free" Optional c_wrap_connection_free
    s2n_shutdown <- mkMethod2 "s2n_shutdown" Optional c_wrap_shutdown
    s2n_shutdown_send <- mkMethod2 "s2n_shutdown_send" Optional c_wrap_shutdown_send
    -- Client Authentication
    s2n_connection_get_client_auth_type <- mkMethod2 "s2n_connection_get_client_auth_type" Optional c_wrap_connection_get_client_auth_type
    s2n_connection_set_client_auth_type <- mkMethod2 "s2n_connection_set_client_auth_type" Optional c_wrap_connection_set_client_auth_type
    s2n_connection_get_client_cert_chain <- mkMethod3 "s2n_connection_get_client_cert_chain" Optional c_wrap_connection_get_client_cert_chain
    s2n_connection_client_cert_used <- mkMethod1 "s2n_connection_client_cert_used" Optional c_wrap_connection_client_cert_used
    -- Session Management
    s2n_connection_add_new_tickets_to_send <- mkMethod2 "s2n_connection_add_new_tickets_to_send" Optional c_wrap_connection_add_new_tickets_to_send
    s2n_connection_get_tickets_sent <- mkMethod2 "s2n_connection_get_tickets_sent" Optional c_wrap_connection_get_tickets_sent
    s2n_connection_set_server_keying_material_lifetime <- mkMethod2 "s2n_connection_set_server_keying_material_lifetime" Optional c_wrap_connection_set_server_keying_material_lifetime
    s2n_session_ticket_get_data_len <- mkMethod2 "s2n_session_ticket_get_data_len" Optional c_wrap_session_ticket_get_data_len
    s2n_session_ticket_get_data <- mkMethod3 "s2n_session_ticket_get_data" Optional c_wrap_session_ticket_get_data
    s2n_session_ticket_get_lifetime <- mkMethod2 "s2n_session_ticket_get_lifetime" Optional c_wrap_session_ticket_get_lifetime
    s2n_connection_set_session <- mkMethod3 "s2n_connection_set_session" Optional c_wrap_connection_set_session
    s2n_connection_get_session <- mkMethod3 "s2n_connection_get_session" Optional c_wrap_connection_get_session
    s2n_connection_get_session_ticket_lifetime_hint <- mkMethod1 "s2n_connection_get_session_ticket_lifetime_hint" Optional c_wrap_connection_get_session_ticket_lifetime_hint
    s2n_connection_get_session_length <- mkMethod1 "s2n_connection_get_session_length" Optional c_wrap_connection_get_session_length
    s2n_connection_get_session_id_length <- mkMethod1 "s2n_connection_get_session_id_length" Optional c_wrap_connection_get_session_id_length
    s2n_connection_get_session_id <- mkMethod3 "s2n_connection_get_session_id" Optional c_wrap_connection_get_session_id
    s2n_connection_is_session_resumed <- mkMethod1 "s2n_connection_is_session_resumed" Optional c_wrap_connection_is_session_resumed
    -- Certificate Information
    s2n_connection_is_ocsp_stapled <- mkMethod1 "s2n_connection_is_ocsp_stapled" Optional c_wrap_connection_is_ocsp_stapled
    s2n_connection_get_selected_signature_algorithm <- mkMethod2 "s2n_connection_get_selected_signature_algorithm" Optional c_wrap_connection_get_selected_signature_algorithm
    s2n_connection_get_selected_digest_algorithm <- mkMethod2 "s2n_connection_get_selected_digest_algorithm" Optional c_wrap_connection_get_selected_digest_algorithm
    s2n_connection_get_selected_client_cert_signature_algorithm <- mkMethod2 "s2n_connection_get_selected_client_cert_signature_algorithm" Optional c_wrap_connection_get_selected_client_cert_signature_algorithm
    s2n_connection_get_selected_client_cert_digest_algorithm <- mkMethod2 "s2n_connection_get_selected_client_cert_digest_algorithm" Optional c_wrap_connection_get_selected_client_cert_digest_algorithm
    s2n_connection_get_selected_cert <- mkMethod1 "s2n_connection_get_selected_cert" Optional c_wrap_connection_get_selected_cert
    s2n_cert_chain_get_length <- mkMethod2 "s2n_cert_chain_get_length" Optional c_wrap_cert_chain_get_length
    s2n_cert_chain_get_cert <- mkMethod3 "s2n_cert_chain_get_cert" Optional c_wrap_cert_chain_get_cert
    s2n_cert_get_der <- mkMethod3 "s2n_cert_get_der" Optional c_wrap_cert_get_der
    s2n_connection_get_peer_cert_chain <- mkMethod2 "s2n_connection_get_peer_cert_chain" Optional c_wrap_connection_get_peer_cert_chain
    s2n_cert_get_x509_extension_value_length <- mkMethod3 "s2n_cert_get_x509_extension_value_length" Optional c_wrap_cert_get_x509_extension_value_length
    s2n_cert_get_x509_extension_value <- mkMethod5 "s2n_cert_get_x509_extension_value" Optional c_wrap_cert_get_x509_extension_value
    s2n_cert_get_utf8_string_from_extension_data_length <- mkMethod3 "s2n_cert_get_utf8_string_from_extension_data_length" Optional c_wrap_cert_get_utf8_string_from_extension_data_length
    s2n_cert_get_utf8_string_from_extension_data <- mkMethod4 "s2n_cert_get_utf8_string_from_extension_data" Optional c_wrap_cert_get_utf8_string_from_extension_data
    -- Pre-Shared Keys (PSK)
    s2n_external_psk_new <- mkMethod0 "s2n_external_psk_new" Optional c_wrap_external_psk_new
    s2n_psk_free <- mkMethod1 "s2n_psk_free" Optional c_wrap_psk_free
    s2n_psk_set_identity <- mkMethod3 "s2n_psk_set_identity" Optional c_wrap_psk_set_identity
    s2n_psk_set_secret <- mkMethod3 "s2n_psk_set_secret" Optional c_wrap_psk_set_secret
    s2n_psk_set_hmac <- mkMethod2 "s2n_psk_set_hmac" Optional c_wrap_psk_set_hmac
    s2n_connection_append_psk <- mkMethod2 "s2n_connection_append_psk" Optional c_wrap_connection_append_psk
    s2n_connection_set_psk_mode <- mkMethod2 "s2n_connection_set_psk_mode" Optional c_wrap_connection_set_psk_mode
    s2n_connection_get_negotiated_psk_identity_length <- mkMethod2 "s2n_connection_get_negotiated_psk_identity_length" Optional c_wrap_connection_get_negotiated_psk_identity_length
    s2n_connection_get_negotiated_psk_identity <- mkMethod3 "s2n_connection_get_negotiated_psk_identity" Optional c_wrap_connection_get_negotiated_psk_identity
    s2n_offered_psk_new <- mkMethod0 "s2n_offered_psk_new" Optional c_wrap_offered_psk_new
    s2n_offered_psk_free <- mkMethod1 "s2n_offered_psk_free" Optional c_wrap_offered_psk_free
    s2n_offered_psk_get_identity <- mkMethod3 "s2n_offered_psk_get_identity" Optional c_wrap_offered_psk_get_identity
    s2n_offered_psk_list_has_next <- mkMethod1Direct "s2n_offered_psk_list_has_next" Optional mk_s2n_offered_psk_list_has_next
    s2n_offered_psk_list_next <- mkMethod2 "s2n_offered_psk_list_next" Optional c_wrap_offered_psk_list_next
    s2n_offered_psk_list_reread <- mkMethod1 "s2n_offered_psk_list_reread" Optional c_wrap_offered_psk_list_reread
    s2n_offered_psk_list_choose_psk <- mkMethod2 "s2n_offered_psk_list_choose_psk" Optional c_wrap_offered_psk_list_choose_psk
    s2n_psk_configure_early_data <- mkMethod4 "s2n_psk_configure_early_data" Optional c_wrap_psk_configure_early_data
    s2n_psk_set_application_protocol <- mkMethod3 "s2n_psk_set_application_protocol" Optional c_wrap_psk_set_application_protocol
    s2n_psk_set_early_data_context <- mkMethod3 "s2n_psk_set_early_data_context" Optional c_wrap_psk_set_early_data_context
    -- Connection Statistics
    s2n_connection_get_wire_bytes_in <- mkMethod1Direct "s2n_connection_get_wire_bytes_in" Optional mk_s2n_connection_get_wire_bytes_in
    s2n_connection_get_wire_bytes_out <- mkMethod1Direct "s2n_connection_get_wire_bytes_out" Optional mk_s2n_connection_get_wire_bytes_out
    -- Protocol Version Information
    s2n_connection_get_client_protocol_version <- mkMethod1 "s2n_connection_get_client_protocol_version" Optional c_wrap_connection_get_client_protocol_version
    s2n_connection_get_server_protocol_version <- mkMethod1 "s2n_connection_get_server_protocol_version" Optional c_wrap_connection_get_server_protocol_version
    s2n_connection_get_actual_protocol_version <- mkMethod1 "s2n_connection_get_actual_protocol_version" Optional c_wrap_connection_get_actual_protocol_version
    s2n_connection_get_client_hello_version <- mkMethod1 "s2n_connection_get_client_hello_version" Optional c_wrap_connection_get_client_hello_version
    -- Cipher & Security Information
    s2n_connection_get_cipher <- mkMethod1 "s2n_connection_get_cipher" Optional c_wrap_connection_get_cipher
    s2n_connection_get_certificate_match <- mkMethod2 "s2n_connection_get_certificate_match" Optional c_wrap_connection_get_certificate_match
    s2n_connection_get_master_secret <- mkMethod3 "s2n_connection_get_master_secret" Optional c_wrap_connection_get_master_secret
    s2n_connection_tls_exporter <- mkMethod7 "s2n_connection_tls_exporter" Optional c_wrap_connection_tls_exporter
    s2n_connection_get_cipher_iana_value <- mkMethod3 "s2n_connection_get_cipher_iana_value" Optional c_wrap_connection_get_cipher_iana_value
    s2n_connection_is_valid_for_cipher_preferences <- mkMethod2 "s2n_connection_is_valid_for_cipher_preferences" Optional c_wrap_connection_is_valid_for_cipher_preferences
    s2n_connection_get_curve <- mkMethod1 "s2n_connection_get_curve" Optional c_wrap_connection_get_curve
    s2n_connection_get_kem_name <- mkMethod1 "s2n_connection_get_kem_name" Optional c_wrap_connection_get_kem_name
    s2n_connection_get_kem_group_name <- mkMethod1 "s2n_connection_get_kem_group_name" Optional c_wrap_connection_get_kem_group_name
    s2n_connection_get_key_exchange_group <- mkMethod2 "s2n_connection_get_key_exchange_group" Optional c_wrap_connection_get_key_exchange_group
    s2n_connection_get_alert <- mkMethod1 "s2n_connection_get_alert" Optional c_wrap_connection_get_alert
    s2n_connection_get_handshake_type_name <- mkMethod1 "s2n_connection_get_handshake_type_name" Optional c_wrap_connection_get_handshake_type_name
    s2n_connection_get_last_message_name <- mkMethod1 "s2n_connection_get_last_message_name" Optional c_wrap_connection_get_last_message_name
    -- Async Private Key Operations
    s2n_async_pkey_op_perform <- mkMethod2 "s2n_async_pkey_op_perform" Optional c_wrap_async_pkey_op_perform
    s2n_async_pkey_op_apply <- mkMethod2 "s2n_async_pkey_op_apply" Optional c_wrap_async_pkey_op_apply
    s2n_async_pkey_op_free <- mkMethod1 "s2n_async_pkey_op_free" Optional c_wrap_async_pkey_op_free
    s2n_async_pkey_op_get_op_type <- mkMethod2 "s2n_async_pkey_op_get_op_type" Optional c_wrap_async_pkey_op_get_op_type
    s2n_async_pkey_op_get_input_size <- mkMethod2 "s2n_async_pkey_op_get_input_size" Optional c_wrap_async_pkey_op_get_input_size
    s2n_async_pkey_op_get_input <- mkMethod3 "s2n_async_pkey_op_get_input" Optional c_wrap_async_pkey_op_get_input
    s2n_async_pkey_op_set_output <- mkMethod3 "s2n_async_pkey_op_set_output" Optional c_wrap_async_pkey_op_set_output
    -- Early Data
    s2n_connection_set_server_max_early_data_size <- mkMethod2 "s2n_connection_set_server_max_early_data_size" Optional c_wrap_connection_set_server_max_early_data_size
    s2n_connection_set_server_early_data_context <- mkMethod3 "s2n_connection_set_server_early_data_context" Optional c_wrap_connection_set_server_early_data_context
    s2n_connection_get_early_data_status <- mkMethod2 "s2n_connection_get_early_data_status" Optional c_wrap_connection_get_early_data_status
    s2n_connection_get_remaining_early_data_size <- mkMethod2 "s2n_connection_get_remaining_early_data_size" Optional c_wrap_connection_get_remaining_early_data_size
    s2n_connection_get_max_early_data_size <- mkMethod2 "s2n_connection_get_max_early_data_size" Optional c_wrap_connection_get_max_early_data_size
    s2n_send_early_data <- mkMethod5 "s2n_send_early_data" Optional c_wrap_send_early_data
    s2n_recv_early_data <- mkMethod5 "s2n_recv_early_data" Optional c_wrap_recv_early_data
    s2n_offered_early_data_get_context_length <- mkMethod2 "s2n_offered_early_data_get_context_length" Optional c_wrap_offered_early_data_get_context_length
    s2n_offered_early_data_get_context <- mkMethod3 "s2n_offered_early_data_get_context" Optional c_wrap_offered_early_data_get_context
    s2n_offered_early_data_reject <- mkMethod1 "s2n_offered_early_data_reject" Optional c_wrap_offered_early_data_reject
    s2n_offered_early_data_accept <- mkMethod1 "s2n_offered_early_data_accept" Optional c_wrap_offered_early_data_accept
    -- Connection Serialization
    s2n_connection_serialization_length <- mkMethod2 "s2n_connection_serialization_length" Optional c_wrap_connection_serialization_length
    s2n_connection_serialize <- mkMethod3 "s2n_connection_serialize" Optional c_wrap_connection_serialize
    s2n_connection_deserialize <- mkMethod3 "s2n_connection_deserialize" Optional c_wrap_connection_deserialize

    missingSymbols <- readIORef missingRef
    pure (S2nTlsFfi{..}, missingSymbols)

-- Foreign imports for C wrappers and direct function pointers
-- These are defined in cbits/s2n_wrapper.c

foreign import ccall "dynamic" mk_s2n_errno_location :: FunPtr (IO (Ptr CInt)) -> IO (Ptr CInt)
foreign import ccall "dynamic" mk_s2n_strerror :: FunPtr (CInt -> CString -> IO CString) -> CInt -> CString -> IO CString
foreign import ccall "dynamic" mk_s2n_strerror_debug :: FunPtr (CInt -> CString -> IO CString) -> CInt -> CString -> IO CString
foreign import ccall "dynamic" mk_s2n_strerror_source :: FunPtr (CInt -> IO CString) -> CInt -> IO CString
foreign import ccall "dynamic" mk_s2n_strerror_name :: FunPtr (CInt -> IO CString) -> CInt -> IO CString
foreign import ccall "dynamic" mk_s2n_error_get_type :: FunPtr (CInt -> IO S2nErrorType) -> CInt -> IO S2nErrorType
foreign import ccall "dynamic" mk_s2n_get_openssl_version :: FunPtr (IO CLong) -> IO CLong
foreign import ccall "dynamic" mk_s2n_stack_traces_enabled :: FunPtr (IO CBool) -> IO CBool
foreign import ccall "dynamic" mk_s2n_peek :: FunPtr (Ptr S2nConnection -> IO Word32) -> Ptr S2nConnection -> IO Word32
foreign import ccall "dynamic" mk_s2n_peek_buffered :: FunPtr (Ptr S2nConnection -> IO Word32) -> Ptr S2nConnection -> IO Word32
foreign import ccall "dynamic" mk_s2n_connection_get_delay :: FunPtr (Ptr S2nConnection -> IO Word64) -> Ptr S2nConnection -> IO Word64
foreign import ccall "dynamic" mk_s2n_connection_get_wire_bytes_in :: FunPtr (Ptr S2nConnection -> IO Word64) -> Ptr S2nConnection -> IO Word64
foreign import ccall "dynamic" mk_s2n_connection_get_wire_bytes_out :: FunPtr (Ptr S2nConnection -> IO Word64) -> Ptr S2nConnection -> IO Word64
foreign import ccall "dynamic" mk_s2n_cert_chain_and_key_get_ctx :: FunPtr (Ptr S2nCertChainAndKey -> IO (Ptr ())) -> Ptr S2nCertChainAndKey -> IO (Ptr ())
foreign import ccall "dynamic" mk_s2n_offered_psk_list_has_next :: FunPtr (Ptr S2nOfferedPskList -> IO CBool) -> Ptr S2nOfferedPskList -> IO CBool

-- C wrapper imports
foreign import ccall safe "s2n_wrap_init" c_wrap_init :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cleanup" c_wrap_cleanup :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cleanup_final" c_wrap_cleanup_final :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_crypto_disable_init" c_wrap_crypto_disable_init :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_disable_atexit" c_wrap_disable_atexit :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_get_fips_mode" c_wrap_get_fips_mode :: FunPtr () -> Ptr S2nFipsMode -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_stack_traces_enabled_set" c_wrap_stack_traces_enabled_set :: FunPtr () -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_calculate_stacktrace" c_wrap_calculate_stacktrace :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_free_stacktrace" c_wrap_free_stacktrace :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_get_stacktrace" c_wrap_get_stacktrace :: FunPtr () -> Ptr S2nStacktrace -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_new" c_wrap_config_new :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nConfig)
foreign import ccall safe "s2n_wrap_config_new_minimal" c_wrap_config_new_minimal :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nConfig)
foreign import ccall safe "s2n_wrap_config_free" c_wrap_config_free :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_free_dhparams" c_wrap_config_free_dhparams :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_free_cert_chain_and_key" c_wrap_config_free_cert_chain_and_key :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_wall_clock" c_wrap_config_set_wall_clock :: FunPtr () -> Ptr S2nConfig -> S2nClockTimeNanoseconds -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_monotonic_clock" c_wrap_config_set_monotonic_clock :: FunPtr () -> Ptr S2nConfig -> S2nClockTimeNanoseconds -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_cache_store_callback" c_wrap_config_set_cache_store_callback :: FunPtr () -> Ptr S2nConfig -> S2nCacheStoreCallback -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_cache_retrieve_callback" c_wrap_config_set_cache_retrieve_callback :: FunPtr () -> Ptr S2nConfig -> S2nCacheRetrieveCallback -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_cache_delete_callback" c_wrap_config_set_cache_delete_callback :: FunPtr () -> Ptr S2nConfig -> S2nCacheDeleteCallback -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_mem_set_callbacks" c_wrap_mem_set_callbacks :: FunPtr () -> S2nMemInitCallback -> S2nMemCleanupCallback -> S2nMemMallocCallback -> S2nMemFreeCallback -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_rand_set_callbacks" c_wrap_rand_set_callbacks :: FunPtr () -> S2nRandInitCallback -> S2nRandCleanupCallback -> S2nRandSeedCallback -> S2nRandMixCallback -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_chain_and_key_new" c_wrap_cert_chain_and_key_new :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nCertChainAndKey)
foreign import ccall safe "s2n_wrap_cert_chain_and_key_load_pem" c_wrap_cert_chain_and_key_load_pem :: FunPtr () -> Ptr S2nCertChainAndKey -> CString -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_chain_and_key_load_pem_bytes" c_wrap_cert_chain_and_key_load_pem_bytes :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_chain_and_key_load_public_pem_bytes" c_wrap_cert_chain_and_key_load_public_pem_bytes :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_chain_and_key_free" c_wrap_cert_chain_and_key_free :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_chain_and_key_set_ctx" c_wrap_cert_chain_and_key_set_ctx :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_chain_and_key_get_private_key" c_wrap_cert_chain_and_key_get_private_key :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nCertPrivateKey)
foreign import ccall safe "s2n_wrap_cert_chain_and_key_set_ocsp_data" c_wrap_cert_chain_and_key_set_ocsp_data :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_chain_and_key_set_sct_list" c_wrap_cert_chain_and_key_set_sct_list :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_cert_tiebreak_callback" c_wrap_config_set_cert_tiebreak_callback :: FunPtr () -> Ptr S2nConfig -> S2nCertTiebreakCallback -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_add_cert_chain_and_key" c_wrap_config_add_cert_chain_and_key :: FunPtr () -> Ptr S2nConfig -> CString -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_add_cert_chain_and_key_to_store" c_wrap_config_add_cert_chain_and_key_to_store :: FunPtr () -> Ptr S2nConfig -> Ptr S2nCertChainAndKey -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_cert_chain_and_key_defaults" c_wrap_config_set_cert_chain_and_key_defaults :: FunPtr () -> Ptr S2nConfig -> Ptr (Ptr S2nCertChainAndKey) -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_verification_ca_location" c_wrap_config_set_verification_ca_location :: FunPtr () -> Ptr S2nConfig -> CString -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_add_pem_to_trust_store" c_wrap_config_add_pem_to_trust_store :: FunPtr () -> Ptr S2nConfig -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_wipe_trust_store" c_wrap_config_wipe_trust_store :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_load_system_certs" c_wrap_config_load_system_certs :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_cert_authorities_from_trust_store" c_wrap_config_set_cert_authorities_from_trust_store :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_verify_after_sign" c_wrap_config_set_verify_after_sign :: FunPtr () -> Ptr S2nConfig -> S2nVerifyAfterSign -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_check_stapled_ocsp_response" c_wrap_config_set_check_stapled_ocsp_response :: FunPtr () -> Ptr S2nConfig -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_disable_x509_time_verification" c_wrap_config_disable_x509_time_verification :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_disable_x509_verification" c_wrap_config_disable_x509_verification :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_max_cert_chain_depth" c_wrap_config_set_max_cert_chain_depth :: FunPtr () -> Ptr S2nConfig -> Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_verify_host_callback" c_wrap_config_set_verify_host_callback :: FunPtr () -> Ptr S2nConfig -> S2nVerifyHostFn -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_add_dhparams" c_wrap_config_add_dhparams :: FunPtr () -> Ptr S2nConfig -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_cipher_preferences" c_wrap_config_set_cipher_preferences :: FunPtr () -> Ptr S2nConfig -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_append_protocol_preference" c_wrap_config_append_protocol_preference :: FunPtr () -> Ptr S2nConfig -> Ptr Word8 -> Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_protocol_preferences" c_wrap_config_set_protocol_preferences :: FunPtr () -> Ptr S2nConfig -> Ptr CString -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_status_request_type" c_wrap_config_set_status_request_type :: FunPtr () -> Ptr S2nConfig -> S2nStatusRequestType -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_ct_support_level" c_wrap_config_set_ct_support_level :: FunPtr () -> Ptr S2nConfig -> S2nCtSupportLevel -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_alert_behavior" c_wrap_config_set_alert_behavior :: FunPtr () -> Ptr S2nConfig -> S2nAlertBehavior -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_extension_data" c_wrap_config_set_extension_data :: FunPtr () -> Ptr S2nConfig -> S2nTlsExtensionType -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_send_max_fragment_length" c_wrap_config_send_max_fragment_length :: FunPtr () -> Ptr S2nConfig -> S2nMaxFragLen -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_accept_max_fragment_length" c_wrap_config_accept_max_fragment_length :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_session_state_lifetime" c_wrap_config_set_session_state_lifetime :: FunPtr () -> Ptr S2nConfig -> Word64 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_session_tickets_onoff" c_wrap_config_set_session_tickets_onoff :: FunPtr () -> Ptr S2nConfig -> Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_session_cache_onoff" c_wrap_config_set_session_cache_onoff :: FunPtr () -> Ptr S2nConfig -> Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_ticket_encrypt_decrypt_key_lifetime" c_wrap_config_set_ticket_encrypt_decrypt_key_lifetime :: FunPtr () -> Ptr S2nConfig -> Word64 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_ticket_decrypt_key_lifetime" c_wrap_config_set_ticket_decrypt_key_lifetime :: FunPtr () -> Ptr S2nConfig -> Word64 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_add_ticket_crypto_key" c_wrap_config_add_ticket_crypto_key :: FunPtr () -> Ptr S2nConfig -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Word64 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_require_ticket_forward_secrecy" c_wrap_config_require_ticket_forward_secrecy :: FunPtr () -> Ptr S2nConfig -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_send_buffer_size" c_wrap_config_set_send_buffer_size :: FunPtr () -> Ptr S2nConfig -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_recv_multi_record" c_wrap_config_set_recv_multi_record :: FunPtr () -> Ptr S2nConfig -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_ctx" c_wrap_config_set_ctx :: FunPtr () -> Ptr S2nConfig -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_get_ctx" c_wrap_config_get_ctx :: FunPtr () -> Ptr S2nConfig -> Ptr (Ptr ()) -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_client_hello_cb" c_wrap_config_set_client_hello_cb :: FunPtr () -> Ptr S2nConfig -> S2nClientHelloFn -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_client_hello_cb_mode" c_wrap_config_set_client_hello_cb_mode :: FunPtr () -> Ptr S2nConfig -> S2nClientHelloCbMode -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_max_blinding_delay" c_wrap_config_set_max_blinding_delay :: FunPtr () -> Ptr S2nConfig -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_get_client_auth_type" c_wrap_config_get_client_auth_type :: FunPtr () -> Ptr S2nConfig -> Ptr S2nCertAuthType -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_client_auth_type" c_wrap_config_set_client_auth_type :: FunPtr () -> Ptr S2nConfig -> S2nCertAuthType -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_initial_ticket_count" c_wrap_config_set_initial_ticket_count :: FunPtr () -> Ptr S2nConfig -> Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_psk_mode" c_wrap_config_set_psk_mode :: FunPtr () -> Ptr S2nConfig -> S2nPskMode -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_psk_selection_callback" c_wrap_config_set_psk_selection_callback :: FunPtr () -> Ptr S2nConfig -> S2nPskSelectionCallback -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_async_pkey_callback" c_wrap_config_set_async_pkey_callback :: FunPtr () -> Ptr S2nConfig -> S2nAsyncPkeyFn -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_async_pkey_validation_mode" c_wrap_config_set_async_pkey_validation_mode :: FunPtr () -> Ptr S2nConfig -> S2nAsyncPkeyValidationMode -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_session_ticket_cb" c_wrap_config_set_session_ticket_cb :: FunPtr () -> Ptr S2nConfig -> S2nSessionTicketFn -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_key_log_cb" c_wrap_config_set_key_log_cb :: FunPtr () -> Ptr S2nConfig -> S2nKeyLogFn -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_enable_cert_req_dss_legacy_compat" c_wrap_config_enable_cert_req_dss_legacy_compat :: FunPtr () -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_server_max_early_data_size" c_wrap_config_set_server_max_early_data_size :: FunPtr () -> Ptr S2nConfig -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_early_data_cb" c_wrap_config_set_early_data_cb :: FunPtr () -> Ptr S2nConfig -> S2nEarlyDataCb -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_get_supported_groups" c_wrap_config_get_supported_groups :: FunPtr () -> Ptr S2nConfig -> Ptr Word16 -> Word16 -> Ptr Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_config_set_serialization_version" c_wrap_config_set_serialization_version :: FunPtr () -> Ptr S2nConfig -> S2nSerializationVersion -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_new" c_wrap_connection_new :: FunPtr () -> S2nMode -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nConnection)
foreign import ccall safe "s2n_wrap_connection_set_config" c_wrap_connection_set_config :: FunPtr () -> Ptr S2nConnection -> Ptr S2nConfig -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_ctx" c_wrap_connection_set_ctx :: FunPtr () -> Ptr S2nConnection -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_ctx" c_wrap_connection_get_ctx :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr ())
foreign import ccall safe "s2n_wrap_client_hello_cb_done" c_wrap_client_hello_cb_done :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_server_name_extension_used" c_wrap_connection_server_name_extension_used :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_client_hello" c_wrap_connection_get_client_hello :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nClientHello)
foreign import ccall safe "s2n_wrap_client_hello_parse_message" c_wrap_client_hello_parse_message :: FunPtr () -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nClientHello)
foreign import ccall safe "s2n_wrap_client_hello_free" c_wrap_client_hello_free :: FunPtr () -> Ptr (Ptr S2nClientHello) -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_raw_message_length" c_wrap_client_hello_get_raw_message_length :: FunPtr () -> Ptr S2nClientHello -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_client_hello_get_raw_message" c_wrap_client_hello_get_raw_message :: FunPtr () -> Ptr S2nClientHello -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_client_hello_get_cipher_suites_length" c_wrap_client_hello_get_cipher_suites_length :: FunPtr () -> Ptr S2nClientHello -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_client_hello_get_cipher_suites" c_wrap_client_hello_get_cipher_suites :: FunPtr () -> Ptr S2nClientHello -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_client_hello_get_extensions_length" c_wrap_client_hello_get_extensions_length :: FunPtr () -> Ptr S2nClientHello -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_client_hello_get_extensions" c_wrap_client_hello_get_extensions :: FunPtr () -> Ptr S2nClientHello -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_client_hello_get_extension_length" c_wrap_client_hello_get_extension_length :: FunPtr () -> Ptr S2nClientHello -> S2nTlsExtensionType -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_client_hello_get_extension_by_id" c_wrap_client_hello_get_extension_by_id :: FunPtr () -> Ptr S2nClientHello -> S2nTlsExtensionType -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_client_hello_has_extension" c_wrap_client_hello_has_extension :: FunPtr () -> Ptr S2nClientHello -> Word16 -> Ptr CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_session_id_length" c_wrap_client_hello_get_session_id_length :: FunPtr () -> Ptr S2nClientHello -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_session_id" c_wrap_client_hello_get_session_id :: FunPtr () -> Ptr S2nClientHello -> Ptr Word8 -> Ptr Word32 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_compression_methods_length" c_wrap_client_hello_get_compression_methods_length :: FunPtr () -> Ptr S2nClientHello -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_compression_methods" c_wrap_client_hello_get_compression_methods :: FunPtr () -> Ptr S2nClientHello -> Ptr Word8 -> Word32 -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_legacy_protocol_version" c_wrap_client_hello_get_legacy_protocol_version :: FunPtr () -> Ptr S2nClientHello -> Ptr Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_supported_groups" c_wrap_client_hello_get_supported_groups :: FunPtr () -> Ptr S2nClientHello -> Ptr Word16 -> Word16 -> Ptr Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_server_name_length" c_wrap_client_hello_get_server_name_length :: FunPtr () -> Ptr S2nClientHello -> Ptr Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_server_name" c_wrap_client_hello_get_server_name :: FunPtr () -> Ptr S2nClientHello -> Ptr Word8 -> Word16 -> Ptr Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_client_hello_get_legacy_record_version" c_wrap_client_hello_get_legacy_record_version :: FunPtr () -> Ptr S2nClientHello -> Ptr Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_fd" c_wrap_connection_set_fd :: FunPtr () -> Ptr S2nConnection -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_read_fd" c_wrap_connection_set_read_fd :: FunPtr () -> Ptr S2nConnection -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_write_fd" c_wrap_connection_set_write_fd :: FunPtr () -> Ptr S2nConnection -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_read_fd" c_wrap_connection_get_read_fd :: FunPtr () -> Ptr S2nConnection -> Ptr CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_write_fd" c_wrap_connection_get_write_fd :: FunPtr () -> Ptr S2nConnection -> Ptr CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_use_corked_io" c_wrap_connection_use_corked_io :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_recv_ctx" c_wrap_connection_set_recv_ctx :: FunPtr () -> Ptr S2nConnection -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_send_ctx" c_wrap_connection_set_send_ctx :: FunPtr () -> Ptr S2nConnection -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_recv_cb" c_wrap_connection_set_recv_cb :: FunPtr () -> Ptr S2nConnection -> S2nRecvFn -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_send_cb" c_wrap_connection_set_send_cb :: FunPtr () -> Ptr S2nConnection -> S2nSendFn -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_prefer_throughput" c_wrap_connection_prefer_throughput :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_prefer_low_latency" c_wrap_connection_prefer_low_latency :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_recv_buffering" c_wrap_connection_set_recv_buffering :: FunPtr () -> Ptr S2nConnection -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_dynamic_buffers" c_wrap_connection_set_dynamic_buffers :: FunPtr () -> Ptr S2nConnection -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_dynamic_record_threshold" c_wrap_connection_set_dynamic_record_threshold :: FunPtr () -> Ptr S2nConnection -> Word32 -> Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_verify_host_callback" c_wrap_connection_set_verify_host_callback :: FunPtr () -> Ptr S2nConnection -> S2nVerifyHostFn -> Ptr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_blinding" c_wrap_connection_set_blinding :: FunPtr () -> Ptr S2nConnection -> S2nBlinding -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_cipher_preferences" c_wrap_connection_set_cipher_preferences :: FunPtr () -> Ptr S2nConnection -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_request_key_update" c_wrap_connection_request_key_update :: FunPtr () -> Ptr S2nConnection -> S2nPeerKeyUpdate -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_append_protocol_preference" c_wrap_connection_append_protocol_preference :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_protocol_preferences" c_wrap_connection_set_protocol_preferences :: FunPtr () -> Ptr S2nConnection -> Ptr CString -> CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_set_server_name" c_wrap_set_server_name :: FunPtr () -> Ptr S2nConnection -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_get_server_name" c_wrap_get_server_name :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CString
foreign import ccall safe "s2n_wrap_get_application_protocol" c_wrap_get_application_protocol :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CString
foreign import ccall safe "s2n_wrap_connection_get_ocsp_response" c_wrap_connection_get_ocsp_response :: FunPtr () -> Ptr S2nConnection -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr Word8)
foreign import ccall safe "s2n_wrap_connection_get_sct_list" c_wrap_connection_get_sct_list :: FunPtr () -> Ptr S2nConnection -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr Word8)
foreign import ccall safe "s2n_wrap_negotiate" c_wrap_negotiate :: FunPtr () -> Ptr S2nConnection -> Ptr S2nBlockedStatus -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_send" c_wrap_send :: FunPtr () -> Ptr S2nConnection -> Ptr () -> CSsize -> Ptr S2nBlockedStatus -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_recv" c_wrap_recv :: FunPtr () -> Ptr S2nConnection -> Ptr () -> CSsize -> Ptr S2nBlockedStatus -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CSsize
foreign import ccall safe "s2n_wrap_connection_free_handshake" c_wrap_connection_free_handshake :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_release_buffers" c_wrap_connection_release_buffers :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_wipe" c_wrap_connection_wipe :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_free" c_wrap_connection_free :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_shutdown" c_wrap_shutdown :: FunPtr () -> Ptr S2nConnection -> Ptr S2nBlockedStatus -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_shutdown_send" c_wrap_shutdown_send :: FunPtr () -> Ptr S2nConnection -> Ptr S2nBlockedStatus -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_client_auth_type" c_wrap_connection_get_client_auth_type :: FunPtr () -> Ptr S2nConnection -> Ptr S2nCertAuthType -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_client_auth_type" c_wrap_connection_set_client_auth_type :: FunPtr () -> Ptr S2nConnection -> S2nCertAuthType -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_client_cert_chain" c_wrap_connection_get_client_cert_chain :: FunPtr () -> Ptr S2nConnection -> Ptr (Ptr Word8) -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_client_cert_used" c_wrap_connection_client_cert_used :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_add_new_tickets_to_send" c_wrap_connection_add_new_tickets_to_send :: FunPtr () -> Ptr S2nConnection -> Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_tickets_sent" c_wrap_connection_get_tickets_sent :: FunPtr () -> Ptr S2nConnection -> Ptr Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_server_keying_material_lifetime" c_wrap_connection_set_server_keying_material_lifetime :: FunPtr () -> Ptr S2nConnection -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_session_ticket_get_data_len" c_wrap_session_ticket_get_data_len :: FunPtr () -> Ptr S2nSessionTicket -> Ptr CSize -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_session_ticket_get_data" c_wrap_session_ticket_get_data :: FunPtr () -> Ptr S2nSessionTicket -> CSize -> Ptr Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_session_ticket_get_lifetime" c_wrap_session_ticket_get_lifetime :: FunPtr () -> Ptr S2nSessionTicket -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_session" c_wrap_connection_set_session :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> CSize -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_session" c_wrap_connection_get_session :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> CSize -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_session_ticket_lifetime_hint" c_wrap_connection_get_session_ticket_lifetime_hint :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_session_length" c_wrap_connection_get_session_length :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_session_id_length" c_wrap_connection_get_session_id_length :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_session_id" c_wrap_connection_get_session_id :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> CSize -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_is_session_resumed" c_wrap_connection_is_session_resumed :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_is_ocsp_stapled" c_wrap_connection_is_ocsp_stapled :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_selected_signature_algorithm" c_wrap_connection_get_selected_signature_algorithm :: FunPtr () -> Ptr S2nConnection -> Ptr S2nTlsSignatureAlgorithm -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_selected_digest_algorithm" c_wrap_connection_get_selected_digest_algorithm :: FunPtr () -> Ptr S2nConnection -> Ptr S2nTlsHashAlgorithm -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_selected_client_cert_signature_algorithm" c_wrap_connection_get_selected_client_cert_signature_algorithm :: FunPtr () -> Ptr S2nConnection -> Ptr S2nTlsSignatureAlgorithm -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_selected_client_cert_digest_algorithm" c_wrap_connection_get_selected_client_cert_digest_algorithm :: FunPtr () -> Ptr S2nConnection -> Ptr S2nTlsHashAlgorithm -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_selected_cert" c_wrap_connection_get_selected_cert :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nCertChainAndKey)
foreign import ccall safe "s2n_wrap_cert_chain_get_length" c_wrap_cert_chain_get_length :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_chain_get_cert" c_wrap_cert_chain_get_cert :: FunPtr () -> Ptr S2nCertChainAndKey -> Ptr (Ptr S2nCert) -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_get_der" c_wrap_cert_get_der :: FunPtr () -> Ptr S2nCert -> Ptr (Ptr Word8) -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_peer_cert_chain" c_wrap_connection_get_peer_cert_chain :: FunPtr () -> Ptr S2nConnection -> Ptr S2nCertChainAndKey -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_get_x509_extension_value_length" c_wrap_cert_get_x509_extension_value_length :: FunPtr () -> Ptr S2nCert -> Ptr Word8 -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_get_x509_extension_value" c_wrap_cert_get_x509_extension_value :: FunPtr () -> Ptr S2nCert -> Ptr Word8 -> Ptr Word8 -> Ptr Word32 -> Ptr CInt -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_get_utf8_string_from_extension_data_length" c_wrap_cert_get_utf8_string_from_extension_data_length :: FunPtr () -> Ptr Word8 -> Word32 -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_cert_get_utf8_string_from_extension_data" c_wrap_cert_get_utf8_string_from_extension_data :: FunPtr () -> Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_external_psk_new" c_wrap_external_psk_new :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nPsk)
foreign import ccall safe "s2n_wrap_psk_free" c_wrap_psk_free :: FunPtr () -> Ptr (Ptr S2nPsk) -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_psk_set_identity" c_wrap_psk_set_identity :: FunPtr () -> Ptr S2nPsk -> Ptr Word8 -> Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_psk_set_secret" c_wrap_psk_set_secret :: FunPtr () -> Ptr S2nPsk -> Ptr Word8 -> Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_psk_set_hmac" c_wrap_psk_set_hmac :: FunPtr () -> Ptr S2nPsk -> S2nPskHmac -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_append_psk" c_wrap_connection_append_psk :: FunPtr () -> Ptr S2nConnection -> Ptr S2nPsk -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_psk_mode" c_wrap_connection_set_psk_mode :: FunPtr () -> Ptr S2nConnection -> S2nPskMode -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_negotiated_psk_identity_length" c_wrap_connection_get_negotiated_psk_identity_length :: FunPtr () -> Ptr S2nConnection -> Ptr Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_negotiated_psk_identity" c_wrap_connection_get_negotiated_psk_identity :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_psk_new" c_wrap_offered_psk_new :: FunPtr () -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO (Ptr S2nOfferedPsk)
foreign import ccall safe "s2n_wrap_offered_psk_free" c_wrap_offered_psk_free :: FunPtr () -> Ptr (Ptr S2nOfferedPsk) -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_psk_get_identity" c_wrap_offered_psk_get_identity :: FunPtr () -> Ptr S2nOfferedPsk -> Ptr (Ptr Word8) -> Ptr Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_psk_list_next" c_wrap_offered_psk_list_next :: FunPtr () -> Ptr S2nOfferedPskList -> Ptr S2nOfferedPsk -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_psk_list_reread" c_wrap_offered_psk_list_reread :: FunPtr () -> Ptr S2nOfferedPskList -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_psk_list_choose_psk" c_wrap_offered_psk_list_choose_psk :: FunPtr () -> Ptr S2nOfferedPskList -> Ptr S2nOfferedPsk -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_psk_configure_early_data" c_wrap_psk_configure_early_data :: FunPtr () -> Ptr S2nPsk -> Word32 -> Word8 -> Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_psk_set_application_protocol" c_wrap_psk_set_application_protocol :: FunPtr () -> Ptr S2nPsk -> Ptr Word8 -> Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_psk_set_early_data_context" c_wrap_psk_set_early_data_context :: FunPtr () -> Ptr S2nPsk -> Ptr Word8 -> Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_client_protocol_version" c_wrap_connection_get_client_protocol_version :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_server_protocol_version" c_wrap_connection_get_server_protocol_version :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_actual_protocol_version" c_wrap_connection_get_actual_protocol_version :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_client_hello_version" c_wrap_connection_get_client_hello_version :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_cipher" c_wrap_connection_get_cipher :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CString
foreign import ccall safe "s2n_wrap_connection_get_certificate_match" c_wrap_connection_get_certificate_match :: FunPtr () -> Ptr S2nConnection -> Ptr S2nCertSniMatch -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_master_secret" c_wrap_connection_get_master_secret :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> CSize -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_tls_exporter" c_wrap_connection_tls_exporter :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_cipher_iana_value" c_wrap_connection_get_cipher_iana_value :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> Ptr Word8 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_is_valid_for_cipher_preferences" c_wrap_connection_is_valid_for_cipher_preferences :: FunPtr () -> Ptr S2nConnection -> CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_curve" c_wrap_connection_get_curve :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CString
foreign import ccall safe "s2n_wrap_connection_get_kem_name" c_wrap_connection_get_kem_name :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CString
foreign import ccall safe "s2n_wrap_connection_get_kem_group_name" c_wrap_connection_get_kem_group_name :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CString
foreign import ccall safe "s2n_wrap_connection_get_key_exchange_group" c_wrap_connection_get_key_exchange_group :: FunPtr () -> Ptr S2nConnection -> Ptr CString -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_alert" c_wrap_connection_get_alert :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_handshake_type_name" c_wrap_connection_get_handshake_type_name :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CString
foreign import ccall safe "s2n_wrap_connection_get_last_message_name" c_wrap_connection_get_last_message_name :: FunPtr () -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CString
foreign import ccall safe "s2n_wrap_async_pkey_op_perform" c_wrap_async_pkey_op_perform :: FunPtr () -> Ptr S2nAsyncPkeyOp -> Ptr S2nCertPrivateKey -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_async_pkey_op_apply" c_wrap_async_pkey_op_apply :: FunPtr () -> Ptr S2nAsyncPkeyOp -> Ptr S2nConnection -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_async_pkey_op_free" c_wrap_async_pkey_op_free :: FunPtr () -> Ptr S2nAsyncPkeyOp -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_async_pkey_op_get_op_type" c_wrap_async_pkey_op_get_op_type :: FunPtr () -> Ptr S2nAsyncPkeyOp -> Ptr S2nAsyncPkeyOpType -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_async_pkey_op_get_input_size" c_wrap_async_pkey_op_get_input_size :: FunPtr () -> Ptr S2nAsyncPkeyOp -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_async_pkey_op_get_input" c_wrap_async_pkey_op_get_input :: FunPtr () -> Ptr S2nAsyncPkeyOp -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_async_pkey_op_set_output" c_wrap_async_pkey_op_set_output :: FunPtr () -> Ptr S2nAsyncPkeyOp -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_server_max_early_data_size" c_wrap_connection_set_server_max_early_data_size :: FunPtr () -> Ptr S2nConnection -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_set_server_early_data_context" c_wrap_connection_set_server_early_data_context :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_early_data_status" c_wrap_connection_get_early_data_status :: FunPtr () -> Ptr S2nConnection -> Ptr S2nEarlyDataStatus -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_remaining_early_data_size" c_wrap_connection_get_remaining_early_data_size :: FunPtr () -> Ptr S2nConnection -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_get_max_early_data_size" c_wrap_connection_get_max_early_data_size :: FunPtr () -> Ptr S2nConnection -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_send_early_data" c_wrap_send_early_data :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> CSsize -> Ptr CSsize -> Ptr S2nBlockedStatus -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_recv_early_data" c_wrap_recv_early_data :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> CSsize -> Ptr CSsize -> Ptr S2nBlockedStatus -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_early_data_get_context_length" c_wrap_offered_early_data_get_context_length :: FunPtr () -> Ptr S2nOfferedEarlyData -> Ptr Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_early_data_get_context" c_wrap_offered_early_data_get_context :: FunPtr () -> Ptr S2nOfferedEarlyData -> Ptr Word8 -> Word16 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_early_data_reject" c_wrap_offered_early_data_reject :: FunPtr () -> Ptr S2nOfferedEarlyData -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_offered_early_data_accept" c_wrap_offered_early_data_accept :: FunPtr () -> Ptr S2nOfferedEarlyData -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_serialization_length" c_wrap_connection_serialization_length :: FunPtr () -> Ptr S2nConnection -> Ptr Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_serialize" c_wrap_connection_serialize :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
foreign import ccall safe "s2n_wrap_connection_deserialize" c_wrap_connection_deserialize :: FunPtr () -> Ptr S2nConnection -> Ptr Word8 -> Word32 -> Ptr S2nErrorFuncs -> Ptr S2nError -> IO CInt
