{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : S2nTls.Ffi.Types
Description : Core types for s2n-tls FFI bindings
Copyright   : (c) 2026 Daniel Goertzen
License     : Apache-2.0
Maintainer  : daniel.goertzen@gmail.com
Stability   : experimental
Portability : non-portable (requires s2n-tls C library)

This module defines the core types used by the s2n-tls FFI bindings,
including the 'S2nTlsFfi' record that contains all FFI function pointers.
-}
module S2nTls.Ffi.Types (
  -- * Error Types
  S2nError (..),
  S2nErrorFuncs (..),
  MissingSymbol (..),

  -- * Opaque Types
  S2nConfig,
  S2nConnection,
  S2nCertChainAndKey,
  S2nCert,
  S2nClientHello,
  S2nPsk,
  S2nOfferedPsk,
  S2nOfferedPskList,
  S2nSessionTicket,
  S2nAsyncPkeyOp,
  S2nCertPrivateKey,
  S2nOfferedEarlyData,
  S2nStacktrace,

  -- * Return Codes
  pattern S2N_SUCCESS,
  pattern S2N_FAILURE,
  pattern S2N_CALLBACK_BLOCKED,

  -- * TLS Versions
  pattern S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION,
  pattern S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION,
  pattern S2N_SSLv2,
  pattern S2N_SSLv3,
  pattern S2N_TLS10,
  pattern S2N_TLS11,
  pattern S2N_TLS12,
  pattern S2N_TLS13,
  pattern S2N_UNKNOWN_PROTOCOL_VERSION,

  -- * Enumerations
  S2nErrorType (..),
  pattern S2N_ERR_T_OK,
  pattern S2N_ERR_T_IO,
  pattern S2N_ERR_T_CLOSED,
  pattern S2N_ERR_T_BLOCKED,
  pattern S2N_ERR_T_ALERT,
  pattern S2N_ERR_T_PROTO,
  pattern S2N_ERR_T_INTERNAL,
  pattern S2N_ERR_T_USAGE,
  S2nMode (..),
  pattern S2N_SERVER,
  pattern S2N_CLIENT,
  S2nBlinding (..),
  pattern S2N_BUILT_IN_BLINDING,
  pattern S2N_SELF_SERVICE_BLINDING,
  S2nBlockedStatus (..),
  pattern S2N_NOT_BLOCKED,
  pattern S2N_BLOCKED_ON_READ,
  pattern S2N_BLOCKED_ON_WRITE,
  pattern S2N_BLOCKED_ON_APPLICATION_INPUT,
  pattern S2N_BLOCKED_ON_EARLY_DATA,
  S2nCertAuthType (..),
  pattern S2N_CERT_AUTH_NONE,
  pattern S2N_CERT_AUTH_REQUIRED,
  pattern S2N_CERT_AUTH_OPTIONAL,
  S2nPskHmac (..),
  pattern S2N_PSK_HMAC_SHA256,
  pattern S2N_PSK_HMAC_SHA384,
  S2nPskMode (..),
  pattern S2N_PSK_MODE_RESUMPTION,
  pattern S2N_PSK_MODE_EXTERNAL,
  S2nEarlyDataStatus (..),
  pattern S2N_EARLY_DATA_STATUS_OK,
  pattern S2N_EARLY_DATA_STATUS_NOT_REQUESTED,
  pattern S2N_EARLY_DATA_STATUS_REJECTED,
  pattern S2N_EARLY_DATA_STATUS_END,
  S2nAsyncPkeyOpType (..),
  pattern S2N_ASYNC_DECRYPT,
  pattern S2N_ASYNC_SIGN,
  S2nAsyncPkeyValidationMode (..),
  pattern S2N_ASYNC_PKEY_VALIDATION_FAST,
  pattern S2N_ASYNC_PKEY_VALIDATION_STRICT,
  S2nSerializationVersion (..),
  pattern S2N_SERIALIZED_CONN_NONE,
  pattern S2N_SERIALIZED_CONN_V1,
  S2nTlsExtensionType (..),
  pattern S2N_EXTENSION_SERVER_NAME,
  pattern S2N_EXTENSION_MAX_FRAG_LEN,
  pattern S2N_EXTENSION_OCSP_STAPLING,
  pattern S2N_EXTENSION_SUPPORTED_GROUPS,
  pattern S2N_EXTENSION_EC_POINT_FORMATS,
  pattern S2N_EXTENSION_SIGNATURE_ALGORITHMS,
  pattern S2N_EXTENSION_ALPN,
  pattern S2N_EXTENSION_CERTIFICATE_TRANSPARENCY,
  pattern S2N_EXTENSION_RENEGOTIATION_INFO,
  S2nMaxFragLen (..),
  pattern S2N_TLS_MAX_FRAG_LEN_512,
  pattern S2N_TLS_MAX_FRAG_LEN_1024,
  pattern S2N_TLS_MAX_FRAG_LEN_2048,
  pattern S2N_TLS_MAX_FRAG_LEN_4096,
  S2nFipsMode (..),
  pattern S2N_FIPS_MODE_DISABLED,
  pattern S2N_FIPS_MODE_ENABLED,
  S2nStatusRequestType (..),
  pattern S2N_STATUS_REQUEST_NONE,
  pattern S2N_STATUS_REQUEST_OCSP,
  S2nCtSupportLevel (..),
  pattern S2N_CT_SUPPORT_NONE,
  pattern S2N_CT_SUPPORT_REQUEST,
  S2nAlertBehavior (..),
  pattern S2N_ALERT_FAIL_ON_WARNINGS,
  pattern S2N_ALERT_IGNORE_WARNINGS,
  S2nClientHelloCbMode (..),
  pattern S2N_CLIENT_HELLO_CB_BLOCKING,
  pattern S2N_CLIENT_HELLO_CB_NONBLOCKING,
  S2nTlsSignatureAlgorithm (..),
  pattern S2N_TLS_SIGNATURE_ANONYMOUS,
  pattern S2N_TLS_SIGNATURE_RSA,
  pattern S2N_TLS_SIGNATURE_ECDSA,
  pattern S2N_TLS_SIGNATURE_RSA_PSS_RSAE,
  pattern S2N_TLS_SIGNATURE_RSA_PSS_PSS,
  S2nTlsHashAlgorithm (..),
  pattern S2N_TLS_HASH_NONE,
  pattern S2N_TLS_HASH_MD5,
  pattern S2N_TLS_HASH_SHA1,
  pattern S2N_TLS_HASH_SHA224,
  pattern S2N_TLS_HASH_SHA256,
  pattern S2N_TLS_HASH_SHA384,
  pattern S2N_TLS_HASH_SHA512,
  S2nCertSniMatch (..),
  pattern S2N_CERT_SNI_MATCH_NOT_APPLICABLE,
  pattern S2N_CERT_SNI_MATCH,
  pattern S2N_CERT_SNI_NO_MATCH_FOUND,
  S2nPeerKeyUpdate (..),
  pattern S2N_KEY_UPDATE_NOT_REQUESTED,
  pattern S2N_KEY_UPDATE_REQUESTED,
  S2nVerifyAfterSign (..),
  pattern S2N_VERIFY_AFTER_SIGN_DISABLED,
  pattern S2N_VERIFY_AFTER_SIGN_ENABLED,

  -- * Callback Types
  S2nClockTimeNanoseconds,
  S2nRecvFn,
  S2nSendFn,
  S2nCacheStoreCallback,
  S2nCacheRetrieveCallback,
  S2nCacheDeleteCallback,
  S2nMemInitCallback,
  S2nMemCleanupCallback,
  S2nMemMallocCallback,
  S2nMemFreeCallback,
  S2nRandInitCallback,
  S2nRandCleanupCallback,
  S2nRandSeedCallback,
  S2nRandMixCallback,
  S2nClientHelloFn,
  S2nCertTiebreakCallback,
  S2nVerifyHostFn,
  S2nPskSelectionCallback,
  S2nAsyncPkeyFn,
  S2nSessionTicketFn,
  S2nKeyLogFn,
  S2nEarlyDataCb,

  -- * FFI Record
  S2nTlsFfi (..),
) where

import Control.Exception (Exception)
import Data.Word (Word16, Word32, Word64, Word8)
import Foreign.C.String (CString, castCharToCChar, peekCString)
import Foreign.C.Types (CBool (..), CInt (..), CLong (..), CSize (..))
import Foreign.Marshal.Array (pokeArray0)
import Foreign.Ptr (FunPtr, Ptr, plusPtr)
import Foreign.Storable (Storable (..))
import System.Posix.Types (CSsize (..))

--------------------------------------------------------------------------------
-- Error Types
--------------------------------------------------------------------------------

{- | Exception thrown when calling an s2n function that wasn't loaded.
The string contains the name of the missing symbol.
-}
newtype MissingSymbol = MissingSymbol String
  deriving (Show, Eq)

instance Exception MissingSymbol

{- | Full error information captured from an s2n function call.
Contains the error code plus the string representations.
-}
data S2nError = S2nError
  { s2nErrorCode :: !CInt
  , s2nErrorDebugMessage :: String
  -- ^ Result of s2n_strerror_debug()
  }
  deriving (Show, Eq)

instance Exception S2nError

{- | Struct of error function pointers, passed to C wrappers.
Loaded first during initialization - fatal if any are missing.
-}
data S2nErrorFuncs = S2nErrorFuncs
  { errnoLocation :: !(FunPtr (IO (Ptr CInt)))
  , strerrorDebug :: !(FunPtr (CInt -> CString -> IO CString))
  , errorGetType :: !(FunPtr (CInt -> IO S2nErrorType))
  }

instance Storable S2nErrorFuncs where
  sizeOf _ = 3 * sizeOf (undefined :: FunPtr ())
  alignment _ = alignment (undefined :: FunPtr ())
  peek ptr = do
    a <- peekByteOff ptr 0
    b <- peekByteOff ptr (sizeOf (undefined :: FunPtr ()))
    c <- peekByteOff ptr (2 * sizeOf (undefined :: FunPtr ()))
    pure $ S2nErrorFuncs a b c
  poke ptr (S2nErrorFuncs a b c) = do
    pokeByteOff ptr 0 a
    pokeByteOff ptr (sizeOf (undefined :: FunPtr ())) b
    pokeByteOff ptr (2 * sizeOf (undefined :: FunPtr ())) c

-- | Size of the debug string buffer in S2nError (must match C S2N_ERROR_DEBUG_STRING_SIZE)
s2nErrorDebugStringSize :: Int
s2nErrorDebugStringSize = 256

{- | Output struct populated by C wrappers on error.
Contains error code and an owned copy of the debug string.
-}
instance Storable S2nError where
  sizeOf _ = sizeOf (undefined :: CInt) + s2nErrorDebugStringSize
  alignment _ = alignment (undefined :: CInt)
  peek ptr = do
    code <- peekByteOff ptr 0
    -- Read the fixed-size debug string buffer
    let strPtr = ptr `plusPtr` sizeOf (undefined :: CInt)
    dbgStr <- peekCString strPtr
    pure $ S2nError code dbgStr
  poke ptr (S2nError code dbgStr) = do
    pokeByteOff ptr 0 code
    -- Write the debug string to the fixed-size buffer
    let strPtr = ptr `plusPtr` sizeOf (undefined :: CInt)
    -- Zero out the buffer first, then copy the string
    _ <- memset strPtr 0 (fromIntegral s2nErrorDebugStringSize)
    let truncated = take (s2nErrorDebugStringSize - 1) dbgStr
    pokeArray0 0 strPtr (map castCharToCChar truncated)

-- | Foreign import for memset
foreign import ccall unsafe "string.h memset"
  memset :: Ptr a -> CInt -> CSize -> IO (Ptr a)

--------------------------------------------------------------------------------
-- Opaque Types
--------------------------------------------------------------------------------

-- | Opaque type representing an s2n configuration.
data S2nConfig

-- | Opaque type representing an s2n connection.
data S2nConnection

-- | Opaque type representing a certificate chain and private key pair.
data S2nCertChainAndKey

-- | Opaque type representing a certificate.
data S2nCert

-- | Opaque type representing a parsed ClientHello message.
data S2nClientHello

-- | Opaque type representing a pre-shared key.
data S2nPsk

-- | Opaque type representing an offered PSK during negotiation.
data S2nOfferedPsk

-- | Opaque type representing a list of offered PSKs.
data S2nOfferedPskList

-- | Opaque type representing a session ticket.
data S2nSessionTicket

-- | Opaque type representing an async private key operation.
data S2nAsyncPkeyOp

-- | Opaque type representing a certificate's private key.
data S2nCertPrivateKey

-- | Opaque type representing offered early data.
data S2nOfferedEarlyData

-- | Opaque type representing a stack trace.
data S2nStacktrace

--------------------------------------------------------------------------------
-- Return Codes
--------------------------------------------------------------------------------

-- | Function completed successfully.
pattern S2N_SUCCESS :: CInt
pattern S2N_SUCCESS = 0

-- | Function encountered an error.
pattern S2N_FAILURE :: CInt
pattern S2N_FAILURE = -1

-- | Callback was blocked and needs to be retried.
pattern S2N_CALLBACK_BLOCKED :: CInt
pattern S2N_CALLBACK_BLOCKED = -2

--------------------------------------------------------------------------------
-- TLS Versions
--------------------------------------------------------------------------------

-- | Minimum supported TLS record major version.
pattern S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION :: Word8
pattern S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION = 2

-- | Maximum supported TLS record major version.
pattern S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION :: Word8
pattern S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION = 3

-- | SSL version 2 (deprecated, insecure).
pattern S2N_SSLv2 :: CInt
pattern S2N_SSLv2 = 20

-- | SSL version 3 (deprecated, insecure).
pattern S2N_SSLv3 :: CInt
pattern S2N_SSLv3 = 30

-- | TLS version 1.0.
pattern S2N_TLS10 :: CInt
pattern S2N_TLS10 = 31

-- | TLS version 1.1.
pattern S2N_TLS11 :: CInt
pattern S2N_TLS11 = 32

-- | TLS version 1.2.
pattern S2N_TLS12 :: CInt
pattern S2N_TLS12 = 33

-- | TLS version 1.3.
pattern S2N_TLS13 :: CInt
pattern S2N_TLS13 = 34

-- | Unknown or unrecognized protocol version.
pattern S2N_UNKNOWN_PROTOCOL_VERSION :: CInt
pattern S2N_UNKNOWN_PROTOCOL_VERSION = 0

--------------------------------------------------------------------------------
-- Enumerations
--------------------------------------------------------------------------------

-- | Type of error returned by s2n functions.
newtype S2nErrorType = S2nErrorType CInt
  deriving (Eq, Ord, Show, Storable)

-- | No error occurred.
pattern S2N_ERR_T_OK :: S2nErrorType
pattern S2N_ERR_T_OK = S2nErrorType 0

-- | I\/O error (check errno).
pattern S2N_ERR_T_IO :: S2nErrorType
pattern S2N_ERR_T_IO = S2nErrorType 1

-- | Connection was closed.
pattern S2N_ERR_T_CLOSED :: S2nErrorType
pattern S2N_ERR_T_CLOSED = S2nErrorType 2

-- | Operation blocked (retry needed).
pattern S2N_ERR_T_BLOCKED :: S2nErrorType
pattern S2N_ERR_T_BLOCKED = S2nErrorType 3

-- | TLS alert received.
pattern S2N_ERR_T_ALERT :: S2nErrorType
pattern S2N_ERR_T_ALERT = S2nErrorType 4

-- | Protocol error.
pattern S2N_ERR_T_PROTO :: S2nErrorType
pattern S2N_ERR_T_PROTO = S2nErrorType 5

-- | Internal library error.
pattern S2N_ERR_T_INTERNAL :: S2nErrorType
pattern S2N_ERR_T_INTERNAL = S2nErrorType 6

-- | Incorrect API usage.
pattern S2N_ERR_T_USAGE :: S2nErrorType
pattern S2N_ERR_T_USAGE = S2nErrorType 7

-- | TLS connection mode (server or client).
newtype S2nMode = S2nMode CInt
  deriving (Eq, Ord, Show, Storable)

-- | Server mode.
pattern S2N_SERVER :: S2nMode
pattern S2N_SERVER = S2nMode 0

-- | Client mode.
pattern S2N_CLIENT :: S2nMode
pattern S2N_CLIENT = S2nMode 1

-- | Blinding mode for timing attack mitigation.
newtype S2nBlinding = S2nBlinding CInt
  deriving (Eq, Ord, Show, Storable)

-- | s2n handles blinding automatically.
pattern S2N_BUILT_IN_BLINDING :: S2nBlinding
pattern S2N_BUILT_IN_BLINDING = S2nBlinding 0

-- | Application handles blinding delays.
pattern S2N_SELF_SERVICE_BLINDING :: S2nBlinding
pattern S2N_SELF_SERVICE_BLINDING = S2nBlinding 1

-- | Status indicating why an operation was blocked.
newtype S2nBlockedStatus = S2nBlockedStatus CInt
  deriving (Eq, Ord, Show, Storable)

-- | Operation completed successfully.
pattern S2N_NOT_BLOCKED :: S2nBlockedStatus
pattern S2N_NOT_BLOCKED = S2nBlockedStatus 0

-- | Blocked waiting for data to read.
pattern S2N_BLOCKED_ON_READ :: S2nBlockedStatus
pattern S2N_BLOCKED_ON_READ = S2nBlockedStatus 1

-- | Blocked waiting to write data.
pattern S2N_BLOCKED_ON_WRITE :: S2nBlockedStatus
pattern S2N_BLOCKED_ON_WRITE = S2nBlockedStatus 2

-- | Blocked waiting for application input.
pattern S2N_BLOCKED_ON_APPLICATION_INPUT :: S2nBlockedStatus
pattern S2N_BLOCKED_ON_APPLICATION_INPUT = S2nBlockedStatus 3

-- | Blocked on early data processing.
pattern S2N_BLOCKED_ON_EARLY_DATA :: S2nBlockedStatus
pattern S2N_BLOCKED_ON_EARLY_DATA = S2nBlockedStatus 4

-- | Client certificate authentication mode.
newtype S2nCertAuthType = S2nCertAuthType CInt
  deriving (Eq, Ord, Show, Storable)

-- | No client authentication.
pattern S2N_CERT_AUTH_NONE :: S2nCertAuthType
pattern S2N_CERT_AUTH_NONE = S2nCertAuthType 0

-- | Client certificate required.
pattern S2N_CERT_AUTH_REQUIRED :: S2nCertAuthType
pattern S2N_CERT_AUTH_REQUIRED = S2nCertAuthType 1

-- | Client certificate optional.
pattern S2N_CERT_AUTH_OPTIONAL :: S2nCertAuthType
pattern S2N_CERT_AUTH_OPTIONAL = S2nCertAuthType 2

-- | HMAC algorithm for pre-shared keys.
newtype S2nPskHmac = S2nPskHmac CInt
  deriving (Eq, Ord, Show, Storable)

-- | HMAC-SHA256 for PSK.
pattern S2N_PSK_HMAC_SHA256 :: S2nPskHmac
pattern S2N_PSK_HMAC_SHA256 = S2nPskHmac 0

-- | HMAC-SHA384 for PSK.
pattern S2N_PSK_HMAC_SHA384 :: S2nPskHmac
pattern S2N_PSK_HMAC_SHA384 = S2nPskHmac 1

-- | Pre-shared key mode.
newtype S2nPskMode = S2nPskMode CInt
  deriving (Eq, Ord, Show, Storable)

-- | PSK for session resumption.
pattern S2N_PSK_MODE_RESUMPTION :: S2nPskMode
pattern S2N_PSK_MODE_RESUMPTION = S2nPskMode 0

-- | External\/out-of-band PSK.
pattern S2N_PSK_MODE_EXTERNAL :: S2nPskMode
pattern S2N_PSK_MODE_EXTERNAL = S2nPskMode 1

-- | Status of TLS 1.3 early data (0-RTT).
newtype S2nEarlyDataStatus = S2nEarlyDataStatus CInt
  deriving (Eq, Ord, Show, Storable)

-- | Early data accepted.
pattern S2N_EARLY_DATA_STATUS_OK :: S2nEarlyDataStatus
pattern S2N_EARLY_DATA_STATUS_OK = S2nEarlyDataStatus 0

-- | Early data not requested.
pattern S2N_EARLY_DATA_STATUS_NOT_REQUESTED :: S2nEarlyDataStatus
pattern S2N_EARLY_DATA_STATUS_NOT_REQUESTED = S2nEarlyDataStatus 1

-- | Early data rejected.
pattern S2N_EARLY_DATA_STATUS_REJECTED :: S2nEarlyDataStatus
pattern S2N_EARLY_DATA_STATUS_REJECTED = S2nEarlyDataStatus 2

-- | Early data processing complete.
pattern S2N_EARLY_DATA_STATUS_END :: S2nEarlyDataStatus
pattern S2N_EARLY_DATA_STATUS_END = S2nEarlyDataStatus 3

-- | Type of async private key operation.
newtype S2nAsyncPkeyOpType = S2nAsyncPkeyOpType CInt
  deriving (Eq, Ord, Show, Storable)

-- | Decryption operation.
pattern S2N_ASYNC_DECRYPT :: S2nAsyncPkeyOpType
pattern S2N_ASYNC_DECRYPT = S2nAsyncPkeyOpType 0

-- | Signing operation.
pattern S2N_ASYNC_SIGN :: S2nAsyncPkeyOpType
pattern S2N_ASYNC_SIGN = S2nAsyncPkeyOpType 1

-- | Validation mode for async private key operations.
newtype S2nAsyncPkeyValidationMode = S2nAsyncPkeyValidationMode CInt
  deriving (Eq, Ord, Show, Storable)

-- | Fast validation (less strict).
pattern S2N_ASYNC_PKEY_VALIDATION_FAST :: S2nAsyncPkeyValidationMode
pattern S2N_ASYNC_PKEY_VALIDATION_FAST = S2nAsyncPkeyValidationMode 0

-- | Strict validation.
pattern S2N_ASYNC_PKEY_VALIDATION_STRICT :: S2nAsyncPkeyValidationMode
pattern S2N_ASYNC_PKEY_VALIDATION_STRICT = S2nAsyncPkeyValidationMode 1

-- | Connection serialization format version.
newtype S2nSerializationVersion = S2nSerializationVersion CInt
  deriving (Eq, Ord, Show, Storable)

-- | No serialization.
pattern S2N_SERIALIZED_CONN_NONE :: S2nSerializationVersion
pattern S2N_SERIALIZED_CONN_NONE = S2nSerializationVersion 0

-- | Serialization format version 1.
pattern S2N_SERIALIZED_CONN_V1 :: S2nSerializationVersion
pattern S2N_SERIALIZED_CONN_V1 = S2nSerializationVersion 1

-- | TLS extension type identifier.
newtype S2nTlsExtensionType = S2nTlsExtensionType CInt
  deriving (Eq, Ord, Show, Storable)

-- | Server Name Indication (SNI) extension.
pattern S2N_EXTENSION_SERVER_NAME :: S2nTlsExtensionType
pattern S2N_EXTENSION_SERVER_NAME = S2nTlsExtensionType 0

-- | Maximum fragment length extension.
pattern S2N_EXTENSION_MAX_FRAG_LEN :: S2nTlsExtensionType
pattern S2N_EXTENSION_MAX_FRAG_LEN = S2nTlsExtensionType 1

-- | OCSP stapling extension.
pattern S2N_EXTENSION_OCSP_STAPLING :: S2nTlsExtensionType
pattern S2N_EXTENSION_OCSP_STAPLING = S2nTlsExtensionType 5

-- | Supported groups (elliptic curves) extension.
pattern S2N_EXTENSION_SUPPORTED_GROUPS :: S2nTlsExtensionType
pattern S2N_EXTENSION_SUPPORTED_GROUPS = S2nTlsExtensionType 10

-- | EC point formats extension.
pattern S2N_EXTENSION_EC_POINT_FORMATS :: S2nTlsExtensionType
pattern S2N_EXTENSION_EC_POINT_FORMATS = S2nTlsExtensionType 11

-- | Signature algorithms extension.
pattern S2N_EXTENSION_SIGNATURE_ALGORITHMS :: S2nTlsExtensionType
pattern S2N_EXTENSION_SIGNATURE_ALGORITHMS = S2nTlsExtensionType 13

-- | Application-Layer Protocol Negotiation (ALPN) extension.
pattern S2N_EXTENSION_ALPN :: S2nTlsExtensionType
pattern S2N_EXTENSION_ALPN = S2nTlsExtensionType 16

-- | Certificate Transparency extension.
pattern S2N_EXTENSION_CERTIFICATE_TRANSPARENCY :: S2nTlsExtensionType
pattern S2N_EXTENSION_CERTIFICATE_TRANSPARENCY = S2nTlsExtensionType 18

-- | Renegotiation info extension.
pattern S2N_EXTENSION_RENEGOTIATION_INFO :: S2nTlsExtensionType
pattern S2N_EXTENSION_RENEGOTIATION_INFO = S2nTlsExtensionType 65281

-- | Maximum TLS fragment length.
newtype S2nMaxFragLen = S2nMaxFragLen CInt
  deriving (Eq, Ord, Show, Storable)

-- | Maximum fragment length of 512 bytes.
pattern S2N_TLS_MAX_FRAG_LEN_512 :: S2nMaxFragLen
pattern S2N_TLS_MAX_FRAG_LEN_512 = S2nMaxFragLen 1

-- | Maximum fragment length of 1024 bytes.
pattern S2N_TLS_MAX_FRAG_LEN_1024 :: S2nMaxFragLen
pattern S2N_TLS_MAX_FRAG_LEN_1024 = S2nMaxFragLen 2

-- | Maximum fragment length of 2048 bytes.
pattern S2N_TLS_MAX_FRAG_LEN_2048 :: S2nMaxFragLen
pattern S2N_TLS_MAX_FRAG_LEN_2048 = S2nMaxFragLen 3

-- | Maximum fragment length of 4096 bytes.
pattern S2N_TLS_MAX_FRAG_LEN_4096 :: S2nMaxFragLen
pattern S2N_TLS_MAX_FRAG_LEN_4096 = S2nMaxFragLen 4

-- | FIPS mode status.
newtype S2nFipsMode = S2nFipsMode CInt
  deriving (Eq, Ord, Show, Storable)

-- | FIPS mode disabled.
pattern S2N_FIPS_MODE_DISABLED :: S2nFipsMode
pattern S2N_FIPS_MODE_DISABLED = S2nFipsMode 0

-- | FIPS mode enabled.
pattern S2N_FIPS_MODE_ENABLED :: S2nFipsMode
pattern S2N_FIPS_MODE_ENABLED = S2nFipsMode 1

-- | OCSP status request type.
newtype S2nStatusRequestType = S2nStatusRequestType CInt
  deriving (Eq, Ord, Show, Storable)

-- | No status request.
pattern S2N_STATUS_REQUEST_NONE :: S2nStatusRequestType
pattern S2N_STATUS_REQUEST_NONE = S2nStatusRequestType 0

-- | Request OCSP status.
pattern S2N_STATUS_REQUEST_OCSP :: S2nStatusRequestType
pattern S2N_STATUS_REQUEST_OCSP = S2nStatusRequestType 1

-- | Certificate Transparency support level.
newtype S2nCtSupportLevel = S2nCtSupportLevel CInt
  deriving (Eq, Ord, Show, Storable)

-- | No Certificate Transparency support.
pattern S2N_CT_SUPPORT_NONE :: S2nCtSupportLevel
pattern S2N_CT_SUPPORT_NONE = S2nCtSupportLevel 0

-- | Request Certificate Transparency.
pattern S2N_CT_SUPPORT_REQUEST :: S2nCtSupportLevel
pattern S2N_CT_SUPPORT_REQUEST = S2nCtSupportLevel 1

-- | TLS alert behavior on warnings.
newtype S2nAlertBehavior = S2nAlertBehavior CInt
  deriving (Eq, Ord, Show, Storable)

-- | Fail on warning alerts.
pattern S2N_ALERT_FAIL_ON_WARNINGS :: S2nAlertBehavior
pattern S2N_ALERT_FAIL_ON_WARNINGS = S2nAlertBehavior 0

-- | Ignore warning alerts.
pattern S2N_ALERT_IGNORE_WARNINGS :: S2nAlertBehavior
pattern S2N_ALERT_IGNORE_WARNINGS = S2nAlertBehavior 1

-- | Client hello callback mode.
newtype S2nClientHelloCbMode = S2nClientHelloCbMode CInt
  deriving (Eq, Ord, Show, Storable)

-- | Blocking callback mode.
pattern S2N_CLIENT_HELLO_CB_BLOCKING :: S2nClientHelloCbMode
pattern S2N_CLIENT_HELLO_CB_BLOCKING = S2nClientHelloCbMode 0

-- | Non-blocking callback mode.
pattern S2N_CLIENT_HELLO_CB_NONBLOCKING :: S2nClientHelloCbMode
pattern S2N_CLIENT_HELLO_CB_NONBLOCKING = S2nClientHelloCbMode 1

-- | TLS signature algorithm.
newtype S2nTlsSignatureAlgorithm = S2nTlsSignatureAlgorithm CInt
  deriving (Eq, Ord, Show, Storable)

-- | Anonymous (no signature).
pattern S2N_TLS_SIGNATURE_ANONYMOUS :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_ANONYMOUS = S2nTlsSignatureAlgorithm 0

-- | RSA signature.
pattern S2N_TLS_SIGNATURE_RSA :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_RSA = S2nTlsSignatureAlgorithm 1

-- | ECDSA signature.
pattern S2N_TLS_SIGNATURE_ECDSA :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_ECDSA = S2nTlsSignatureAlgorithm 3

-- | RSA-PSS with RSAE key.
pattern S2N_TLS_SIGNATURE_RSA_PSS_RSAE :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_RSA_PSS_RSAE = S2nTlsSignatureAlgorithm 4

-- | RSA-PSS with PSS key.
pattern S2N_TLS_SIGNATURE_RSA_PSS_PSS :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_RSA_PSS_PSS = S2nTlsSignatureAlgorithm 5

-- | TLS hash algorithm.
newtype S2nTlsHashAlgorithm = S2nTlsHashAlgorithm CInt
  deriving (Eq, Ord, Show, Storable)

-- | No hash algorithm.
pattern S2N_TLS_HASH_NONE :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_NONE = S2nTlsHashAlgorithm 0

-- | MD5 hash (deprecated).
pattern S2N_TLS_HASH_MD5 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_MD5 = S2nTlsHashAlgorithm 1

-- | SHA-1 hash (deprecated).
pattern S2N_TLS_HASH_SHA1 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA1 = S2nTlsHashAlgorithm 2

-- | SHA-224 hash.
pattern S2N_TLS_HASH_SHA224 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA224 = S2nTlsHashAlgorithm 3

-- | SHA-256 hash.
pattern S2N_TLS_HASH_SHA256 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA256 = S2nTlsHashAlgorithm 4

-- | SHA-384 hash.
pattern S2N_TLS_HASH_SHA384 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA384 = S2nTlsHashAlgorithm 5

-- | SHA-512 hash.
pattern S2N_TLS_HASH_SHA512 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA512 = S2nTlsHashAlgorithm 6

-- | Certificate SNI match result.
newtype S2nCertSniMatch = S2nCertSniMatch CInt
  deriving (Eq, Ord, Show, Storable)

-- | SNI matching not applicable.
pattern S2N_CERT_SNI_MATCH_NOT_APPLICABLE :: S2nCertSniMatch
pattern S2N_CERT_SNI_MATCH_NOT_APPLICABLE = S2nCertSniMatch 0

-- | Certificate matches SNI.
pattern S2N_CERT_SNI_MATCH :: S2nCertSniMatch
pattern S2N_CERT_SNI_MATCH = S2nCertSniMatch 1

-- | No matching certificate found.
pattern S2N_CERT_SNI_NO_MATCH_FOUND :: S2nCertSniMatch
pattern S2N_CERT_SNI_NO_MATCH_FOUND = S2nCertSniMatch 2

-- | Peer key update request type.
newtype S2nPeerKeyUpdate = S2nPeerKeyUpdate CInt
  deriving (Eq, Ord, Show, Storable)

-- | Key update not requested.
pattern S2N_KEY_UPDATE_NOT_REQUESTED :: S2nPeerKeyUpdate
pattern S2N_KEY_UPDATE_NOT_REQUESTED = S2nPeerKeyUpdate 0

-- | Key update requested.
pattern S2N_KEY_UPDATE_REQUESTED :: S2nPeerKeyUpdate
pattern S2N_KEY_UPDATE_REQUESTED = S2nPeerKeyUpdate 1

-- | Verify-after-sign mode for signatures.
newtype S2nVerifyAfterSign = S2nVerifyAfterSign CInt
  deriving (Eq, Ord, Show, Storable)

-- | Verification after signing disabled.
pattern S2N_VERIFY_AFTER_SIGN_DISABLED :: S2nVerifyAfterSign
pattern S2N_VERIFY_AFTER_SIGN_DISABLED = S2nVerifyAfterSign 0

-- | Verification after signing enabled.
pattern S2N_VERIFY_AFTER_SIGN_ENABLED :: S2nVerifyAfterSign
pattern S2N_VERIFY_AFTER_SIGN_ENABLED = S2nVerifyAfterSign 1

--------------------------------------------------------------------------------
-- Callback Types
--------------------------------------------------------------------------------

-- | Clock callback: returns current time in nanoseconds.
type S2nClockTimeNanoseconds = FunPtr (Ptr () -> Ptr Word64 -> IO CInt)

-- | Receive callback for custom I/O.
type S2nRecvFn = FunPtr (Ptr () -> Ptr Word8 -> Word32 -> IO CInt)

-- | Send callback for custom I/O.
type S2nSendFn = FunPtr (Ptr () -> Ptr Word8 -> Word32 -> IO CInt)

-- | Cache store callback.
type S2nCacheStoreCallback = FunPtr (Ptr S2nConnection -> Ptr () -> Word64 -> Ptr Word8 -> Word64 -> Ptr Word8 -> Word64 -> IO CInt)

-- | Cache retrieve callback.
type S2nCacheRetrieveCallback = FunPtr (Ptr S2nConnection -> Ptr () -> Ptr Word8 -> Word64 -> Ptr Word8 -> Ptr Word64 -> IO CInt)

-- | Cache delete callback.
type S2nCacheDeleteCallback = FunPtr (Ptr S2nConnection -> Ptr () -> Ptr Word8 -> Word64 -> IO CInt)

-- | Memory initialization callback.
type S2nMemInitCallback = FunPtr (IO CInt)

-- | Memory cleanup callback.
type S2nMemCleanupCallback = FunPtr (IO CInt)

-- | Memory allocation callback.
type S2nMemMallocCallback = FunPtr (Ptr (Ptr ()) -> Word32 -> Word32 -> IO CInt)

-- | Memory free callback.
type S2nMemFreeCallback = FunPtr (Ptr () -> Word32 -> IO CInt)

-- | Random initialization callback.
type S2nRandInitCallback = FunPtr (IO CInt)

-- | Random cleanup callback.
type S2nRandCleanupCallback = FunPtr (IO CInt)

-- | Random seed callback.
type S2nRandSeedCallback = FunPtr (Ptr () -> Word32 -> IO CInt)

-- | Random mix callback.
type S2nRandMixCallback = FunPtr (Ptr () -> Word32 -> IO CInt)

-- | Client hello callback.
type S2nClientHelloFn = FunPtr (Ptr S2nConnection -> Ptr () -> IO CInt)

-- | Certificate tiebreak callback.
type S2nCertTiebreakCallback = FunPtr (Ptr S2nCertChainAndKey -> Ptr S2nCertChainAndKey -> Word8 -> Ptr (Ptr S2nCertChainAndKey) -> IO CInt)

-- | Verify host callback.
type S2nVerifyHostFn = FunPtr (CString -> CSize -> Ptr () -> IO Word8)

-- | PSK selection callback.
type S2nPskSelectionCallback = FunPtr (Ptr S2nConnection -> Ptr () -> Ptr S2nOfferedPskList -> IO CInt)

-- | Async private key callback.
type S2nAsyncPkeyFn = FunPtr (Ptr S2nConnection -> Ptr S2nAsyncPkeyOp -> IO CInt)

-- | Session ticket callback.
type S2nSessionTicketFn = FunPtr (Ptr S2nConnection -> Ptr () -> Ptr S2nSessionTicket -> IO CInt)

-- | Key log callback (for debugging).
type S2nKeyLogFn = FunPtr (Ptr () -> Ptr S2nConnection -> Ptr Word8 -> CSize -> IO CInt)

-- | Early data callback.
type S2nEarlyDataCb = FunPtr (Ptr S2nConnection -> Ptr S2nOfferedEarlyData -> IO CInt)

--------------------------------------------------------------------------------
-- S2nTlsFfi Record
--------------------------------------------------------------------------------

{- | A record containing all FFI bindings to the s2n-tls library.

This record is populated by 'S2nTls.Ffi.withS2nTlsFfi' with the 'Library'
parameter specifying either 'Linked' or 'Dynamic' loading.
-}
data S2nTlsFfi = S2nTlsFfi
  { missingSymbols :: [String]
  -- ^ List of symbol names that couldn't be loaded.
  -- Calling functions for these symbols will throw 'MissingSymbol'.
  , s2n_init :: IO (Either S2nError CInt)
  -- ^ __Initialization & Cleanup__
  , s2n_cleanup :: IO (Either S2nError CInt)
  , s2n_cleanup_final :: IO (Either S2nError CInt)
  , s2n_crypto_disable_init :: IO (Either S2nError CInt)
  , s2n_disable_atexit :: IO (Either S2nError CInt)
  , s2n_get_openssl_version :: IO CLong
  , s2n_get_fips_mode :: Ptr S2nFipsMode -> IO (Either S2nError CInt)
  , s2n_errno_location :: IO (Ptr CInt)
  -- ^ __Error Handling__
  , s2n_error_get_type :: CInt -> IO S2nErrorType
  , s2n_strerror :: CInt -> CString -> IO CString
  , s2n_strerror_debug :: CInt -> CString -> IO CString
  , s2n_strerror_name :: CInt -> IO CString
  , s2n_strerror_source :: CInt -> IO CString
  , s2n_stack_traces_enabled :: IO CBool
  -- ^ __Stack Traces__
  , s2n_stack_traces_enabled_set :: CInt -> IO (Either S2nError CInt)
  , s2n_calculate_stacktrace :: IO (Either S2nError CInt)
  , s2n_free_stacktrace :: IO (Either S2nError CInt)
  , s2n_get_stacktrace :: Ptr S2nStacktrace -> IO (Either S2nError CInt)
  , s2n_config_new :: IO (Either S2nError (Ptr S2nConfig))
  -- ^ __Config Management__
  , s2n_config_new_minimal :: IO (Either S2nError (Ptr S2nConfig))
  , s2n_config_free :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_free_dhparams :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_free_cert_chain_and_key :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_set_wall_clock :: Ptr S2nConfig -> S2nClockTimeNanoseconds -> Ptr () -> IO (Either S2nError CInt)
  , s2n_config_set_monotonic_clock :: Ptr S2nConfig -> S2nClockTimeNanoseconds -> Ptr () -> IO (Either S2nError CInt)
  , s2n_config_set_cache_store_callback :: Ptr S2nConfig -> S2nCacheStoreCallback -> Ptr () -> IO (Either S2nError CInt)
  -- ^ __Cache Callbacks__
  , s2n_config_set_cache_retrieve_callback :: Ptr S2nConfig -> S2nCacheRetrieveCallback -> Ptr () -> IO (Either S2nError CInt)
  , s2n_config_set_cache_delete_callback :: Ptr S2nConfig -> S2nCacheDeleteCallback -> Ptr () -> IO (Either S2nError CInt)
  , s2n_mem_set_callbacks :: S2nMemInitCallback -> S2nMemCleanupCallback -> S2nMemMallocCallback -> S2nMemFreeCallback -> IO (Either S2nError CInt)
  -- ^ __Memory & Random Callbacks__
  , s2n_rand_set_callbacks :: S2nRandInitCallback -> S2nRandCleanupCallback -> S2nRandSeedCallback -> S2nRandMixCallback -> IO (Either S2nError CInt)
  , s2n_cert_chain_and_key_new :: IO (Either S2nError (Ptr S2nCertChainAndKey))
  -- ^ __Certificate Chain Management__
  , s2n_cert_chain_and_key_load_pem :: Ptr S2nCertChainAndKey -> CString -> CString -> IO (Either S2nError CInt)
  , s2n_cert_chain_and_key_load_pem_bytes :: Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  , s2n_cert_chain_and_key_load_public_pem_bytes :: Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  , s2n_cert_chain_and_key_free :: Ptr S2nCertChainAndKey -> IO (Either S2nError CInt)
  , s2n_cert_chain_and_key_set_ctx :: Ptr S2nCertChainAndKey -> Ptr () -> IO (Either S2nError CInt)
  , s2n_cert_chain_and_key_get_ctx :: Ptr S2nCertChainAndKey -> IO (Ptr ())
  , s2n_cert_chain_and_key_get_private_key :: Ptr S2nCertChainAndKey -> IO (Either S2nError (Ptr S2nCertPrivateKey))
  , s2n_cert_chain_and_key_set_ocsp_data :: Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  , s2n_cert_chain_and_key_set_sct_list :: Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  , s2n_config_set_cert_tiebreak_callback :: Ptr S2nConfig -> S2nCertTiebreakCallback -> IO (Either S2nError CInt)
  , s2n_config_add_cert_chain_and_key :: Ptr S2nConfig -> CString -> CString -> IO (Either S2nError CInt)
  , s2n_config_add_cert_chain_and_key_to_store :: Ptr S2nConfig -> Ptr S2nCertChainAndKey -> IO (Either S2nError CInt)
  , s2n_config_set_cert_chain_and_key_defaults :: Ptr S2nConfig -> Ptr (Ptr S2nCertChainAndKey) -> Word32 -> IO (Either S2nError CInt)
  , s2n_config_set_verification_ca_location :: Ptr S2nConfig -> CString -> CString -> IO (Either S2nError CInt)
  -- ^ __Trust Store__
  , s2n_config_add_pem_to_trust_store :: Ptr S2nConfig -> CString -> IO (Either S2nError CInt)
  , s2n_config_wipe_trust_store :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_load_system_certs :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_set_cert_authorities_from_trust_store :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_set_verify_after_sign :: Ptr S2nConfig -> S2nVerifyAfterSign -> IO (Either S2nError CInt)
  -- ^ __Verification & Validation__
  , s2n_config_set_check_stapled_ocsp_response :: Ptr S2nConfig -> CInt -> IO (Either S2nError CInt)
  , s2n_config_disable_x509_time_verification :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , -- , s2n_config_disable_x509_intent_verification :: Ptr S2nConfig -> IO (Either S2nError CInt)
    s2n_config_disable_x509_verification :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_set_max_cert_chain_depth :: Ptr S2nConfig -> Word16 -> IO (Either S2nError CInt)
  , s2n_config_set_verify_host_callback :: Ptr S2nConfig -> S2nVerifyHostFn -> Ptr () -> IO (Either S2nError CInt)
  , s2n_config_add_dhparams :: Ptr S2nConfig -> CString -> IO (Either S2nError CInt)
  -- ^ __DH Parameters__
  , s2n_config_set_cipher_preferences :: Ptr S2nConfig -> CString -> IO (Either S2nError CInt)
  -- ^ __Security Policies & Preferences__
  , s2n_config_append_protocol_preference :: Ptr S2nConfig -> Ptr Word8 -> Word8 -> IO (Either S2nError CInt)
  , s2n_config_set_protocol_preferences :: Ptr S2nConfig -> Ptr CString -> CInt -> IO (Either S2nError CInt)
  , s2n_config_set_status_request_type :: Ptr S2nConfig -> S2nStatusRequestType -> IO (Either S2nError CInt)
  , s2n_config_set_ct_support_level :: Ptr S2nConfig -> S2nCtSupportLevel -> IO (Either S2nError CInt)
  , s2n_config_set_alert_behavior :: Ptr S2nConfig -> S2nAlertBehavior -> IO (Either S2nError CInt)
  , s2n_config_set_extension_data :: Ptr S2nConfig -> S2nTlsExtensionType -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  -- ^ __Extension Data__
  , s2n_config_send_max_fragment_length :: Ptr S2nConfig -> S2nMaxFragLen -> IO (Either S2nError CInt)
  , s2n_config_accept_max_fragment_length :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_set_session_state_lifetime :: Ptr S2nConfig -> Word64 -> IO (Either S2nError CInt)
  -- ^ __Session & Ticket Configuration__
  , s2n_config_set_session_tickets_onoff :: Ptr S2nConfig -> Word8 -> IO (Either S2nError CInt)
  , s2n_config_set_session_cache_onoff :: Ptr S2nConfig -> Word8 -> IO (Either S2nError CInt)
  , s2n_config_set_ticket_encrypt_decrypt_key_lifetime :: Ptr S2nConfig -> Word64 -> IO (Either S2nError CInt)
  , s2n_config_set_ticket_decrypt_key_lifetime :: Ptr S2nConfig -> Word64 -> IO (Either S2nError CInt)
  , s2n_config_add_ticket_crypto_key :: Ptr S2nConfig -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Word64 -> IO (Either S2nError CInt)
  , s2n_config_require_ticket_forward_secrecy :: Ptr S2nConfig -> CInt -> IO (Either S2nError CInt)
  , s2n_config_set_send_buffer_size :: Ptr S2nConfig -> Word32 -> IO (Either S2nError CInt)
  -- ^ __Buffer & I\/O Configuration__
  , s2n_config_set_recv_multi_record :: Ptr S2nConfig -> CInt -> IO (Either S2nError CInt)
  , s2n_config_set_ctx :: Ptr S2nConfig -> Ptr () -> IO (Either S2nError CInt)
  -- ^ __Miscellaneous Config__
  , s2n_config_get_ctx :: Ptr S2nConfig -> Ptr (Ptr ()) -> IO (Either S2nError CInt)
  , s2n_config_set_client_hello_cb :: Ptr S2nConfig -> S2nClientHelloFn -> Ptr () -> IO (Either S2nError CInt)
  , s2n_config_set_client_hello_cb_mode :: Ptr S2nConfig -> S2nClientHelloCbMode -> IO (Either S2nError CInt)
  , s2n_config_set_max_blinding_delay :: Ptr S2nConfig -> Word32 -> IO (Either S2nError CInt)
  , s2n_config_get_client_auth_type :: Ptr S2nConfig -> Ptr S2nCertAuthType -> IO (Either S2nError CInt)
  , s2n_config_set_client_auth_type :: Ptr S2nConfig -> S2nCertAuthType -> IO (Either S2nError CInt)
  , s2n_config_set_initial_ticket_count :: Ptr S2nConfig -> Word8 -> IO (Either S2nError CInt)
  , s2n_config_set_psk_mode :: Ptr S2nConfig -> S2nPskMode -> IO (Either S2nError CInt)
  , s2n_config_set_psk_selection_callback :: Ptr S2nConfig -> S2nPskSelectionCallback -> Ptr () -> IO (Either S2nError CInt)
  , s2n_config_set_async_pkey_callback :: Ptr S2nConfig -> S2nAsyncPkeyFn -> IO (Either S2nError CInt)
  , s2n_config_set_async_pkey_validation_mode :: Ptr S2nConfig -> S2nAsyncPkeyValidationMode -> IO (Either S2nError CInt)
  , s2n_config_set_session_ticket_cb :: Ptr S2nConfig -> S2nSessionTicketFn -> Ptr () -> IO (Either S2nError CInt)
  , s2n_config_set_key_log_cb :: Ptr S2nConfig -> S2nKeyLogFn -> Ptr () -> IO (Either S2nError CInt)
  , s2n_config_enable_cert_req_dss_legacy_compat :: Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_config_set_server_max_early_data_size :: Ptr S2nConfig -> Word32 -> IO (Either S2nError CInt)
  , s2n_config_set_early_data_cb :: Ptr S2nConfig -> S2nEarlyDataCb -> IO (Either S2nError CInt)
  , s2n_config_get_supported_groups :: Ptr S2nConfig -> Ptr Word16 -> Word16 -> Ptr Word16 -> IO (Either S2nError CInt)
  , s2n_config_set_serialization_version :: Ptr S2nConfig -> S2nSerializationVersion -> IO (Either S2nError CInt)
  , s2n_connection_new :: S2nMode -> IO (Either S2nError (Ptr S2nConnection))
  -- ^ __Connection Creation & Management__
  , s2n_connection_set_config :: Ptr S2nConnection -> Ptr S2nConfig -> IO (Either S2nError CInt)
  , s2n_connection_set_ctx :: Ptr S2nConnection -> Ptr () -> IO (Either S2nError CInt)
  , s2n_connection_get_ctx :: Ptr S2nConnection -> IO (Either S2nError (Ptr ()))
  , s2n_client_hello_cb_done :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_server_name_extension_used :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_get_client_hello :: Ptr S2nConnection -> IO (Either S2nError (Ptr S2nClientHello))
  -- ^ __Client Hello Access__
  , s2n_client_hello_parse_message :: Ptr Word8 -> Word32 -> IO (Either S2nError (Ptr S2nClientHello))
  , s2n_client_hello_free :: Ptr (Ptr S2nClientHello) -> IO (Either S2nError CInt)
  , s2n_client_hello_get_raw_message_length :: Ptr S2nClientHello -> IO (Either S2nError CSsize)
  , s2n_client_hello_get_raw_message :: Ptr S2nClientHello -> Ptr Word8 -> Word32 -> IO (Either S2nError CSsize)
  , s2n_client_hello_get_cipher_suites_length :: Ptr S2nClientHello -> IO (Either S2nError CSsize)
  , s2n_client_hello_get_cipher_suites :: Ptr S2nClientHello -> Ptr Word8 -> Word32 -> IO (Either S2nError CSsize)
  , s2n_client_hello_get_extensions_length :: Ptr S2nClientHello -> IO (Either S2nError CSsize)
  , s2n_client_hello_get_extensions :: Ptr S2nClientHello -> Ptr Word8 -> Word32 -> IO (Either S2nError CSsize)
  , s2n_client_hello_get_extension_length :: Ptr S2nClientHello -> S2nTlsExtensionType -> IO (Either S2nError CSsize)
  , s2n_client_hello_get_extension_by_id :: Ptr S2nClientHello -> S2nTlsExtensionType -> Ptr Word8 -> Word32 -> IO (Either S2nError CSsize)
  , s2n_client_hello_has_extension :: Ptr S2nClientHello -> Word16 -> Ptr CInt -> IO (Either S2nError CInt)
  , s2n_client_hello_get_session_id_length :: Ptr S2nClientHello -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_client_hello_get_session_id :: Ptr S2nClientHello -> Ptr Word8 -> Ptr Word32 -> Word32 -> IO (Either S2nError CInt)
  , s2n_client_hello_get_compression_methods_length :: Ptr S2nClientHello -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_client_hello_get_compression_methods :: Ptr S2nClientHello -> Ptr Word8 -> Word32 -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_client_hello_get_legacy_protocol_version :: Ptr S2nClientHello -> Ptr Word8 -> IO (Either S2nError CInt)
  , -- , s2n_client_hello_get_random :: Ptr S2nClientHello -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
    s2n_client_hello_get_supported_groups :: Ptr S2nClientHello -> Ptr Word16 -> Word16 -> Ptr Word16 -> IO (Either S2nError CInt)
  , s2n_client_hello_get_server_name_length :: Ptr S2nClientHello -> Ptr Word16 -> IO (Either S2nError CInt)
  , s2n_client_hello_get_server_name :: Ptr S2nClientHello -> Ptr Word8 -> Word16 -> Ptr Word16 -> IO (Either S2nError CInt)
  , s2n_client_hello_get_legacy_record_version :: Ptr S2nClientHello -> Ptr Word8 -> IO (Either S2nError CInt)
  , s2n_connection_set_fd :: Ptr S2nConnection -> CInt -> IO (Either S2nError CInt)
  -- ^ __File Descriptor & I\/O__
  , s2n_connection_set_read_fd :: Ptr S2nConnection -> CInt -> IO (Either S2nError CInt)
  , s2n_connection_set_write_fd :: Ptr S2nConnection -> CInt -> IO (Either S2nError CInt)
  , s2n_connection_get_read_fd :: Ptr S2nConnection -> Ptr CInt -> IO (Either S2nError CInt)
  , s2n_connection_get_write_fd :: Ptr S2nConnection -> Ptr CInt -> IO (Either S2nError CInt)
  , s2n_connection_use_corked_io :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_set_recv_ctx :: Ptr S2nConnection -> Ptr () -> IO (Either S2nError CInt)
  , s2n_connection_set_send_ctx :: Ptr S2nConnection -> Ptr () -> IO (Either S2nError CInt)
  , s2n_connection_set_recv_cb :: Ptr S2nConnection -> S2nRecvFn -> IO (Either S2nError CInt)
  , s2n_connection_set_send_cb :: Ptr S2nConnection -> S2nSendFn -> IO (Either S2nError CInt)
  , s2n_connection_prefer_throughput :: Ptr S2nConnection -> IO (Either S2nError CInt)
  -- ^ __Connection Preferences__
  , s2n_connection_prefer_low_latency :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_set_recv_buffering :: Ptr S2nConnection -> CInt -> IO (Either S2nError CInt)
  , s2n_peek_buffered :: Ptr S2nConnection -> IO Word32
  , s2n_connection_set_dynamic_buffers :: Ptr S2nConnection -> CInt -> IO (Either S2nError CInt)
  , s2n_connection_set_dynamic_record_threshold :: Ptr S2nConnection -> Word32 -> Word16 -> IO (Either S2nError CInt)
  , s2n_connection_set_verify_host_callback :: Ptr S2nConnection -> S2nVerifyHostFn -> Ptr () -> IO (Either S2nError CInt)
  -- ^ __Host Verification__
  , s2n_connection_set_blinding :: Ptr S2nConnection -> S2nBlinding -> IO (Either S2nError CInt)
  -- ^ __Blinding & Security__
  , s2n_connection_get_delay :: Ptr S2nConnection -> IO Word64
  , s2n_connection_set_cipher_preferences :: Ptr S2nConnection -> CString -> IO (Either S2nError CInt)
  -- ^ __Cipher & Protocol Configuration__
  , s2n_connection_request_key_update :: Ptr S2nConnection -> S2nPeerKeyUpdate -> IO (Either S2nError CInt)
  , s2n_connection_append_protocol_preference :: Ptr S2nConnection -> Ptr Word8 -> Word8 -> IO (Either S2nError CInt)
  , s2n_connection_set_protocol_preferences :: Ptr S2nConnection -> Ptr CString -> CInt -> IO (Either S2nError CInt)
  , s2n_set_server_name :: Ptr S2nConnection -> CString -> IO (Either S2nError CInt)
  -- ^ __Server Name (SNI)__
  , s2n_get_server_name :: Ptr S2nConnection -> IO (Either S2nError CString)
  , s2n_get_application_protocol :: Ptr S2nConnection -> IO (Either S2nError CString)
  -- ^ __Application Protocol (ALPN)__
  , s2n_connection_get_ocsp_response :: Ptr S2nConnection -> Ptr Word32 -> IO (Either S2nError (Ptr Word8))
  -- ^ __OCSP & Certificate Transparency__
  , s2n_connection_get_sct_list :: Ptr S2nConnection -> Ptr Word32 -> IO (Either S2nError (Ptr Word8))
  , s2n_negotiate :: Ptr S2nConnection -> Ptr S2nBlockedStatus -> IO (Either S2nError CInt)
  -- ^ __Handshake & TLS Operations__
  , s2n_send :: Ptr S2nConnection -> Ptr () -> CSsize -> Ptr S2nBlockedStatus -> IO (Either S2nError CSsize)
  , s2n_recv :: Ptr S2nConnection -> Ptr () -> CSsize -> Ptr S2nBlockedStatus -> IO (Either S2nError CSsize)
  , s2n_peek :: Ptr S2nConnection -> IO Word32
  , s2n_connection_free_handshake :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_release_buffers :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_wipe :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_free :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_shutdown :: Ptr S2nConnection -> Ptr S2nBlockedStatus -> IO (Either S2nError CInt)
  , s2n_shutdown_send :: Ptr S2nConnection -> Ptr S2nBlockedStatus -> IO (Either S2nError CInt)
  , s2n_connection_get_client_auth_type :: Ptr S2nConnection -> Ptr S2nCertAuthType -> IO (Either S2nError CInt)
  -- ^ __Client Authentication__
  , s2n_connection_set_client_auth_type :: Ptr S2nConnection -> S2nCertAuthType -> IO (Either S2nError CInt)
  , s2n_connection_get_client_cert_chain :: Ptr S2nConnection -> Ptr (Ptr Word8) -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_connection_client_cert_used :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_add_new_tickets_to_send :: Ptr S2nConnection -> Word8 -> IO (Either S2nError CInt)
  -- ^ __Session Management__
  , s2n_connection_get_tickets_sent :: Ptr S2nConnection -> Ptr Word16 -> IO (Either S2nError CInt)
  , s2n_connection_set_server_keying_material_lifetime :: Ptr S2nConnection -> Word32 -> IO (Either S2nError CInt)
  , s2n_session_ticket_get_data_len :: Ptr S2nSessionTicket -> Ptr CSize -> IO (Either S2nError CInt)
  , s2n_session_ticket_get_data :: Ptr S2nSessionTicket -> CSize -> Ptr Word8 -> IO (Either S2nError CInt)
  , s2n_session_ticket_get_lifetime :: Ptr S2nSessionTicket -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_connection_set_session :: Ptr S2nConnection -> Ptr Word8 -> CSize -> IO (Either S2nError CInt)
  , s2n_connection_get_session :: Ptr S2nConnection -> Ptr Word8 -> CSize -> IO (Either S2nError CInt)
  , s2n_connection_get_session_ticket_lifetime_hint :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_get_session_length :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_get_session_id_length :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_get_session_id :: Ptr S2nConnection -> Ptr Word8 -> CSize -> IO (Either S2nError CInt)
  , s2n_connection_is_session_resumed :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_is_ocsp_stapled :: Ptr S2nConnection -> IO (Either S2nError CInt)
  -- ^ __Certificate Information__
  , s2n_connection_get_selected_signature_algorithm :: Ptr S2nConnection -> Ptr S2nTlsSignatureAlgorithm -> IO (Either S2nError CInt)
  , s2n_connection_get_selected_digest_algorithm :: Ptr S2nConnection -> Ptr S2nTlsHashAlgorithm -> IO (Either S2nError CInt)
  , s2n_connection_get_selected_client_cert_signature_algorithm :: Ptr S2nConnection -> Ptr S2nTlsSignatureAlgorithm -> IO (Either S2nError CInt)
  , s2n_connection_get_selected_client_cert_digest_algorithm :: Ptr S2nConnection -> Ptr S2nTlsHashAlgorithm -> IO (Either S2nError CInt)
  , -- , s2n_connection_get_signature_scheme :: Ptr S2nConnection -> Ptr CString -> IO (Either S2nError CInt)
    s2n_connection_get_selected_cert :: Ptr S2nConnection -> IO (Either S2nError (Ptr S2nCertChainAndKey))
  , s2n_cert_chain_get_length :: Ptr S2nCertChainAndKey -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_cert_chain_get_cert :: Ptr S2nCertChainAndKey -> Ptr (Ptr S2nCert) -> Word32 -> IO (Either S2nError CInt)
  , s2n_cert_get_der :: Ptr S2nCert -> Ptr (Ptr Word8) -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_connection_get_peer_cert_chain :: Ptr S2nConnection -> Ptr S2nCertChainAndKey -> IO (Either S2nError CInt)
  , s2n_cert_get_x509_extension_value_length :: Ptr S2nCert -> Ptr Word8 -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_cert_get_x509_extension_value :: Ptr S2nCert -> Ptr Word8 -> Ptr Word8 -> Ptr Word32 -> Ptr CInt -> IO (Either S2nError CInt)
  , s2n_cert_get_utf8_string_from_extension_data_length :: Ptr Word8 -> Word32 -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_cert_get_utf8_string_from_extension_data :: Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_external_psk_new :: IO (Either S2nError (Ptr S2nPsk))
  -- ^ __Pre-Shared Keys (PSK)__
  , s2n_psk_free :: Ptr (Ptr S2nPsk) -> IO (Either S2nError CInt)
  , s2n_psk_set_identity :: Ptr S2nPsk -> Ptr Word8 -> Word16 -> IO (Either S2nError CInt)
  , s2n_psk_set_secret :: Ptr S2nPsk -> Ptr Word8 -> Word16 -> IO (Either S2nError CInt)
  , s2n_psk_set_hmac :: Ptr S2nPsk -> S2nPskHmac -> IO (Either S2nError CInt)
  , s2n_connection_append_psk :: Ptr S2nConnection -> Ptr S2nPsk -> IO (Either S2nError CInt)
  , s2n_connection_set_psk_mode :: Ptr S2nConnection -> S2nPskMode -> IO (Either S2nError CInt)
  , s2n_connection_get_negotiated_psk_identity_length :: Ptr S2nConnection -> Ptr Word16 -> IO (Either S2nError CInt)
  , s2n_connection_get_negotiated_psk_identity :: Ptr S2nConnection -> Ptr Word8 -> Word16 -> IO (Either S2nError CInt)
  , s2n_offered_psk_new :: IO (Either S2nError (Ptr S2nOfferedPsk))
  , s2n_offered_psk_free :: Ptr (Ptr S2nOfferedPsk) -> IO (Either S2nError CInt)
  , s2n_offered_psk_get_identity :: Ptr S2nOfferedPsk -> Ptr (Ptr Word8) -> Ptr Word16 -> IO (Either S2nError CInt)
  , s2n_offered_psk_list_has_next :: Ptr S2nOfferedPskList -> IO CBool
  , s2n_offered_psk_list_next :: Ptr S2nOfferedPskList -> Ptr S2nOfferedPsk -> IO (Either S2nError CInt)
  , s2n_offered_psk_list_reread :: Ptr S2nOfferedPskList -> IO (Either S2nError CInt)
  , s2n_offered_psk_list_choose_psk :: Ptr S2nOfferedPskList -> Ptr S2nOfferedPsk -> IO (Either S2nError CInt)
  , s2n_psk_configure_early_data :: Ptr S2nPsk -> Word32 -> Word8 -> Word8 -> IO (Either S2nError CInt)
  , s2n_psk_set_application_protocol :: Ptr S2nPsk -> Ptr Word8 -> Word8 -> IO (Either S2nError CInt)
  , s2n_psk_set_early_data_context :: Ptr S2nPsk -> Ptr Word8 -> Word16 -> IO (Either S2nError CInt)
  , s2n_connection_get_wire_bytes_in :: Ptr S2nConnection -> IO Word64
  -- ^ __Connection Statistics__
  , s2n_connection_get_wire_bytes_out :: Ptr S2nConnection -> IO Word64
  , s2n_connection_get_client_protocol_version :: Ptr S2nConnection -> IO (Either S2nError CInt)
  -- ^ __Protocol Version Information__
  , s2n_connection_get_server_protocol_version :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_get_actual_protocol_version :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_get_client_hello_version :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_get_cipher :: Ptr S2nConnection -> IO (Either S2nError CString)
  -- ^ __Cipher & Security Information__
  , s2n_connection_get_certificate_match :: Ptr S2nConnection -> Ptr S2nCertSniMatch -> IO (Either S2nError CInt)
  , s2n_connection_get_master_secret :: Ptr S2nConnection -> Ptr Word8 -> CSize -> IO (Either S2nError CInt)
  , s2n_connection_tls_exporter :: Ptr S2nConnection -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  , s2n_connection_get_cipher_iana_value :: Ptr S2nConnection -> Ptr Word8 -> Ptr Word8 -> IO (Either S2nError CInt)
  , s2n_connection_is_valid_for_cipher_preferences :: Ptr S2nConnection -> CString -> IO (Either S2nError CInt)
  , s2n_connection_get_curve :: Ptr S2nConnection -> IO (Either S2nError CString)
  , s2n_connection_get_kem_name :: Ptr S2nConnection -> IO (Either S2nError CString)
  , s2n_connection_get_kem_group_name :: Ptr S2nConnection -> IO (Either S2nError CString)
  , s2n_connection_get_key_exchange_group :: Ptr S2nConnection -> Ptr CString -> IO (Either S2nError CInt)
  , s2n_connection_get_alert :: Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_connection_get_handshake_type_name :: Ptr S2nConnection -> IO (Either S2nError CString)
  , s2n_connection_get_last_message_name :: Ptr S2nConnection -> IO (Either S2nError CString)
  , s2n_async_pkey_op_perform :: Ptr S2nAsyncPkeyOp -> Ptr S2nCertPrivateKey -> IO (Either S2nError CInt)
  -- ^ __Async Private Key Operations__
  , s2n_async_pkey_op_apply :: Ptr S2nAsyncPkeyOp -> Ptr S2nConnection -> IO (Either S2nError CInt)
  , s2n_async_pkey_op_free :: Ptr S2nAsyncPkeyOp -> IO (Either S2nError CInt)
  , s2n_async_pkey_op_get_op_type :: Ptr S2nAsyncPkeyOp -> Ptr S2nAsyncPkeyOpType -> IO (Either S2nError CInt)
  , s2n_async_pkey_op_get_input_size :: Ptr S2nAsyncPkeyOp -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_async_pkey_op_get_input :: Ptr S2nAsyncPkeyOp -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  , s2n_async_pkey_op_set_output :: Ptr S2nAsyncPkeyOp -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  , s2n_connection_set_server_max_early_data_size :: Ptr S2nConnection -> Word32 -> IO (Either S2nError CInt)
  -- ^ __Early Data__
  , s2n_connection_set_server_early_data_context :: Ptr S2nConnection -> Ptr Word8 -> Word16 -> IO (Either S2nError CInt)
  , s2n_connection_get_early_data_status :: Ptr S2nConnection -> Ptr S2nEarlyDataStatus -> IO (Either S2nError CInt)
  , s2n_connection_get_remaining_early_data_size :: Ptr S2nConnection -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_connection_get_max_early_data_size :: Ptr S2nConnection -> Ptr Word32 -> IO (Either S2nError CInt)
  , s2n_send_early_data :: Ptr S2nConnection -> Ptr Word8 -> CSsize -> Ptr CSsize -> Ptr S2nBlockedStatus -> IO (Either S2nError CInt)
  , s2n_recv_early_data :: Ptr S2nConnection -> Ptr Word8 -> CSsize -> Ptr CSsize -> Ptr S2nBlockedStatus -> IO (Either S2nError CInt)
  , s2n_offered_early_data_get_context_length :: Ptr S2nOfferedEarlyData -> Ptr Word16 -> IO (Either S2nError CInt)
  , s2n_offered_early_data_get_context :: Ptr S2nOfferedEarlyData -> Ptr Word8 -> Word16 -> IO (Either S2nError CInt)
  , s2n_offered_early_data_reject :: Ptr S2nOfferedEarlyData -> IO (Either S2nError CInt)
  , s2n_offered_early_data_accept :: Ptr S2nOfferedEarlyData -> IO (Either S2nError CInt)
  , s2n_connection_serialization_length :: Ptr S2nConnection -> Ptr Word32 -> IO (Either S2nError CInt)
  -- ^ __Connection Serialization__
  , s2n_connection_serialize :: Ptr S2nConnection -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  , s2n_connection_deserialize :: Ptr S2nConnection -> Ptr Word8 -> Word32 -> IO (Either S2nError CInt)
  }
