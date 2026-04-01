{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module      : S2nTls.Sys.Types
-- Description : Core types for s2n-tls FFI bindings
-- License     : BSD-3-Clause
--
-- This module defines the core types used by the s2n-tls FFI bindings,
-- including the 'S2nTlsSys' record that contains all FFI function pointers.
module S2nTls.Sys.Types
    ( -- * Opaque Types
      S2nConfig
    , S2nConnection
    , S2nCertChainAndKey
    , S2nCert
    , S2nClientHello
    , S2nPsk
    , S2nOfferedPsk
    , S2nOfferedPskList
    , S2nSessionTicket
    , S2nAsyncPkeyOp
    , S2nCertPrivateKey
    , S2nOfferedEarlyData
    , S2nStacktrace

      -- * Return Codes
    , pattern S2N_SUCCESS
    , pattern S2N_FAILURE
    , pattern S2N_CALLBACK_BLOCKED

      -- * TLS Versions
    , pattern S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION
    , pattern S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION
    , pattern S2N_SSLv2
    , pattern S2N_SSLv3
    , pattern S2N_TLS10
    , pattern S2N_TLS11
    , pattern S2N_TLS12
    , pattern S2N_TLS13
    , pattern S2N_UNKNOWN_PROTOCOL_VERSION

      -- * Enumerations
    , S2nErrorType (..)
    , pattern S2N_ERR_T_OK
    , pattern S2N_ERR_T_IO
    , pattern S2N_ERR_T_CLOSED
    , pattern S2N_ERR_T_BLOCKED
    , pattern S2N_ERR_T_ALERT
    , pattern S2N_ERR_T_PROTO
    , pattern S2N_ERR_T_INTERNAL
    , pattern S2N_ERR_T_USAGE

    , S2nMode (..)
    , pattern S2N_SERVER
    , pattern S2N_CLIENT

    , S2nBlinding (..)
    , pattern S2N_BUILT_IN_BLINDING
    , pattern S2N_SELF_SERVICE_BLINDING

    , S2nBlockedStatus (..)
    , pattern S2N_NOT_BLOCKED
    , pattern S2N_BLOCKED_ON_READ
    , pattern S2N_BLOCKED_ON_WRITE
    , pattern S2N_BLOCKED_ON_APPLICATION_INPUT
    , pattern S2N_BLOCKED_ON_EARLY_DATA

    , S2nCertAuthType (..)
    , pattern S2N_CERT_AUTH_NONE
    , pattern S2N_CERT_AUTH_REQUIRED
    , pattern S2N_CERT_AUTH_OPTIONAL

    , S2nPskHmac (..)
    , pattern S2N_PSK_HMAC_SHA256
    , pattern S2N_PSK_HMAC_SHA384

    , S2nPskMode (..)
    , pattern S2N_PSK_MODE_RESUMPTION
    , pattern S2N_PSK_MODE_EXTERNAL

    , S2nEarlyDataStatus (..)
    , pattern S2N_EARLY_DATA_STATUS_OK
    , pattern S2N_EARLY_DATA_STATUS_NOT_REQUESTED
    , pattern S2N_EARLY_DATA_STATUS_REJECTED
    , pattern S2N_EARLY_DATA_STATUS_END

    , S2nAsyncPkeyOpType (..)
    , pattern S2N_ASYNC_DECRYPT
    , pattern S2N_ASYNC_SIGN

    , S2nAsyncPkeyValidationMode (..)
    , pattern S2N_ASYNC_PKEY_VALIDATION_FAST
    , pattern S2N_ASYNC_PKEY_VALIDATION_STRICT

    , S2nSerializationVersion (..)
    , pattern S2N_SERIALIZED_CONN_NONE
    , pattern S2N_SERIALIZED_CONN_V1

    , S2nTlsExtensionType (..)
    , pattern S2N_EXTENSION_SERVER_NAME
    , pattern S2N_EXTENSION_MAX_FRAG_LEN
    , pattern S2N_EXTENSION_OCSP_STAPLING
    , pattern S2N_EXTENSION_SUPPORTED_GROUPS
    , pattern S2N_EXTENSION_EC_POINT_FORMATS
    , pattern S2N_EXTENSION_SIGNATURE_ALGORITHMS
    , pattern S2N_EXTENSION_ALPN
    , pattern S2N_EXTENSION_CERTIFICATE_TRANSPARENCY
    , pattern S2N_EXTENSION_RENEGOTIATION_INFO

    , S2nMaxFragLen (..)
    , pattern S2N_TLS_MAX_FRAG_LEN_512
    , pattern S2N_TLS_MAX_FRAG_LEN_1024
    , pattern S2N_TLS_MAX_FRAG_LEN_2048
    , pattern S2N_TLS_MAX_FRAG_LEN_4096

    , S2nFipsMode (..)
    , pattern S2N_FIPS_MODE_DISABLED
    , pattern S2N_FIPS_MODE_ENABLED

    , S2nStatusRequestType (..)
    , pattern S2N_STATUS_REQUEST_NONE
    , pattern S2N_STATUS_REQUEST_OCSP

    , S2nCtSupportLevel (..)
    , pattern S2N_CT_SUPPORT_NONE
    , pattern S2N_CT_SUPPORT_REQUEST

    , S2nAlertBehavior (..)
    , pattern S2N_ALERT_FAIL_ON_WARNINGS
    , pattern S2N_ALERT_IGNORE_WARNINGS

    , S2nClientHelloCbMode (..)
    , pattern S2N_CLIENT_HELLO_CB_BLOCKING
    , pattern S2N_CLIENT_HELLO_CB_NONBLOCKING

    , S2nTlsSignatureAlgorithm (..)
    , pattern S2N_TLS_SIGNATURE_ANONYMOUS
    , pattern S2N_TLS_SIGNATURE_RSA
    , pattern S2N_TLS_SIGNATURE_ECDSA
    , pattern S2N_TLS_SIGNATURE_RSA_PSS_RSAE
    , pattern S2N_TLS_SIGNATURE_RSA_PSS_PSS

    , S2nTlsHashAlgorithm (..)
    , pattern S2N_TLS_HASH_NONE
    , pattern S2N_TLS_HASH_MD5
    , pattern S2N_TLS_HASH_SHA1
    , pattern S2N_TLS_HASH_SHA224
    , pattern S2N_TLS_HASH_SHA256
    , pattern S2N_TLS_HASH_SHA384
    , pattern S2N_TLS_HASH_SHA512

    , S2nCertSniMatch (..)
    , pattern S2N_CERT_SNI_MATCH_NOT_APPLICABLE
    , pattern S2N_CERT_SNI_MATCH
    , pattern S2N_CERT_SNI_NO_MATCH_FOUND

    , S2nPeerKeyUpdate (..)
    , pattern S2N_KEY_UPDATE_NOT_REQUESTED
    , pattern S2N_KEY_UPDATE_REQUESTED

    , S2nVerifyAfterSign (..)
    , pattern S2N_VERIFY_AFTER_SIGN_DISABLED
    , pattern S2N_VERIFY_AFTER_SIGN_ENABLED

      -- * Callback Types
    , S2nClockTimeNanoseconds
    , S2nRecvFn
    , S2nSendFn
    , S2nCacheStoreCallback
    , S2nCacheRetrieveCallback
    , S2nCacheDeleteCallback
    , S2nMemInitCallback
    , S2nMemCleanupCallback
    , S2nMemMallocCallback
    , S2nMemFreeCallback
    , S2nRandInitCallback
    , S2nRandCleanupCallback
    , S2nRandSeedCallback
    , S2nRandMixCallback
    , S2nClientHelloFn
    , S2nCertTiebreakCallback
    , S2nVerifyHostFn
    , S2nPskSelectionCallback
    , S2nAsyncPkeyFn
    , S2nSessionTicketFn
    , S2nKeyLogFn
    , S2nEarlyDataCb

      -- * Function Types
      -- ** Initialization & Cleanup
    , S2nInit
    , S2nCleanup
    , S2nCleanupFinal
    , S2nCryptoDisableInit
    , S2nDisableAtexit
    , S2nGetOpensslVersion
    , S2nGetFipsMode

      -- ** Error Handling
    , S2nErrnoLocation
    , S2nErrorGetType
    , S2nStrerror
    , S2nStrerrorDebug
    , S2nStrerrorName
    , S2nStrerrorSource

      -- ** Stack Traces
    , S2nStackTracesEnabled
    , S2nStackTracesEnabledSet
    , S2nCalculateStacktrace
    , S2nFreeStacktrace
    , S2nGetStacktrace

      -- ** Config Management
    , S2nConfigNew
    , S2nConfigNewMinimal
    , S2nConfigFree
    , S2nConfigFreeDhparams
    , S2nConfigFreeCertChainAndKey
    , S2nConfigSetWallClock
    , S2nConfigSetMonotonicClock

      -- ** Cache Callbacks
    , S2nConfigSetCacheStoreCallback
    , S2nConfigSetCacheRetrieveCallback
    , S2nConfigSetCacheDeleteCallback

      -- ** Memory & Random Callbacks
    , S2nMemSetCallbacks
    , S2nRandSetCallbacks

      -- ** Certificate Chain Management
    , S2nCertChainAndKeyNew
    , S2nCertChainAndKeyLoadPem
    , S2nCertChainAndKeyLoadPemBytes
    , S2nCertChainAndKeyLoadPublicPemBytes
    , S2nCertChainAndKeyFree
    , S2nCertChainAndKeySetCtx
    , S2nCertChainAndKeyGetCtx
    , S2nCertChainAndKeyGetPrivateKey
    , S2nCertChainAndKeySetOcspData
    , S2nCertChainAndKeySetSctList
    , S2nConfigSetCertTiebreakCallback
    , S2nConfigAddCertChainAndKey
    , S2nConfigAddCertChainAndKeyToStore
    , S2nConfigSetCertChainAndKeyDefaults

      -- ** Trust Store
    , S2nConfigSetVerificationCaLocation
    , S2nConfigAddPemToTrustStore
    , S2nConfigWipeTrustStore
    , S2nConfigLoadSystemCerts
    , S2nConfigSetCertAuthoritiesFromTrustStore

      -- ** Verification & Validation
    , S2nConfigSetVerifyAfterSign
    , S2nConfigSetCheckStapledOcspResponse
    , S2nConfigDisableX509TimeVerification
    , S2nConfigDisableX509IntentVerification
    , S2nConfigDisableX509Verification
    , S2nConfigSetMaxCertChainDepth
    , S2nConfigSetVerifyHostCallback

      -- ** DH Parameters
    , S2nConfigAddDhparams

      -- ** Security Policies & Preferences
    , S2nConfigSetCipherPreferences
    , S2nConfigAppendProtocolPreference
    , S2nConfigSetProtocolPreferences
    , S2nConfigSetStatusRequestType
    , S2nConfigSetCtSupportLevel
    , S2nConfigSetAlertBehavior

      -- ** Extension Data
    , S2nConfigSetExtensionData
    , S2nConfigSendMaxFragmentLength
    , S2nConfigAcceptMaxFragmentLength

      -- ** Session & Ticket Configuration
    , S2nConfigSetSessionStateLifetime
    , S2nConfigSetSessionTicketsOnoff
    , S2nConfigSetSessionCacheOnoff
    , S2nConfigSetTicketEncryptDecryptKeyLifetime
    , S2nConfigSetTicketDecryptKeyLifetime
    , S2nConfigAddTicketCryptoKey
    , S2nConfigRequireTicketForwardSecrecy

      -- ** Buffer & I/O Configuration
    , S2nConfigSetSendBufferSize
    , S2nConfigSetRecvMultiRecord

      -- ** Miscellaneous Config
    , S2nConfigSetCtx
    , S2nConfigGetCtx
    , S2nConfigSetClientHelloCb
    , S2nConfigSetClientHelloCbMode
    , S2nConfigSetMaxBlindingDelay
    , S2nConfigGetClientAuthType
    , S2nConfigSetClientAuthType
    , S2nConfigSetInitialTicketCount
    , S2nConfigSetPskMode
    , S2nConfigSetPskSelectionCallback
    , S2nConfigSetAsyncPkeyCallback
    , S2nConfigSetAsyncPkeyValidationMode
    , S2nConfigSetSessionTicketCb
    , S2nConfigSetKeyLogCb
    , S2nConfigEnableCertReqDssLegacyCompat
    , S2nConfigSetServerMaxEarlyDataSize
    , S2nConfigSetEarlyDataCb
    , S2nConfigGetSupportedGroups
    , S2nConfigSetSerializationVersion

      -- ** Connection Creation & Management
    , S2nConnectionNew
    , S2nConnectionSetConfig
    , S2nConnectionSetCtx
    , S2nConnectionGetCtx
    , S2nClientHelloCbDone
    , S2nConnectionServerNameExtensionUsed

      -- ** Client Hello Access
    , S2nConnectionGetClientHello
    , S2nClientHelloParseMessage
    , S2nClientHelloFree
    , S2nClientHelloGetRawMessageLength
    , S2nClientHelloGetRawMessage
    , S2nClientHelloGetCipherSuitesLength
    , S2nClientHelloGetCipherSuites
    , S2nClientHelloGetExtensionsLength
    , S2nClientHelloGetExtensions
    , S2nClientHelloGetExtensionLength
    , S2nClientHelloGetExtensionById
    , S2nClientHelloHasExtension
    , S2nClientHelloGetSessionIdLength
    , S2nClientHelloGetSessionId
    , S2nClientHelloGetCompressionMethodsLength
    , S2nClientHelloGetCompressionMethods
    , S2nClientHelloGetLegacyProtocolVersion
    , S2nClientHelloGetRandom
    , S2nClientHelloGetSupportedGroups
    , S2nClientHelloGetServerNameLength
    , S2nClientHelloGetServerName
    , S2nClientHelloGetLegacyRecordVersion

      -- ** File Descriptor & I/O
    , S2nConnectionSetFd
    , S2nConnectionSetReadFd
    , S2nConnectionSetWriteFd
    , S2nConnectionGetReadFd
    , S2nConnectionGetWriteFd
    , S2nConnectionUseCorkedIo
    , S2nConnectionSetRecvCtx
    , S2nConnectionSetSendCtx
    , S2nConnectionSetRecvCb
    , S2nConnectionSetSendCb

      -- ** Connection Preferences
    , S2nConnectionPreferThroughput
    , S2nConnectionPreferLowLatency
    , S2nConnectionSetRecvBuffering
    , S2nPeekBuffered
    , S2nConnectionSetDynamicBuffers
    , S2nConnectionSetDynamicRecordThreshold

      -- ** Host Verification
    , S2nConnectionSetVerifyHostCallback

      -- ** Blinding & Security
    , S2nConnectionSetBlinding
    , S2nConnectionGetDelay

      -- ** Cipher & Protocol Configuration
    , S2nConnectionSetCipherPreferences
    , S2nConnectionRequestKeyUpdate
    , S2nConnectionAppendProtocolPreference
    , S2nConnectionSetProtocolPreferences

      -- ** Server Name (SNI)
    , S2nSetServerName
    , S2nGetServerName

      -- ** Application Protocol (ALPN)
    , S2nGetApplicationProtocol

      -- ** OCSP & Certificate Transparency
    , S2nConnectionGetOcspResponse
    , S2nConnectionGetSctList

      -- ** Handshake & TLS Operations
    , S2nNegotiate
    , S2nSend
    , S2nRecv
    , S2nPeek
    , S2nConnectionFreeHandshake
    , S2nConnectionReleaseBuffers
    , S2nConnectionWipe
    , S2nConnectionFree
    , S2nShutdown
    , S2nShutdownSend

      -- ** Client Authentication
    , S2nConnectionGetClientAuthType
    , S2nConnectionSetClientAuthType
    , S2nConnectionGetClientCertChain
    , S2nConnectionClientCertUsed

      -- ** Session Management
    , S2nConnectionAddNewTicketsToSend
    , S2nConnectionGetTicketsSent
    , S2nConnectionSetServerKeyingMaterialLifetime
    , S2nSessionTicketGetDataLen
    , S2nSessionTicketGetData
    , S2nSessionTicketGetLifetime
    , S2nConnectionSetSession
    , S2nConnectionGetSession
    , S2nConnectionGetSessionTicketLifetimeHint
    , S2nConnectionGetSessionLength
    , S2nConnectionGetSessionIdLength
    , S2nConnectionGetSessionId
    , S2nConnectionIsSessionResumed

      -- ** Certificate Information
    , S2nConnectionIsOcspStapled
    , S2nConnectionGetSelectedSignatureAlgorithm
    , S2nConnectionGetSelectedDigestAlgorithm
    , S2nConnectionGetSelectedClientCertSignatureAlgorithm
    , S2nConnectionGetSelectedClientCertDigestAlgorithm
    , S2nConnectionGetSignatureScheme
    , S2nConnectionGetSelectedCert
    , S2nCertChainGetLength
    , S2nCertChainGetCert
    , S2nCertGetDer
    , S2nConnectionGetPeerCertChain
    , S2nCertGetX509ExtensionValueLength
    , S2nCertGetX509ExtensionValue
    , S2nCertGetUtf8StringFromExtensionDataLength
    , S2nCertGetUtf8StringFromExtensionData

      -- ** Pre-Shared Keys (PSK)
    , S2nExternalPskNew
    , S2nPskFree
    , S2nPskSetIdentity
    , S2nPskSetSecret
    , S2nPskSetHmac
    , S2nConnectionAppendPsk
    , S2nConnectionSetPskMode
    , S2nConnectionGetNegotiatedPskIdentityLength
    , S2nConnectionGetNegotiatedPskIdentity
    , S2nOfferedPskNew
    , S2nOfferedPskFree
    , S2nOfferedPskGetIdentity
    , S2nOfferedPskListHasNext
    , S2nOfferedPskListNext
    , S2nOfferedPskListReread
    , S2nOfferedPskListChoosePsk
    , S2nPskConfigureEarlyData
    , S2nPskSetApplicationProtocol
    , S2nPskSetEarlyDataContext

      -- ** Connection Statistics
    , S2nConnectionGetWireBytesIn
    , S2nConnectionGetWireBytesOut

      -- ** Protocol Version Information
    , S2nConnectionGetClientProtocolVersion
    , S2nConnectionGetServerProtocolVersion
    , S2nConnectionGetActualProtocolVersion
    , S2nConnectionGetClientHelloVersion

      -- ** Cipher & Security Information
    , S2nConnectionGetCipher
    , S2nConnectionGetCertificateMatch
    , S2nConnectionGetMasterSecret
    , S2nConnectionTlsExporter
    , S2nConnectionGetCipherIanaValue
    , S2nConnectionIsValidForCipherPreferences
    , S2nConnectionGetCurve
    , S2nConnectionGetKemName
    , S2nConnectionGetKemGroupName
    , S2nConnectionGetKeyExchangeGroup
    , S2nConnectionGetAlert
    , S2nConnectionGetHandshakeTypeName
    , S2nConnectionGetLastMessageName

      -- ** Async Private Key Operations
    , S2nAsyncPkeyOpPerform
    , S2nAsyncPkeyOpApply
    , S2nAsyncPkeyOpFree
    , S2nAsyncPkeyOpGetOpType
    , S2nAsyncPkeyOpGetInputSize
    , S2nAsyncPkeyOpGetInput
    , S2nAsyncPkeyOpSetOutput

      -- ** Early Data
    , S2nConnectionSetServerMaxEarlyDataSize
    , S2nConnectionSetServerEarlyDataContext
    , S2nConnectionGetEarlyDataStatus
    , S2nConnectionGetRemainingEarlyDataSize
    , S2nConnectionGetMaxEarlyDataSize
    , S2nSendEarlyData
    , S2nRecvEarlyData
    , S2nOfferedEarlyDataGetContextLength
    , S2nOfferedEarlyDataGetContext
    , S2nOfferedEarlyDataReject
    , S2nOfferedEarlyDataAccept

      -- ** Connection Serialization
    , S2nConnectionSerializationLength
    , S2nConnectionSerialize
    , S2nConnectionDeserialize

      -- * FFI Record
    , S2nTlsSys (..)
    ) where

import Data.Word (Word8, Word16, Word32, Word64)
import Foreign.C.String (CString)
import Foreign.C.Types (CInt (..), CSize (..), CLong (..))
import Foreign.Ptr (FunPtr, Ptr)
import Foreign.Storable (Storable)
import System.Posix.Types (CSsize (..))

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

pattern S2N_SUCCESS :: CInt
pattern S2N_SUCCESS = 0

pattern S2N_FAILURE :: CInt
pattern S2N_FAILURE = -1

pattern S2N_CALLBACK_BLOCKED :: CInt
pattern S2N_CALLBACK_BLOCKED = -2

--------------------------------------------------------------------------------
-- TLS Versions
--------------------------------------------------------------------------------

pattern S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION :: Word8
pattern S2N_MINIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION = 2

pattern S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION :: Word8
pattern S2N_MAXIMUM_SUPPORTED_TLS_RECORD_MAJOR_VERSION = 3

pattern S2N_SSLv2 :: CInt
pattern S2N_SSLv2 = 20

pattern S2N_SSLv3 :: CInt
pattern S2N_SSLv3 = 30

pattern S2N_TLS10 :: CInt
pattern S2N_TLS10 = 31

pattern S2N_TLS11 :: CInt
pattern S2N_TLS11 = 32

pattern S2N_TLS12 :: CInt
pattern S2N_TLS12 = 33

pattern S2N_TLS13 :: CInt
pattern S2N_TLS13 = 34

pattern S2N_UNKNOWN_PROTOCOL_VERSION :: CInt
pattern S2N_UNKNOWN_PROTOCOL_VERSION = 0

--------------------------------------------------------------------------------
-- Enumerations
--------------------------------------------------------------------------------

newtype S2nErrorType = S2nErrorType CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_ERR_T_OK :: S2nErrorType
pattern S2N_ERR_T_OK = S2nErrorType 0

pattern S2N_ERR_T_IO :: S2nErrorType
pattern S2N_ERR_T_IO = S2nErrorType 1

pattern S2N_ERR_T_CLOSED :: S2nErrorType
pattern S2N_ERR_T_CLOSED = S2nErrorType 2

pattern S2N_ERR_T_BLOCKED :: S2nErrorType
pattern S2N_ERR_T_BLOCKED = S2nErrorType 3

pattern S2N_ERR_T_ALERT :: S2nErrorType
pattern S2N_ERR_T_ALERT = S2nErrorType 4

pattern S2N_ERR_T_PROTO :: S2nErrorType
pattern S2N_ERR_T_PROTO = S2nErrorType 5

pattern S2N_ERR_T_INTERNAL :: S2nErrorType
pattern S2N_ERR_T_INTERNAL = S2nErrorType 6

pattern S2N_ERR_T_USAGE :: S2nErrorType
pattern S2N_ERR_T_USAGE = S2nErrorType 7

newtype S2nMode = S2nMode CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_SERVER :: S2nMode
pattern S2N_SERVER = S2nMode 0

pattern S2N_CLIENT :: S2nMode
pattern S2N_CLIENT = S2nMode 1

newtype S2nBlinding = S2nBlinding CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_BUILT_IN_BLINDING :: S2nBlinding
pattern S2N_BUILT_IN_BLINDING = S2nBlinding 0

pattern S2N_SELF_SERVICE_BLINDING :: S2nBlinding
pattern S2N_SELF_SERVICE_BLINDING = S2nBlinding 1

newtype S2nBlockedStatus = S2nBlockedStatus CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_NOT_BLOCKED :: S2nBlockedStatus
pattern S2N_NOT_BLOCKED = S2nBlockedStatus 0

pattern S2N_BLOCKED_ON_READ :: S2nBlockedStatus
pattern S2N_BLOCKED_ON_READ = S2nBlockedStatus 1

pattern S2N_BLOCKED_ON_WRITE :: S2nBlockedStatus
pattern S2N_BLOCKED_ON_WRITE = S2nBlockedStatus 2

pattern S2N_BLOCKED_ON_APPLICATION_INPUT :: S2nBlockedStatus
pattern S2N_BLOCKED_ON_APPLICATION_INPUT = S2nBlockedStatus 3

pattern S2N_BLOCKED_ON_EARLY_DATA :: S2nBlockedStatus
pattern S2N_BLOCKED_ON_EARLY_DATA = S2nBlockedStatus 4

newtype S2nCertAuthType = S2nCertAuthType CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_CERT_AUTH_NONE :: S2nCertAuthType
pattern S2N_CERT_AUTH_NONE = S2nCertAuthType 0

pattern S2N_CERT_AUTH_REQUIRED :: S2nCertAuthType
pattern S2N_CERT_AUTH_REQUIRED = S2nCertAuthType 1

pattern S2N_CERT_AUTH_OPTIONAL :: S2nCertAuthType
pattern S2N_CERT_AUTH_OPTIONAL = S2nCertAuthType 2

newtype S2nPskHmac = S2nPskHmac CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_PSK_HMAC_SHA256 :: S2nPskHmac
pattern S2N_PSK_HMAC_SHA256 = S2nPskHmac 0

pattern S2N_PSK_HMAC_SHA384 :: S2nPskHmac
pattern S2N_PSK_HMAC_SHA384 = S2nPskHmac 1

newtype S2nPskMode = S2nPskMode CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_PSK_MODE_RESUMPTION :: S2nPskMode
pattern S2N_PSK_MODE_RESUMPTION = S2nPskMode 0

pattern S2N_PSK_MODE_EXTERNAL :: S2nPskMode
pattern S2N_PSK_MODE_EXTERNAL = S2nPskMode 1

newtype S2nEarlyDataStatus = S2nEarlyDataStatus CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_EARLY_DATA_STATUS_OK :: S2nEarlyDataStatus
pattern S2N_EARLY_DATA_STATUS_OK = S2nEarlyDataStatus 0

pattern S2N_EARLY_DATA_STATUS_NOT_REQUESTED :: S2nEarlyDataStatus
pattern S2N_EARLY_DATA_STATUS_NOT_REQUESTED = S2nEarlyDataStatus 1

pattern S2N_EARLY_DATA_STATUS_REJECTED :: S2nEarlyDataStatus
pattern S2N_EARLY_DATA_STATUS_REJECTED = S2nEarlyDataStatus 2

pattern S2N_EARLY_DATA_STATUS_END :: S2nEarlyDataStatus
pattern S2N_EARLY_DATA_STATUS_END = S2nEarlyDataStatus 3

newtype S2nAsyncPkeyOpType = S2nAsyncPkeyOpType CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_ASYNC_DECRYPT :: S2nAsyncPkeyOpType
pattern S2N_ASYNC_DECRYPT = S2nAsyncPkeyOpType 0

pattern S2N_ASYNC_SIGN :: S2nAsyncPkeyOpType
pattern S2N_ASYNC_SIGN = S2nAsyncPkeyOpType 1

newtype S2nAsyncPkeyValidationMode = S2nAsyncPkeyValidationMode CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_ASYNC_PKEY_VALIDATION_FAST :: S2nAsyncPkeyValidationMode
pattern S2N_ASYNC_PKEY_VALIDATION_FAST = S2nAsyncPkeyValidationMode 0

pattern S2N_ASYNC_PKEY_VALIDATION_STRICT :: S2nAsyncPkeyValidationMode
pattern S2N_ASYNC_PKEY_VALIDATION_STRICT = S2nAsyncPkeyValidationMode 1

newtype S2nSerializationVersion = S2nSerializationVersion CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_SERIALIZED_CONN_NONE :: S2nSerializationVersion
pattern S2N_SERIALIZED_CONN_NONE = S2nSerializationVersion 0

pattern S2N_SERIALIZED_CONN_V1 :: S2nSerializationVersion
pattern S2N_SERIALIZED_CONN_V1 = S2nSerializationVersion 1

newtype S2nTlsExtensionType = S2nTlsExtensionType CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_EXTENSION_SERVER_NAME :: S2nTlsExtensionType
pattern S2N_EXTENSION_SERVER_NAME = S2nTlsExtensionType 0

pattern S2N_EXTENSION_MAX_FRAG_LEN :: S2nTlsExtensionType
pattern S2N_EXTENSION_MAX_FRAG_LEN = S2nTlsExtensionType 1

pattern S2N_EXTENSION_OCSP_STAPLING :: S2nTlsExtensionType
pattern S2N_EXTENSION_OCSP_STAPLING = S2nTlsExtensionType 5

pattern S2N_EXTENSION_SUPPORTED_GROUPS :: S2nTlsExtensionType
pattern S2N_EXTENSION_SUPPORTED_GROUPS = S2nTlsExtensionType 10

pattern S2N_EXTENSION_EC_POINT_FORMATS :: S2nTlsExtensionType
pattern S2N_EXTENSION_EC_POINT_FORMATS = S2nTlsExtensionType 11

pattern S2N_EXTENSION_SIGNATURE_ALGORITHMS :: S2nTlsExtensionType
pattern S2N_EXTENSION_SIGNATURE_ALGORITHMS = S2nTlsExtensionType 13

pattern S2N_EXTENSION_ALPN :: S2nTlsExtensionType
pattern S2N_EXTENSION_ALPN = S2nTlsExtensionType 16

pattern S2N_EXTENSION_CERTIFICATE_TRANSPARENCY :: S2nTlsExtensionType
pattern S2N_EXTENSION_CERTIFICATE_TRANSPARENCY = S2nTlsExtensionType 18

pattern S2N_EXTENSION_RENEGOTIATION_INFO :: S2nTlsExtensionType
pattern S2N_EXTENSION_RENEGOTIATION_INFO = S2nTlsExtensionType 65281

newtype S2nMaxFragLen = S2nMaxFragLen CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_TLS_MAX_FRAG_LEN_512 :: S2nMaxFragLen
pattern S2N_TLS_MAX_FRAG_LEN_512 = S2nMaxFragLen 1

pattern S2N_TLS_MAX_FRAG_LEN_1024 :: S2nMaxFragLen
pattern S2N_TLS_MAX_FRAG_LEN_1024 = S2nMaxFragLen 2

pattern S2N_TLS_MAX_FRAG_LEN_2048 :: S2nMaxFragLen
pattern S2N_TLS_MAX_FRAG_LEN_2048 = S2nMaxFragLen 3

pattern S2N_TLS_MAX_FRAG_LEN_4096 :: S2nMaxFragLen
pattern S2N_TLS_MAX_FRAG_LEN_4096 = S2nMaxFragLen 4

newtype S2nFipsMode = S2nFipsMode CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_FIPS_MODE_DISABLED :: S2nFipsMode
pattern S2N_FIPS_MODE_DISABLED = S2nFipsMode 0

pattern S2N_FIPS_MODE_ENABLED :: S2nFipsMode
pattern S2N_FIPS_MODE_ENABLED = S2nFipsMode 1

newtype S2nStatusRequestType = S2nStatusRequestType CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_STATUS_REQUEST_NONE :: S2nStatusRequestType
pattern S2N_STATUS_REQUEST_NONE = S2nStatusRequestType 0

pattern S2N_STATUS_REQUEST_OCSP :: S2nStatusRequestType
pattern S2N_STATUS_REQUEST_OCSP = S2nStatusRequestType 1

newtype S2nCtSupportLevel = S2nCtSupportLevel CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_CT_SUPPORT_NONE :: S2nCtSupportLevel
pattern S2N_CT_SUPPORT_NONE = S2nCtSupportLevel 0

pattern S2N_CT_SUPPORT_REQUEST :: S2nCtSupportLevel
pattern S2N_CT_SUPPORT_REQUEST = S2nCtSupportLevel 1

newtype S2nAlertBehavior = S2nAlertBehavior CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_ALERT_FAIL_ON_WARNINGS :: S2nAlertBehavior
pattern S2N_ALERT_FAIL_ON_WARNINGS = S2nAlertBehavior 0

pattern S2N_ALERT_IGNORE_WARNINGS :: S2nAlertBehavior
pattern S2N_ALERT_IGNORE_WARNINGS = S2nAlertBehavior 1

newtype S2nClientHelloCbMode = S2nClientHelloCbMode CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_CLIENT_HELLO_CB_BLOCKING :: S2nClientHelloCbMode
pattern S2N_CLIENT_HELLO_CB_BLOCKING = S2nClientHelloCbMode 0

pattern S2N_CLIENT_HELLO_CB_NONBLOCKING :: S2nClientHelloCbMode
pattern S2N_CLIENT_HELLO_CB_NONBLOCKING = S2nClientHelloCbMode 1

newtype S2nTlsSignatureAlgorithm = S2nTlsSignatureAlgorithm CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_TLS_SIGNATURE_ANONYMOUS :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_ANONYMOUS = S2nTlsSignatureAlgorithm 0

pattern S2N_TLS_SIGNATURE_RSA :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_RSA = S2nTlsSignatureAlgorithm 1

pattern S2N_TLS_SIGNATURE_ECDSA :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_ECDSA = S2nTlsSignatureAlgorithm 3

pattern S2N_TLS_SIGNATURE_RSA_PSS_RSAE :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_RSA_PSS_RSAE = S2nTlsSignatureAlgorithm 4

pattern S2N_TLS_SIGNATURE_RSA_PSS_PSS :: S2nTlsSignatureAlgorithm
pattern S2N_TLS_SIGNATURE_RSA_PSS_PSS = S2nTlsSignatureAlgorithm 5

newtype S2nTlsHashAlgorithm = S2nTlsHashAlgorithm CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_TLS_HASH_NONE :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_NONE = S2nTlsHashAlgorithm 0

pattern S2N_TLS_HASH_MD5 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_MD5 = S2nTlsHashAlgorithm 1

pattern S2N_TLS_HASH_SHA1 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA1 = S2nTlsHashAlgorithm 2

pattern S2N_TLS_HASH_SHA224 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA224 = S2nTlsHashAlgorithm 3

pattern S2N_TLS_HASH_SHA256 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA256 = S2nTlsHashAlgorithm 4

pattern S2N_TLS_HASH_SHA384 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA384 = S2nTlsHashAlgorithm 5

pattern S2N_TLS_HASH_SHA512 :: S2nTlsHashAlgorithm
pattern S2N_TLS_HASH_SHA512 = S2nTlsHashAlgorithm 6

newtype S2nCertSniMatch = S2nCertSniMatch CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_CERT_SNI_MATCH_NOT_APPLICABLE :: S2nCertSniMatch
pattern S2N_CERT_SNI_MATCH_NOT_APPLICABLE = S2nCertSniMatch 0

pattern S2N_CERT_SNI_MATCH :: S2nCertSniMatch
pattern S2N_CERT_SNI_MATCH = S2nCertSniMatch 1

pattern S2N_CERT_SNI_NO_MATCH_FOUND :: S2nCertSniMatch
pattern S2N_CERT_SNI_NO_MATCH_FOUND = S2nCertSniMatch 2

newtype S2nPeerKeyUpdate = S2nPeerKeyUpdate CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_KEY_UPDATE_NOT_REQUESTED :: S2nPeerKeyUpdate
pattern S2N_KEY_UPDATE_NOT_REQUESTED = S2nPeerKeyUpdate 0

pattern S2N_KEY_UPDATE_REQUESTED :: S2nPeerKeyUpdate
pattern S2N_KEY_UPDATE_REQUESTED = S2nPeerKeyUpdate 1

newtype S2nVerifyAfterSign = S2nVerifyAfterSign CInt
    deriving (Eq, Ord, Show, Storable)

pattern S2N_VERIFY_AFTER_SIGN_DISABLED :: S2nVerifyAfterSign
pattern S2N_VERIFY_AFTER_SIGN_DISABLED = S2nVerifyAfterSign 0

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
-- Function Types
--------------------------------------------------------------------------------

-- Initialization & Cleanup
type S2nInit = IO CInt
type S2nCleanup = IO CInt
type S2nCleanupFinal = IO CInt
type S2nCryptoDisableInit = IO CInt
type S2nDisableAtexit = IO CInt
type S2nGetOpensslVersion = IO CLong
type S2nGetFipsMode = Ptr S2nFipsMode -> IO CInt

-- Error Handling
type S2nErrnoLocation = IO (Ptr CInt)
type S2nErrorGetType = CInt -> IO S2nErrorType
type S2nStrerror = CInt -> CString -> IO CString
type S2nStrerrorDebug = CInt -> CString -> IO CString
type S2nStrerrorName = CInt -> IO CString
type S2nStrerrorSource = CInt -> IO CString

-- Stack Traces
type S2nStackTracesEnabled = IO Bool
type S2nStackTracesEnabledSet = Bool -> IO CInt
type S2nCalculateStacktrace = IO CInt
type S2nFreeStacktrace = IO CInt
type S2nGetStacktrace = Ptr S2nStacktrace -> IO CInt

-- Config Management
type S2nConfigNew = IO (Ptr S2nConfig)
type S2nConfigNewMinimal = IO (Ptr S2nConfig)
type S2nConfigFree = Ptr S2nConfig -> IO CInt
type S2nConfigFreeDhparams = Ptr S2nConfig -> IO CInt
type S2nConfigFreeCertChainAndKey = Ptr S2nConfig -> IO CInt
type S2nConfigSetWallClock = Ptr S2nConfig -> S2nClockTimeNanoseconds -> Ptr () -> IO CInt
type S2nConfigSetMonotonicClock = Ptr S2nConfig -> S2nClockTimeNanoseconds -> Ptr () -> IO CInt

-- Cache Callbacks
type S2nConfigSetCacheStoreCallback = Ptr S2nConfig -> S2nCacheStoreCallback -> Ptr () -> IO CInt
type S2nConfigSetCacheRetrieveCallback = Ptr S2nConfig -> S2nCacheRetrieveCallback -> Ptr () -> IO CInt
type S2nConfigSetCacheDeleteCallback = Ptr S2nConfig -> S2nCacheDeleteCallback -> Ptr () -> IO CInt

-- Memory & Random Callbacks
type S2nMemSetCallbacks = S2nMemInitCallback -> S2nMemCleanupCallback -> S2nMemMallocCallback -> S2nMemFreeCallback -> IO CInt
type S2nRandSetCallbacks = S2nRandInitCallback -> S2nRandCleanupCallback -> S2nRandSeedCallback -> S2nRandMixCallback -> IO CInt

-- Certificate Chain Management
type S2nCertChainAndKeyNew = IO (Ptr S2nCertChainAndKey)
type S2nCertChainAndKeyLoadPem = Ptr S2nCertChainAndKey -> CString -> CString -> IO CInt
type S2nCertChainAndKeyLoadPemBytes = Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO CInt
type S2nCertChainAndKeyLoadPublicPemBytes = Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> IO CInt
type S2nCertChainAndKeyFree = Ptr S2nCertChainAndKey -> IO CInt
type S2nCertChainAndKeySetCtx = Ptr S2nCertChainAndKey -> Ptr () -> IO CInt
type S2nCertChainAndKeyGetCtx = Ptr S2nCertChainAndKey -> IO (Ptr ())
type S2nCertChainAndKeyGetPrivateKey = Ptr S2nCertChainAndKey -> IO (Ptr S2nCertPrivateKey)
type S2nCertChainAndKeySetOcspData = Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> IO CInt
type S2nCertChainAndKeySetSctList = Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> IO CInt
type S2nConfigSetCertTiebreakCallback = Ptr S2nConfig -> S2nCertTiebreakCallback -> IO CInt
type S2nConfigAddCertChainAndKey = Ptr S2nConfig -> CString -> CString -> IO CInt
type S2nConfigAddCertChainAndKeyToStore = Ptr S2nConfig -> Ptr S2nCertChainAndKey -> IO CInt
type S2nConfigSetCertChainAndKeyDefaults = Ptr S2nConfig -> Ptr (Ptr S2nCertChainAndKey) -> Word32 -> IO CInt

-- Trust Store
type S2nConfigSetVerificationCaLocation = Ptr S2nConfig -> CString -> CString -> IO CInt
type S2nConfigAddPemToTrustStore = Ptr S2nConfig -> CString -> IO CInt
type S2nConfigWipeTrustStore = Ptr S2nConfig -> IO CInt
type S2nConfigLoadSystemCerts = Ptr S2nConfig -> IO CInt
type S2nConfigSetCertAuthoritiesFromTrustStore = Ptr S2nConfig -> IO CInt

-- Verification & Validation
type S2nConfigSetVerifyAfterSign = Ptr S2nConfig -> S2nVerifyAfterSign -> IO CInt
type S2nConfigSetCheckStapledOcspResponse = Ptr S2nConfig -> Word8 -> IO CInt
type S2nConfigDisableX509TimeVerification = Ptr S2nConfig -> IO CInt
type S2nConfigDisableX509IntentVerification = Ptr S2nConfig -> IO CInt
type S2nConfigDisableX509Verification = Ptr S2nConfig -> IO CInt
type S2nConfigSetMaxCertChainDepth = Ptr S2nConfig -> Word16 -> IO CInt
type S2nConfigSetVerifyHostCallback = Ptr S2nConfig -> S2nVerifyHostFn -> Ptr () -> IO CInt

-- DH Parameters
type S2nConfigAddDhparams = Ptr S2nConfig -> CString -> IO CInt

-- Security Policies & Preferences
type S2nConfigSetCipherPreferences = Ptr S2nConfig -> CString -> IO CInt
type S2nConfigAppendProtocolPreference = Ptr S2nConfig -> Ptr Word8 -> Word8 -> IO CInt
type S2nConfigSetProtocolPreferences = Ptr S2nConfig -> Ptr CString -> CInt -> IO CInt
type S2nConfigSetStatusRequestType = Ptr S2nConfig -> S2nStatusRequestType -> IO CInt
type S2nConfigSetCtSupportLevel = Ptr S2nConfig -> S2nCtSupportLevel -> IO CInt
type S2nConfigSetAlertBehavior = Ptr S2nConfig -> S2nAlertBehavior -> IO CInt

-- Extension Data
type S2nConfigSetExtensionData = Ptr S2nConfig -> S2nTlsExtensionType -> Ptr Word8 -> Word32 -> IO CInt
type S2nConfigSendMaxFragmentLength = Ptr S2nConfig -> S2nMaxFragLen -> IO CInt
type S2nConfigAcceptMaxFragmentLength = Ptr S2nConfig -> IO CInt

-- Session & Ticket Configuration
type S2nConfigSetSessionStateLifetime = Ptr S2nConfig -> Word64 -> IO CInt
type S2nConfigSetSessionTicketsOnoff = Ptr S2nConfig -> Word8 -> IO CInt
type S2nConfigSetSessionCacheOnoff = Ptr S2nConfig -> Word8 -> IO CInt
type S2nConfigSetTicketEncryptDecryptKeyLifetime = Ptr S2nConfig -> Word64 -> IO CInt
type S2nConfigSetTicketDecryptKeyLifetime = Ptr S2nConfig -> Word64 -> IO CInt
type S2nConfigAddTicketCryptoKey = Ptr S2nConfig -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Word64 -> IO CInt
type S2nConfigRequireTicketForwardSecrecy = Ptr S2nConfig -> Bool -> IO CInt

-- Buffer & I/O Configuration
type S2nConfigSetSendBufferSize = Ptr S2nConfig -> Word32 -> IO CInt
type S2nConfigSetRecvMultiRecord = Ptr S2nConfig -> Bool -> IO CInt

-- Miscellaneous Config
type S2nConfigSetCtx = Ptr S2nConfig -> Ptr () -> IO CInt
type S2nConfigGetCtx = Ptr S2nConfig -> Ptr (Ptr ()) -> IO CInt
type S2nConfigSetClientHelloCb = Ptr S2nConfig -> S2nClientHelloFn -> Ptr () -> IO CInt
type S2nConfigSetClientHelloCbMode = Ptr S2nConfig -> S2nClientHelloCbMode -> IO CInt
type S2nConfigSetMaxBlindingDelay = Ptr S2nConfig -> Word32 -> IO CInt
type S2nConfigGetClientAuthType = Ptr S2nConfig -> Ptr S2nCertAuthType -> IO CInt
type S2nConfigSetClientAuthType = Ptr S2nConfig -> S2nCertAuthType -> IO CInt
type S2nConfigSetInitialTicketCount = Ptr S2nConfig -> Word8 -> IO CInt
type S2nConfigSetPskMode = Ptr S2nConfig -> S2nPskMode -> IO CInt
type S2nConfigSetPskSelectionCallback = Ptr S2nConfig -> S2nPskSelectionCallback -> Ptr () -> IO CInt
type S2nConfigSetAsyncPkeyCallback = Ptr S2nConfig -> S2nAsyncPkeyFn -> IO CInt
type S2nConfigSetAsyncPkeyValidationMode = Ptr S2nConfig -> S2nAsyncPkeyValidationMode -> IO CInt
type S2nConfigSetSessionTicketCb = Ptr S2nConfig -> S2nSessionTicketFn -> Ptr () -> IO CInt
type S2nConfigSetKeyLogCb = Ptr S2nConfig -> S2nKeyLogFn -> Ptr () -> IO CInt
type S2nConfigEnableCertReqDssLegacyCompat = Ptr S2nConfig -> IO CInt
type S2nConfigSetServerMaxEarlyDataSize = Ptr S2nConfig -> Word32 -> IO CInt
type S2nConfigSetEarlyDataCb = Ptr S2nConfig -> S2nEarlyDataCb -> IO CInt
type S2nConfigGetSupportedGroups = Ptr S2nConfig -> Ptr Word16 -> Word16 -> Ptr Word16 -> IO CInt
type S2nConfigSetSerializationVersion = Ptr S2nConfig -> S2nSerializationVersion -> IO CInt

-- Connection Creation & Management
type S2nConnectionNew = S2nMode -> IO (Ptr S2nConnection)
type S2nConnectionSetConfig = Ptr S2nConnection -> Ptr S2nConfig -> IO CInt
type S2nConnectionSetCtx = Ptr S2nConnection -> Ptr () -> IO CInt
type S2nConnectionGetCtx = Ptr S2nConnection -> IO (Ptr ())
type S2nClientHelloCbDone = Ptr S2nConnection -> IO CInt
type S2nConnectionServerNameExtensionUsed = Ptr S2nConnection -> IO CInt

-- Client Hello Access
type S2nConnectionGetClientHello = Ptr S2nConnection -> IO (Ptr S2nClientHello)
type S2nClientHelloParseMessage = Ptr Word8 -> Word32 -> IO (Ptr S2nClientHello)
type S2nClientHelloFree = Ptr (Ptr S2nClientHello) -> IO CInt
type S2nClientHelloGetRawMessageLength = Ptr S2nClientHello -> IO CSsize
type S2nClientHelloGetRawMessage = Ptr S2nClientHello -> Ptr Word8 -> Word32 -> IO CSsize
type S2nClientHelloGetCipherSuitesLength = Ptr S2nClientHello -> IO CSsize
type S2nClientHelloGetCipherSuites = Ptr S2nClientHello -> Ptr Word8 -> Word32 -> IO CSsize
type S2nClientHelloGetExtensionsLength = Ptr S2nClientHello -> IO CSsize
type S2nClientHelloGetExtensions = Ptr S2nClientHello -> Ptr Word8 -> Word32 -> IO CSsize
type S2nClientHelloGetExtensionLength = Ptr S2nClientHello -> S2nTlsExtensionType -> IO CSsize
type S2nClientHelloGetExtensionById = Ptr S2nClientHello -> S2nTlsExtensionType -> Ptr Word8 -> Word32 -> IO CSsize
type S2nClientHelloHasExtension = Ptr S2nClientHello -> Word16 -> Ptr Bool -> IO CInt
type S2nClientHelloGetSessionIdLength = Ptr S2nClientHello -> Ptr Word32 -> IO CInt
type S2nClientHelloGetSessionId = Ptr S2nClientHello -> Ptr Word8 -> Ptr Word32 -> Word32 -> IO CInt
type S2nClientHelloGetCompressionMethodsLength = Ptr S2nClientHello -> Ptr Word32 -> IO CInt
type S2nClientHelloGetCompressionMethods = Ptr S2nClientHello -> Ptr Word8 -> Word32 -> Ptr Word32 -> IO CInt
type S2nClientHelloGetLegacyProtocolVersion = Ptr S2nClientHello -> Ptr Word8 -> IO CInt
type S2nClientHelloGetRandom = Ptr S2nClientHello -> Ptr Word8 -> Word32 -> IO CInt
type S2nClientHelloGetSupportedGroups = Ptr S2nClientHello -> Ptr Word16 -> Word16 -> Ptr Word16 -> IO CInt
type S2nClientHelloGetServerNameLength = Ptr S2nClientHello -> Ptr Word16 -> IO CInt
type S2nClientHelloGetServerName = Ptr S2nClientHello -> Ptr Word8 -> Word16 -> Ptr Word16 -> IO CInt
type S2nClientHelloGetLegacyRecordVersion = Ptr S2nClientHello -> Ptr Word8 -> IO CInt

-- File Descriptor & I/O
type S2nConnectionSetFd = Ptr S2nConnection -> CInt -> IO CInt
type S2nConnectionSetReadFd = Ptr S2nConnection -> CInt -> IO CInt
type S2nConnectionSetWriteFd = Ptr S2nConnection -> CInt -> IO CInt
type S2nConnectionGetReadFd = Ptr S2nConnection -> Ptr CInt -> IO CInt
type S2nConnectionGetWriteFd = Ptr S2nConnection -> Ptr CInt -> IO CInt
type S2nConnectionUseCorkedIo = Ptr S2nConnection -> IO CInt
type S2nConnectionSetRecvCtx = Ptr S2nConnection -> Ptr () -> IO CInt
type S2nConnectionSetSendCtx = Ptr S2nConnection -> Ptr () -> IO CInt
type S2nConnectionSetRecvCb = Ptr S2nConnection -> S2nRecvFn -> IO CInt
type S2nConnectionSetSendCb = Ptr S2nConnection -> S2nSendFn -> IO CInt

-- Connection Preferences
type S2nConnectionPreferThroughput = Ptr S2nConnection -> IO CInt
type S2nConnectionPreferLowLatency = Ptr S2nConnection -> IO CInt
type S2nConnectionSetRecvBuffering = Ptr S2nConnection -> Bool -> IO CInt
type S2nPeekBuffered = Ptr S2nConnection -> IO Word32
type S2nConnectionSetDynamicBuffers = Ptr S2nConnection -> Bool -> IO CInt
type S2nConnectionSetDynamicRecordThreshold = Ptr S2nConnection -> Word32 -> Word16 -> IO CInt

-- Host Verification
type S2nConnectionSetVerifyHostCallback = Ptr S2nConnection -> S2nVerifyHostFn -> Ptr () -> IO CInt

-- Blinding & Security
type S2nConnectionSetBlinding = Ptr S2nConnection -> S2nBlinding -> IO CInt
type S2nConnectionGetDelay = Ptr S2nConnection -> IO Word64

-- Cipher & Protocol Configuration
type S2nConnectionSetCipherPreferences = Ptr S2nConnection -> CString -> IO CInt
type S2nConnectionRequestKeyUpdate = Ptr S2nConnection -> S2nPeerKeyUpdate -> IO CInt
type S2nConnectionAppendProtocolPreference = Ptr S2nConnection -> Ptr Word8 -> Word8 -> IO CInt
type S2nConnectionSetProtocolPreferences = Ptr S2nConnection -> Ptr CString -> CInt -> IO CInt

-- Server Name (SNI)
type S2nSetServerName = Ptr S2nConnection -> CString -> IO CInt
type S2nGetServerName = Ptr S2nConnection -> IO CString

-- Application Protocol (ALPN)
type S2nGetApplicationProtocol = Ptr S2nConnection -> IO CString

-- OCSP & Certificate Transparency
type S2nConnectionGetOcspResponse = Ptr S2nConnection -> Ptr Word32 -> IO (Ptr Word8)
type S2nConnectionGetSctList = Ptr S2nConnection -> Ptr Word32 -> IO (Ptr Word8)

-- Handshake & TLS Operations
type S2nNegotiate = Ptr S2nConnection -> Ptr S2nBlockedStatus -> IO CInt
type S2nSend = Ptr S2nConnection -> Ptr () -> CSsize -> Ptr S2nBlockedStatus -> IO CSsize
type S2nRecv = Ptr S2nConnection -> Ptr () -> CSsize -> Ptr S2nBlockedStatus -> IO CSsize
type S2nPeek = Ptr S2nConnection -> IO Word32
type S2nConnectionFreeHandshake = Ptr S2nConnection -> IO CInt
type S2nConnectionReleaseBuffers = Ptr S2nConnection -> IO CInt
type S2nConnectionWipe = Ptr S2nConnection -> IO CInt
type S2nConnectionFree = Ptr S2nConnection -> IO CInt
type S2nShutdown = Ptr S2nConnection -> Ptr S2nBlockedStatus -> IO CInt
type S2nShutdownSend = Ptr S2nConnection -> Ptr S2nBlockedStatus -> IO CInt

-- Client Authentication
type S2nConnectionGetClientAuthType = Ptr S2nConnection -> Ptr S2nCertAuthType -> IO CInt
type S2nConnectionSetClientAuthType = Ptr S2nConnection -> S2nCertAuthType -> IO CInt
type S2nConnectionGetClientCertChain = Ptr S2nConnection -> Ptr (Ptr Word8) -> Ptr Word32 -> IO CInt
type S2nConnectionClientCertUsed = Ptr S2nConnection -> IO CInt

-- Session Management
type S2nConnectionAddNewTicketsToSend = Ptr S2nConnection -> Word8 -> IO CInt
type S2nConnectionGetTicketsSent = Ptr S2nConnection -> Ptr Word16 -> IO CInt
type S2nConnectionSetServerKeyingMaterialLifetime = Ptr S2nConnection -> Word32 -> IO CInt
type S2nSessionTicketGetDataLen = Ptr S2nSessionTicket -> Ptr CSize -> IO CInt
type S2nSessionTicketGetData = Ptr S2nSessionTicket -> CSize -> Ptr Word8 -> IO CInt
type S2nSessionTicketGetLifetime = Ptr S2nSessionTicket -> Ptr Word32 -> IO CInt
type S2nConnectionSetSession = Ptr S2nConnection -> Ptr Word8 -> CSize -> IO CInt
type S2nConnectionGetSession = Ptr S2nConnection -> Ptr Word8 -> CSize -> IO CInt
type S2nConnectionGetSessionTicketLifetimeHint = Ptr S2nConnection -> IO CInt
type S2nConnectionGetSessionLength = Ptr S2nConnection -> IO CInt
type S2nConnectionGetSessionIdLength = Ptr S2nConnection -> IO CInt
type S2nConnectionGetSessionId = Ptr S2nConnection -> Ptr Word8 -> CSize -> IO CInt
type S2nConnectionIsSessionResumed = Ptr S2nConnection -> IO CInt

-- Certificate Information
type S2nConnectionIsOcspStapled = Ptr S2nConnection -> IO CInt
type S2nConnectionGetSelectedSignatureAlgorithm = Ptr S2nConnection -> Ptr S2nTlsSignatureAlgorithm -> IO CInt
type S2nConnectionGetSelectedDigestAlgorithm = Ptr S2nConnection -> Ptr S2nTlsHashAlgorithm -> IO CInt
type S2nConnectionGetSelectedClientCertSignatureAlgorithm = Ptr S2nConnection -> Ptr S2nTlsSignatureAlgorithm -> IO CInt
type S2nConnectionGetSelectedClientCertDigestAlgorithm = Ptr S2nConnection -> Ptr S2nTlsHashAlgorithm -> IO CInt
type S2nConnectionGetSignatureScheme = Ptr S2nConnection -> Ptr CString -> IO CInt
type S2nConnectionGetSelectedCert = Ptr S2nConnection -> IO (Ptr S2nCertChainAndKey)
type S2nCertChainGetLength = Ptr S2nCertChainAndKey -> Ptr Word32 -> IO CInt
type S2nCertChainGetCert = Ptr S2nCertChainAndKey -> Ptr (Ptr S2nCert) -> Word32 -> IO CInt
type S2nCertGetDer = Ptr S2nCert -> Ptr (Ptr Word8) -> Ptr Word32 -> IO CInt
type S2nConnectionGetPeerCertChain = Ptr S2nConnection -> Ptr S2nCertChainAndKey -> IO CInt
type S2nCertGetX509ExtensionValueLength = Ptr S2nCert -> Ptr Word8 -> Ptr Word32 -> IO CInt
type S2nCertGetX509ExtensionValue = Ptr S2nCert -> Ptr Word8 -> Ptr Word8 -> Ptr Word32 -> Ptr Bool -> IO CInt
type S2nCertGetUtf8StringFromExtensionDataLength = Ptr Word8 -> Word32 -> Ptr Word32 -> IO CInt
type S2nCertGetUtf8StringFromExtensionData = Ptr Word8 -> Word32 -> Ptr Word8 -> Ptr Word32 -> IO CInt

-- Pre-Shared Keys (PSK)
type S2nExternalPskNew = IO (Ptr S2nPsk)
type S2nPskFree = Ptr (Ptr S2nPsk) -> IO CInt
type S2nPskSetIdentity = Ptr S2nPsk -> Ptr Word8 -> Word16 -> IO CInt
type S2nPskSetSecret = Ptr S2nPsk -> Ptr Word8 -> Word16 -> IO CInt
type S2nPskSetHmac = Ptr S2nPsk -> S2nPskHmac -> IO CInt
type S2nConnectionAppendPsk = Ptr S2nConnection -> Ptr S2nPsk -> IO CInt
type S2nConnectionSetPskMode = Ptr S2nConnection -> S2nPskMode -> IO CInt
type S2nConnectionGetNegotiatedPskIdentityLength = Ptr S2nConnection -> Ptr Word16 -> IO CInt
type S2nConnectionGetNegotiatedPskIdentity = Ptr S2nConnection -> Ptr Word8 -> Word16 -> IO CInt
type S2nOfferedPskNew = IO (Ptr S2nOfferedPsk)
type S2nOfferedPskFree = Ptr (Ptr S2nOfferedPsk) -> IO CInt
type S2nOfferedPskGetIdentity = Ptr S2nOfferedPsk -> Ptr (Ptr Word8) -> Ptr Word16 -> IO CInt
type S2nOfferedPskListHasNext = Ptr S2nOfferedPskList -> IO Bool
type S2nOfferedPskListNext = Ptr S2nOfferedPskList -> Ptr S2nOfferedPsk -> IO CInt
type S2nOfferedPskListReread = Ptr S2nOfferedPskList -> IO CInt
type S2nOfferedPskListChoosePsk = Ptr S2nOfferedPskList -> Ptr S2nOfferedPsk -> IO CInt
type S2nPskConfigureEarlyData = Ptr S2nPsk -> Word32 -> Word8 -> Word8 -> IO CInt
type S2nPskSetApplicationProtocol = Ptr S2nPsk -> Ptr Word8 -> Word8 -> IO CInt
type S2nPskSetEarlyDataContext = Ptr S2nPsk -> Ptr Word8 -> Word16 -> IO CInt

-- Connection Statistics
type S2nConnectionGetWireBytesIn = Ptr S2nConnection -> IO Word64
type S2nConnectionGetWireBytesOut = Ptr S2nConnection -> IO Word64

-- Protocol Version Information
type S2nConnectionGetClientProtocolVersion = Ptr S2nConnection -> IO CInt
type S2nConnectionGetServerProtocolVersion = Ptr S2nConnection -> IO CInt
type S2nConnectionGetActualProtocolVersion = Ptr S2nConnection -> IO CInt
type S2nConnectionGetClientHelloVersion = Ptr S2nConnection -> IO CInt

-- Cipher & Security Information
type S2nConnectionGetCipher = Ptr S2nConnection -> IO CString
type S2nConnectionGetCertificateMatch = Ptr S2nConnection -> Ptr S2nCertSniMatch -> IO CInt
type S2nConnectionGetMasterSecret = Ptr S2nConnection -> Ptr Word8 -> CSize -> IO CInt
type S2nConnectionTlsExporter = Ptr S2nConnection -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> Ptr Word8 -> Word32 -> IO CInt
type S2nConnectionGetCipherIanaValue = Ptr S2nConnection -> Ptr Word8 -> Ptr Word8 -> IO CInt
type S2nConnectionIsValidForCipherPreferences = Ptr S2nConnection -> CString -> IO CInt
type S2nConnectionGetCurve = Ptr S2nConnection -> IO CString
type S2nConnectionGetKemName = Ptr S2nConnection -> IO CString
type S2nConnectionGetKemGroupName = Ptr S2nConnection -> IO CString
type S2nConnectionGetKeyExchangeGroup = Ptr S2nConnection -> Ptr CString -> IO CInt
type S2nConnectionGetAlert = Ptr S2nConnection -> IO CInt
type S2nConnectionGetHandshakeTypeName = Ptr S2nConnection -> IO CString
type S2nConnectionGetLastMessageName = Ptr S2nConnection -> IO CString

-- Async Private Key Operations
type S2nAsyncPkeyOpPerform = Ptr S2nAsyncPkeyOp -> Ptr S2nCertPrivateKey -> IO CInt
type S2nAsyncPkeyOpApply = Ptr S2nAsyncPkeyOp -> Ptr S2nConnection -> IO CInt
type S2nAsyncPkeyOpFree = Ptr S2nAsyncPkeyOp -> IO CInt
type S2nAsyncPkeyOpGetOpType = Ptr S2nAsyncPkeyOp -> Ptr S2nAsyncPkeyOpType -> IO CInt
type S2nAsyncPkeyOpGetInputSize = Ptr S2nAsyncPkeyOp -> Ptr Word32 -> IO CInt
type S2nAsyncPkeyOpGetInput = Ptr S2nAsyncPkeyOp -> Ptr Word8 -> Word32 -> IO CInt
type S2nAsyncPkeyOpSetOutput = Ptr S2nAsyncPkeyOp -> Ptr Word8 -> Word32 -> IO CInt

-- Early Data
type S2nConnectionSetServerMaxEarlyDataSize = Ptr S2nConnection -> Word32 -> IO CInt
type S2nConnectionSetServerEarlyDataContext = Ptr S2nConnection -> Ptr Word8 -> Word16 -> IO CInt
type S2nConnectionGetEarlyDataStatus = Ptr S2nConnection -> Ptr S2nEarlyDataStatus -> IO CInt
type S2nConnectionGetRemainingEarlyDataSize = Ptr S2nConnection -> Ptr Word32 -> IO CInt
type S2nConnectionGetMaxEarlyDataSize = Ptr S2nConnection -> Ptr Word32 -> IO CInt
type S2nSendEarlyData = Ptr S2nConnection -> Ptr Word8 -> CSsize -> Ptr CSsize -> Ptr S2nBlockedStatus -> IO CInt
type S2nRecvEarlyData = Ptr S2nConnection -> Ptr Word8 -> CSsize -> Ptr CSsize -> Ptr S2nBlockedStatus -> IO CInt
type S2nOfferedEarlyDataGetContextLength = Ptr S2nOfferedEarlyData -> Ptr Word16 -> IO CInt
type S2nOfferedEarlyDataGetContext = Ptr S2nOfferedEarlyData -> Ptr Word8 -> Word16 -> IO CInt
type S2nOfferedEarlyDataReject = Ptr S2nOfferedEarlyData -> IO CInt
type S2nOfferedEarlyDataAccept = Ptr S2nOfferedEarlyData -> IO CInt

-- Connection Serialization
type S2nConnectionSerializationLength = Ptr S2nConnection -> Ptr Word32 -> IO CInt
type S2nConnectionSerialize = Ptr S2nConnection -> Ptr Word8 -> Word32 -> IO CInt
type S2nConnectionDeserialize = Ptr S2nConnection -> Ptr Word8 -> Word32 -> IO CInt

--------------------------------------------------------------------------------
-- S2nTlsSys Record
--------------------------------------------------------------------------------

-- | A record containing all FFI bindings to the s2n-tls library.
--
-- This record can be populated either via linked symbols (see
-- "S2nTls.Sys.Linked") or via dynamic loading (see "S2nTls.Sys.Dynamic").
data S2nTlsSys = S2nTlsSys
    { -- Initialization & Cleanup
      s2n_init :: S2nInit
    , s2n_cleanup :: S2nCleanup
    , s2n_cleanup_final :: S2nCleanupFinal
    , s2n_crypto_disable_init :: S2nCryptoDisableInit
    , s2n_disable_atexit :: S2nDisableAtexit
    , s2n_get_openssl_version :: S2nGetOpensslVersion
    , s2n_get_fips_mode :: S2nGetFipsMode

      -- Error Handling
    , s2n_errno_location :: S2nErrnoLocation
    , s2n_error_get_type :: S2nErrorGetType
    , s2n_strerror :: S2nStrerror
    , s2n_strerror_debug :: S2nStrerrorDebug
    , s2n_strerror_name :: S2nStrerrorName
    , s2n_strerror_source :: S2nStrerrorSource

      -- Stack Traces
    , s2n_stack_traces_enabled :: S2nStackTracesEnabled
    , s2n_stack_traces_enabled_set :: S2nStackTracesEnabledSet
    , s2n_calculate_stacktrace :: S2nCalculateStacktrace
    , s2n_free_stacktrace :: S2nFreeStacktrace
    , s2n_get_stacktrace :: S2nGetStacktrace

      -- Config Management
    , s2n_config_new :: S2nConfigNew
    , s2n_config_new_minimal :: S2nConfigNewMinimal
    , s2n_config_free :: S2nConfigFree
    , s2n_config_free_dhparams :: S2nConfigFreeDhparams
    , s2n_config_free_cert_chain_and_key :: S2nConfigFreeCertChainAndKey
    , s2n_config_set_wall_clock :: S2nConfigSetWallClock
    , s2n_config_set_monotonic_clock :: S2nConfigSetMonotonicClock

      -- Cache Callbacks
    , s2n_config_set_cache_store_callback :: S2nConfigSetCacheStoreCallback
    , s2n_config_set_cache_retrieve_callback :: S2nConfigSetCacheRetrieveCallback
    , s2n_config_set_cache_delete_callback :: S2nConfigSetCacheDeleteCallback

      -- Memory & Random Callbacks
    , s2n_mem_set_callbacks :: S2nMemSetCallbacks
    , s2n_rand_set_callbacks :: S2nRandSetCallbacks

      -- Certificate Chain Management
    , s2n_cert_chain_and_key_new :: S2nCertChainAndKeyNew
    , s2n_cert_chain_and_key_load_pem :: S2nCertChainAndKeyLoadPem
    , s2n_cert_chain_and_key_load_pem_bytes :: S2nCertChainAndKeyLoadPemBytes
    , s2n_cert_chain_and_key_load_public_pem_bytes :: S2nCertChainAndKeyLoadPublicPemBytes
    , s2n_cert_chain_and_key_free :: S2nCertChainAndKeyFree
    , s2n_cert_chain_and_key_set_ctx :: S2nCertChainAndKeySetCtx
    , s2n_cert_chain_and_key_get_ctx :: S2nCertChainAndKeyGetCtx
    , s2n_cert_chain_and_key_get_private_key :: S2nCertChainAndKeyGetPrivateKey
    , s2n_cert_chain_and_key_set_ocsp_data :: S2nCertChainAndKeySetOcspData
    , s2n_cert_chain_and_key_set_sct_list :: S2nCertChainAndKeySetSctList
    , s2n_config_set_cert_tiebreak_callback :: S2nConfigSetCertTiebreakCallback
    , s2n_config_add_cert_chain_and_key :: S2nConfigAddCertChainAndKey
    , s2n_config_add_cert_chain_and_key_to_store :: S2nConfigAddCertChainAndKeyToStore
    , s2n_config_set_cert_chain_and_key_defaults :: S2nConfigSetCertChainAndKeyDefaults

      -- Trust Store
    , s2n_config_set_verification_ca_location :: S2nConfigSetVerificationCaLocation
    , s2n_config_add_pem_to_trust_store :: S2nConfigAddPemToTrustStore
    , s2n_config_wipe_trust_store :: S2nConfigWipeTrustStore
    , s2n_config_load_system_certs :: S2nConfigLoadSystemCerts
    , s2n_config_set_cert_authorities_from_trust_store :: S2nConfigSetCertAuthoritiesFromTrustStore

      -- Verification & Validation
    , s2n_config_set_verify_after_sign :: S2nConfigSetVerifyAfterSign
    , s2n_config_set_check_stapled_ocsp_response :: S2nConfigSetCheckStapledOcspResponse
    , s2n_config_disable_x509_time_verification :: S2nConfigDisableX509TimeVerification
    , s2n_config_disable_x509_intent_verification :: S2nConfigDisableX509IntentVerification
    , s2n_config_disable_x509_verification :: S2nConfigDisableX509Verification
    , s2n_config_set_max_cert_chain_depth :: S2nConfigSetMaxCertChainDepth
    , s2n_config_set_verify_host_callback :: S2nConfigSetVerifyHostCallback

      -- DH Parameters
    , s2n_config_add_dhparams :: S2nConfigAddDhparams

      -- Security Policies & Preferences
    , s2n_config_set_cipher_preferences :: S2nConfigSetCipherPreferences
    , s2n_config_append_protocol_preference :: S2nConfigAppendProtocolPreference
    , s2n_config_set_protocol_preferences :: S2nConfigSetProtocolPreferences
    , s2n_config_set_status_request_type :: S2nConfigSetStatusRequestType
    , s2n_config_set_ct_support_level :: S2nConfigSetCtSupportLevel
    , s2n_config_set_alert_behavior :: S2nConfigSetAlertBehavior

      -- Extension Data
    , s2n_config_set_extension_data :: S2nConfigSetExtensionData
    , s2n_config_send_max_fragment_length :: S2nConfigSendMaxFragmentLength
    , s2n_config_accept_max_fragment_length :: S2nConfigAcceptMaxFragmentLength

      -- Session & Ticket Configuration
    , s2n_config_set_session_state_lifetime :: S2nConfigSetSessionStateLifetime
    , s2n_config_set_session_tickets_onoff :: S2nConfigSetSessionTicketsOnoff
    , s2n_config_set_session_cache_onoff :: S2nConfigSetSessionCacheOnoff
    , s2n_config_set_ticket_encrypt_decrypt_key_lifetime :: S2nConfigSetTicketEncryptDecryptKeyLifetime
    , s2n_config_set_ticket_decrypt_key_lifetime :: S2nConfigSetTicketDecryptKeyLifetime
    , s2n_config_add_ticket_crypto_key :: S2nConfigAddTicketCryptoKey
    , s2n_config_require_ticket_forward_secrecy :: S2nConfigRequireTicketForwardSecrecy

      -- Buffer & I/O Configuration
    , s2n_config_set_send_buffer_size :: S2nConfigSetSendBufferSize
    , s2n_config_set_recv_multi_record :: S2nConfigSetRecvMultiRecord

      -- Miscellaneous Config
    , s2n_config_set_ctx :: S2nConfigSetCtx
    , s2n_config_get_ctx :: S2nConfigGetCtx
    , s2n_config_set_client_hello_cb :: S2nConfigSetClientHelloCb
    , s2n_config_set_client_hello_cb_mode :: S2nConfigSetClientHelloCbMode
    , s2n_config_set_max_blinding_delay :: S2nConfigSetMaxBlindingDelay
    , s2n_config_get_client_auth_type :: S2nConfigGetClientAuthType
    , s2n_config_set_client_auth_type :: S2nConfigSetClientAuthType
    , s2n_config_set_initial_ticket_count :: S2nConfigSetInitialTicketCount
    , s2n_config_set_psk_mode :: S2nConfigSetPskMode
    , s2n_config_set_psk_selection_callback :: S2nConfigSetPskSelectionCallback
    , s2n_config_set_async_pkey_callback :: S2nConfigSetAsyncPkeyCallback
    , s2n_config_set_async_pkey_validation_mode :: S2nConfigSetAsyncPkeyValidationMode
    , s2n_config_set_session_ticket_cb :: S2nConfigSetSessionTicketCb
    , s2n_config_set_key_log_cb :: S2nConfigSetKeyLogCb
    , s2n_config_enable_cert_req_dss_legacy_compat :: S2nConfigEnableCertReqDssLegacyCompat
    , s2n_config_set_server_max_early_data_size :: S2nConfigSetServerMaxEarlyDataSize
    , s2n_config_set_early_data_cb :: S2nConfigSetEarlyDataCb
    , s2n_config_get_supported_groups :: S2nConfigGetSupportedGroups
    , s2n_config_set_serialization_version :: S2nConfigSetSerializationVersion

      -- Connection Creation & Management
    , s2n_connection_new :: S2nConnectionNew
    , s2n_connection_set_config :: S2nConnectionSetConfig
    , s2n_connection_set_ctx :: S2nConnectionSetCtx
    , s2n_connection_get_ctx :: S2nConnectionGetCtx
    , s2n_client_hello_cb_done :: S2nClientHelloCbDone
    , s2n_connection_server_name_extension_used :: S2nConnectionServerNameExtensionUsed

      -- Client Hello Access
    , s2n_connection_get_client_hello :: S2nConnectionGetClientHello
    , s2n_client_hello_parse_message :: S2nClientHelloParseMessage
    , s2n_client_hello_free :: S2nClientHelloFree
    , s2n_client_hello_get_raw_message_length :: S2nClientHelloGetRawMessageLength
    , s2n_client_hello_get_raw_message :: S2nClientHelloGetRawMessage
    , s2n_client_hello_get_cipher_suites_length :: S2nClientHelloGetCipherSuitesLength
    , s2n_client_hello_get_cipher_suites :: S2nClientHelloGetCipherSuites
    , s2n_client_hello_get_extensions_length :: S2nClientHelloGetExtensionsLength
    , s2n_client_hello_get_extensions :: S2nClientHelloGetExtensions
    , s2n_client_hello_get_extension_length :: S2nClientHelloGetExtensionLength
    , s2n_client_hello_get_extension_by_id :: S2nClientHelloGetExtensionById
    , s2n_client_hello_has_extension :: S2nClientHelloHasExtension
    , s2n_client_hello_get_session_id_length :: S2nClientHelloGetSessionIdLength
    , s2n_client_hello_get_session_id :: S2nClientHelloGetSessionId
    , s2n_client_hello_get_compression_methods_length :: S2nClientHelloGetCompressionMethodsLength
    , s2n_client_hello_get_compression_methods :: S2nClientHelloGetCompressionMethods
    , s2n_client_hello_get_legacy_protocol_version :: S2nClientHelloGetLegacyProtocolVersion
    , s2n_client_hello_get_random :: S2nClientHelloGetRandom
    , s2n_client_hello_get_supported_groups :: S2nClientHelloGetSupportedGroups
    , s2n_client_hello_get_server_name_length :: S2nClientHelloGetServerNameLength
    , s2n_client_hello_get_server_name :: S2nClientHelloGetServerName
    , s2n_client_hello_get_legacy_record_version :: S2nClientHelloGetLegacyRecordVersion

      -- File Descriptor & I/O
    , s2n_connection_set_fd :: S2nConnectionSetFd
    , s2n_connection_set_read_fd :: S2nConnectionSetReadFd
    , s2n_connection_set_write_fd :: S2nConnectionSetWriteFd
    , s2n_connection_get_read_fd :: S2nConnectionGetReadFd
    , s2n_connection_get_write_fd :: S2nConnectionGetWriteFd
    , s2n_connection_use_corked_io :: S2nConnectionUseCorkedIo
    , s2n_connection_set_recv_ctx :: S2nConnectionSetRecvCtx
    , s2n_connection_set_send_ctx :: S2nConnectionSetSendCtx
    , s2n_connection_set_recv_cb :: S2nConnectionSetRecvCb
    , s2n_connection_set_send_cb :: S2nConnectionSetSendCb

      -- Connection Preferences
    , s2n_connection_prefer_throughput :: S2nConnectionPreferThroughput
    , s2n_connection_prefer_low_latency :: S2nConnectionPreferLowLatency
    , s2n_connection_set_recv_buffering :: S2nConnectionSetRecvBuffering
    , s2n_peek_buffered :: S2nPeekBuffered
    , s2n_connection_set_dynamic_buffers :: S2nConnectionSetDynamicBuffers
    , s2n_connection_set_dynamic_record_threshold :: S2nConnectionSetDynamicRecordThreshold

      -- Host Verification
    , s2n_connection_set_verify_host_callback :: S2nConnectionSetVerifyHostCallback

      -- Blinding & Security
    , s2n_connection_set_blinding :: S2nConnectionSetBlinding
    , s2n_connection_get_delay :: S2nConnectionGetDelay

      -- Cipher & Protocol Configuration
    , s2n_connection_set_cipher_preferences :: S2nConnectionSetCipherPreferences
    , s2n_connection_request_key_update :: S2nConnectionRequestKeyUpdate
    , s2n_connection_append_protocol_preference :: S2nConnectionAppendProtocolPreference
    , s2n_connection_set_protocol_preferences :: S2nConnectionSetProtocolPreferences

      -- Server Name (SNI)
    , s2n_set_server_name :: S2nSetServerName
    , s2n_get_server_name :: S2nGetServerName

      -- Application Protocol (ALPN)
    , s2n_get_application_protocol :: S2nGetApplicationProtocol

      -- OCSP & Certificate Transparency
    , s2n_connection_get_ocsp_response :: S2nConnectionGetOcspResponse
    , s2n_connection_get_sct_list :: S2nConnectionGetSctList

      -- Handshake & TLS Operations
    , s2n_negotiate :: S2nNegotiate
    , s2n_send :: S2nSend
    , s2n_recv :: S2nRecv
    , s2n_peek :: S2nPeek
    , s2n_connection_free_handshake :: S2nConnectionFreeHandshake
    , s2n_connection_release_buffers :: S2nConnectionReleaseBuffers
    , s2n_connection_wipe :: S2nConnectionWipe
    , s2n_connection_free :: S2nConnectionFree
    , s2n_shutdown :: S2nShutdown
    , s2n_shutdown_send :: S2nShutdownSend

      -- Client Authentication
    , s2n_connection_get_client_auth_type :: S2nConnectionGetClientAuthType
    , s2n_connection_set_client_auth_type :: S2nConnectionSetClientAuthType
    , s2n_connection_get_client_cert_chain :: S2nConnectionGetClientCertChain
    , s2n_connection_client_cert_used :: S2nConnectionClientCertUsed

      -- Session Management
    , s2n_connection_add_new_tickets_to_send :: S2nConnectionAddNewTicketsToSend
    , s2n_connection_get_tickets_sent :: S2nConnectionGetTicketsSent
    , s2n_connection_set_server_keying_material_lifetime :: S2nConnectionSetServerKeyingMaterialLifetime
    , s2n_session_ticket_get_data_len :: S2nSessionTicketGetDataLen
    , s2n_session_ticket_get_data :: S2nSessionTicketGetData
    , s2n_session_ticket_get_lifetime :: S2nSessionTicketGetLifetime
    , s2n_connection_set_session :: S2nConnectionSetSession
    , s2n_connection_get_session :: S2nConnectionGetSession
    , s2n_connection_get_session_ticket_lifetime_hint :: S2nConnectionGetSessionTicketLifetimeHint
    , s2n_connection_get_session_length :: S2nConnectionGetSessionLength
    , s2n_connection_get_session_id_length :: S2nConnectionGetSessionIdLength
    , s2n_connection_get_session_id :: S2nConnectionGetSessionId
    , s2n_connection_is_session_resumed :: S2nConnectionIsSessionResumed

      -- Certificate Information
    , s2n_connection_is_ocsp_stapled :: S2nConnectionIsOcspStapled
    , s2n_connection_get_selected_signature_algorithm :: S2nConnectionGetSelectedSignatureAlgorithm
    , s2n_connection_get_selected_digest_algorithm :: S2nConnectionGetSelectedDigestAlgorithm
    , s2n_connection_get_selected_client_cert_signature_algorithm :: S2nConnectionGetSelectedClientCertSignatureAlgorithm
    , s2n_connection_get_selected_client_cert_digest_algorithm :: S2nConnectionGetSelectedClientCertDigestAlgorithm
    , s2n_connection_get_signature_scheme :: S2nConnectionGetSignatureScheme
    , s2n_connection_get_selected_cert :: S2nConnectionGetSelectedCert
    , s2n_cert_chain_get_length :: S2nCertChainGetLength
    , s2n_cert_chain_get_cert :: S2nCertChainGetCert
    , s2n_cert_get_der :: S2nCertGetDer
    , s2n_connection_get_peer_cert_chain :: S2nConnectionGetPeerCertChain
    , s2n_cert_get_x509_extension_value_length :: S2nCertGetX509ExtensionValueLength
    , s2n_cert_get_x509_extension_value :: S2nCertGetX509ExtensionValue
    , s2n_cert_get_utf8_string_from_extension_data_length :: S2nCertGetUtf8StringFromExtensionDataLength
    , s2n_cert_get_utf8_string_from_extension_data :: S2nCertGetUtf8StringFromExtensionData

      -- Pre-Shared Keys (PSK)
    , s2n_external_psk_new :: S2nExternalPskNew
    , s2n_psk_free :: S2nPskFree
    , s2n_psk_set_identity :: S2nPskSetIdentity
    , s2n_psk_set_secret :: S2nPskSetSecret
    , s2n_psk_set_hmac :: S2nPskSetHmac
    , s2n_connection_append_psk :: S2nConnectionAppendPsk
    , s2n_connection_set_psk_mode :: S2nConnectionSetPskMode
    , s2n_connection_get_negotiated_psk_identity_length :: S2nConnectionGetNegotiatedPskIdentityLength
    , s2n_connection_get_negotiated_psk_identity :: S2nConnectionGetNegotiatedPskIdentity
    , s2n_offered_psk_new :: S2nOfferedPskNew
    , s2n_offered_psk_free :: S2nOfferedPskFree
    , s2n_offered_psk_get_identity :: S2nOfferedPskGetIdentity
    , s2n_offered_psk_list_has_next :: S2nOfferedPskListHasNext
    , s2n_offered_psk_list_next :: S2nOfferedPskListNext
    , s2n_offered_psk_list_reread :: S2nOfferedPskListReread
    , s2n_offered_psk_list_choose_psk :: S2nOfferedPskListChoosePsk
    , s2n_psk_configure_early_data :: S2nPskConfigureEarlyData
    , s2n_psk_set_application_protocol :: S2nPskSetApplicationProtocol
    , s2n_psk_set_early_data_context :: S2nPskSetEarlyDataContext

      -- Connection Statistics
    , s2n_connection_get_wire_bytes_in :: S2nConnectionGetWireBytesIn
    , s2n_connection_get_wire_bytes_out :: S2nConnectionGetWireBytesOut

      -- Protocol Version Information
    , s2n_connection_get_client_protocol_version :: S2nConnectionGetClientProtocolVersion
    , s2n_connection_get_server_protocol_version :: S2nConnectionGetServerProtocolVersion
    , s2n_connection_get_actual_protocol_version :: S2nConnectionGetActualProtocolVersion
    , s2n_connection_get_client_hello_version :: S2nConnectionGetClientHelloVersion

      -- Cipher & Security Information
    , s2n_connection_get_cipher :: S2nConnectionGetCipher
    , s2n_connection_get_certificate_match :: S2nConnectionGetCertificateMatch
    , s2n_connection_get_master_secret :: S2nConnectionGetMasterSecret
    , s2n_connection_tls_exporter :: S2nConnectionTlsExporter
    , s2n_connection_get_cipher_iana_value :: S2nConnectionGetCipherIanaValue
    , s2n_connection_is_valid_for_cipher_preferences :: S2nConnectionIsValidForCipherPreferences
    , s2n_connection_get_curve :: S2nConnectionGetCurve
    , s2n_connection_get_kem_name :: S2nConnectionGetKemName
    , s2n_connection_get_kem_group_name :: S2nConnectionGetKemGroupName
    , s2n_connection_get_key_exchange_group :: S2nConnectionGetKeyExchangeGroup
    , s2n_connection_get_alert :: S2nConnectionGetAlert
    , s2n_connection_get_handshake_type_name :: S2nConnectionGetHandshakeTypeName
    , s2n_connection_get_last_message_name :: S2nConnectionGetLastMessageName

      -- Async Private Key Operations
    , s2n_async_pkey_op_perform :: S2nAsyncPkeyOpPerform
    , s2n_async_pkey_op_apply :: S2nAsyncPkeyOpApply
    , s2n_async_pkey_op_free :: S2nAsyncPkeyOpFree
    , s2n_async_pkey_op_get_op_type :: S2nAsyncPkeyOpGetOpType
    , s2n_async_pkey_op_get_input_size :: S2nAsyncPkeyOpGetInputSize
    , s2n_async_pkey_op_get_input :: S2nAsyncPkeyOpGetInput
    , s2n_async_pkey_op_set_output :: S2nAsyncPkeyOpSetOutput

      -- Early Data
    , s2n_connection_set_server_max_early_data_size :: S2nConnectionSetServerMaxEarlyDataSize
    , s2n_connection_set_server_early_data_context :: S2nConnectionSetServerEarlyDataContext
    , s2n_connection_get_early_data_status :: S2nConnectionGetEarlyDataStatus
    , s2n_connection_get_remaining_early_data_size :: S2nConnectionGetRemainingEarlyDataSize
    , s2n_connection_get_max_early_data_size :: S2nConnectionGetMaxEarlyDataSize
    , s2n_send_early_data :: S2nSendEarlyData
    , s2n_recv_early_data :: S2nRecvEarlyData
    , s2n_offered_early_data_get_context_length :: S2nOfferedEarlyDataGetContextLength
    , s2n_offered_early_data_get_context :: S2nOfferedEarlyDataGetContext
    , s2n_offered_early_data_reject :: S2nOfferedEarlyDataReject
    , s2n_offered_early_data_accept :: S2nOfferedEarlyDataAccept

      -- Connection Serialization
    , s2n_connection_serialization_length :: S2nConnectionSerializationLength
    , s2n_connection_serialize :: S2nConnectionSerialize
    , s2n_connection_deserialize :: S2nConnectionDeserialize
    }
