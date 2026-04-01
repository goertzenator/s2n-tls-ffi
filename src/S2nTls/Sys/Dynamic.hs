-- |
-- Module      : S2nTls.Sys.Dynamic
-- Description : Dynamic loading bindings to s2n-tls
-- License     : BSD-3-Clause
--
-- This module provides s2n-tls bindings via dynamic loading (dlopen).
-- It is only available when the package is built with the @dynamic@ flag.
--
-- Use 'withDynamicTlsSys' to load the s2n-tls library at runtime and
-- obtain a 'S2nTlsSys' record populated with dynamically resolved
-- function pointers.
module S2nTls.Sys.Dynamic
    ( withDynamicTlsSys
    , DynamicLoadError (..)
    ) where

import Control.Exception (Exception, bracket, throwIO)
import System.Posix.DynamicLinker
    ( DL
    , RTLDFlags (RTLD_LAZY, RTLD_LOCAL)
    , dlclose
    , dlopen
    , dlsym
    )

import S2nTls.Sys.Types (S2nTlsSys (..))

-- | Errors that can occur when dynamically loading the s2n-tls library.
data DynamicLoadError
    = LibraryNotFound FilePath
    | SymbolNotFound String
    deriving (Show, Eq)

instance Exception DynamicLoadError

-- | Load the s2n-tls library dynamically and provide a 'S2nTlsSys' record
-- to the given callback. The library is automatically unloaded when the
-- callback returns (or throws an exception).
--
-- @
-- withDynamicTlsSys "libs2n.so" $ \\sys -> do
--     -- use sys here
-- @
withDynamicTlsSys
    :: FilePath
    -- ^ Path to the s2n-tls shared library (e.g., "libs2n.so")
    -> (S2nTlsSys -> IO a)
    -- ^ Callback that receives the populated 'S2nTlsSys' record
    -> IO a
withDynamicTlsSys libPath action =
    bracket (dlopen libPath [RTLD_LAZY, RTLD_LOCAL]) dlclose $ \dl -> do
        sys <- loadSymbols dl
        action sys

-- | Load all s2n-tls symbols from the given dynamic library handle.
loadSymbols :: DL -> IO S2nTlsSys
loadSymbols _dl = do
    -- Symbol loading will be implemented here.
    -- Example:
    -- initPtr <- dlsym dl "s2n_init"
    -- cleanupPtr <- dlsym dl "s2n_cleanup"
    -- let s2n_init = mkS2nInit initPtr
    --     s2n_cleanup = mkS2nCleanup cleanupPtr
    pure S2nTlsSys
        {
        -- Populate fields with dynamically loaded functions here.
        }

-- Foreign import "dynamic" declarations will be added here to convert
-- function pointers to Haskell functions.
-- Example:
-- foreign import ccall "dynamic"
--     mkS2nInit :: FunPtr (IO CInt) -> IO CInt
