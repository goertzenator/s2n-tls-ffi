-- |
-- Module      : S2nTls.Sys
-- Description : Low-level FFI bindings to the s2n-tls library
-- License     : BSD-3-Clause
--
-- This module provides low-level FFI bindings to the s2n-tls library,
-- following the Rust convention of "sys" packages for raw bindings.
--
-- The core type is 'S2nTlsSys', a record containing all FFI function
-- pointers. This record can be obtained in two ways:
--
-- * 'withLinkedTlsSys': For executables that link s2n-tls at compile time.
--   Uses dlopen(NULL) to load symbols from the running executable.
--
-- * 'withDynamicTlsSys': To load the library at runtime via dlopen.
--   Pass the path to libs2n.so.
--
-- Both methods use C wrappers to safely capture error information
-- (including TLS-dependent error strings) in the same C stack frame,
-- avoiding thread-local storage issues in Haskell FFI.
--
-- Symbol loading is forgiving - missing symbols don't cause failure
-- at load time. Instead, calling a missing symbol throws 'MissingSymbol'.
-- Check the 'missingSymbols' field to see which symbols weren't found.
module S2nTls.Sys
    ( -- * Core Types
      S2nTlsSys (..)

      -- * Linked Bindings
    , withLinkedTlsSys

      -- * Dynamic Bindings
    , withDynamicTlsSys
    , DynamicLoadError (..)

      -- * Error Types
    , MissingSymbol (..)
    , S2nError (..)
    , S2nErrorFuncs (..)
    ) where

import S2nTls.Sys.Types (S2nTlsSys (..), S2nError (..), S2nErrorFuncs (..), MissingSymbol (..))
import S2nTls.Sys.Linked (withLinkedTlsSys)
import S2nTls.Sys.Dynamic (DynamicLoadError (..), withDynamicTlsSys)
