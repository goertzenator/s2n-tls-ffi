{-# LANGUAGE CPP #-}

-- |
-- Module      : S2nTls.Sys
-- Description : Low-level FFI bindings to the s2n-tls library
-- License     : BSD-3-Clause
--
-- This module provides low-level FFI bindings to the s2n-tls library,
-- following the Rust convention of "sys" packages for raw bindings.
--
-- The core type is 'S2nTlsSys', a record containing all FFI function
-- pointers. This record can be obtained in two ways depending on which
-- cabal flags are enabled:
--
-- * @linked@ flag: Provides 'getLinkedTlsSys' for statically linked bindings.
--
-- * @dynamic@ flag: Provides 'withDynamicTlsSys' to load the library at
--   runtime via dlopen.
module S2nTls.Sys
    ( -- * Core Types
      S2nTlsSys (..)

#ifdef S2N_TLS_SYS_LINKED
      -- * Linked Bindings
    , getLinkedTlsSys
#endif

#ifdef S2N_TLS_SYS_DYNAMIC
      -- * Dynamic Bindings
    , withDynamicTlsSys
    , DynamicLoadError (..)
#endif
    ) where

import S2nTls.Sys.Types (S2nTlsSys (..))

#ifdef S2N_TLS_SYS_LINKED
import S2nTls.Sys.Linked (getLinkedTlsSys)
#endif

#ifdef S2N_TLS_SYS_DYNAMIC
import S2nTls.Sys.Dynamic (DynamicLoadError (..), withDynamicTlsSys)
#endif
