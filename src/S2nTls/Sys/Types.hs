-- |
-- Module      : S2nTls.Sys.Types
-- Description : Core types for s2n-tls FFI bindings
-- License     : BSD-3-Clause
--
-- This module defines the core types used by the s2n-tls FFI bindings,
-- including the 'S2nTlsSys' record that contains all FFI function pointers.
module S2nTls.Sys.Types
    ( S2nTlsSys (..)
    ) where

-- | A record containing all FFI bindings to the s2n-tls library.
--
-- This record can be populated either via linked symbols (see
-- "S2nTls.Sys.Linked") or via dynamic loading (see "S2nTls.Sys.Dynamic").
--
-- Each field corresponds to a function from the s2n-tls C API.
data S2nTlsSys = S2nTlsSys
    {
    -- FFI function fields will be added here as the bindings are implemented.
    -- Example fields (to be replaced with actual bindings):
    -- s2n_init :: IO CInt
    -- s2n_cleanup :: IO CInt
    -- s2n_config_new :: IO (Ptr S2nConfig)
    -- etc.
    }
