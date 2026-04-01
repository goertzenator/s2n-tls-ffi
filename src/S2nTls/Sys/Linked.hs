-- |
-- Module      : S2nTls.Sys.Linked
-- Description : Linked symbol bindings to s2n-tls
-- License     : BSD-3-Clause
--
-- This module provides s2n-tls bindings via statically linked symbols.
-- It is only available when the package is built with the @linked@ flag.
--
-- Use 'getLinkedTlsSys' to obtain a 'S2nTlsSys' record populated with
-- function pointers from the linked library.
module S2nTls.Sys.Linked
    ( getLinkedTlsSys
    ) where

import S2nTls.Sys.Types (S2nTlsSys (..))

-- Foreign imports for linked symbols will be added here.
-- Example:
-- foreign import ccall "s2n_init" c_s2n_init :: IO CInt
-- foreign import ccall "s2n_cleanup" c_s2n_cleanup :: IO CInt

-- | Obtain the 'S2nTlsSys' record populated with function pointers
-- from the linked s2n-tls library.
--
-- This function is pure because the linked symbols are resolved at
-- load time and do not change.
getLinkedTlsSys :: S2nTlsSys
getLinkedTlsSys = S2nTlsSys
    {
    -- Populate fields with foreign imported functions here.
    -- Example:
    -- s2n_init = c_s2n_init
    -- s2n_cleanup = c_s2n_cleanup
    }
