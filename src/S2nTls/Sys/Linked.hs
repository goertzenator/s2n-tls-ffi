{- |
Module      : S2nTls.Sys.Linked
Description : Statically linked bindings to s2n-tls
License     : BSD-3-Clause

This module provides s2n-tls bindings for executables that link
against s2n-tls at compile time.

Use 'withLinkedTlsSys' to obtain a 'S2nTlsSys' record that uses
symbols from the already-linked executable (via dlopen(NULL)).
-}
module S2nTls.Sys.Linked (
    withLinkedTlsSys,
) where

import S2nTls.Sys.Dynamic (withDynamicTlsSys)
import S2nTls.Sys.Types (S2nTlsSys)

{- | Provide a 'S2nTlsSys' record using symbols from the currently
linked executable. This is useful when s2n-tls is linked statically
or dynamically at compile time.

The callback is guaranteed to have access to the symbols for the
duration of its execution. Uses dlopen(NULL) internally.

@
withLinkedTlsSys $ \\sys -> do
    -- use sys here
    result <- s2n_init sys
    ...
@
-}
withLinkedTlsSys ::
    -- | Callback that receives the populated 'S2nTlsSys' record
    (S2nTlsSys -> IO a) ->
    IO a
withLinkedTlsSys = withDynamicTlsSys ""
