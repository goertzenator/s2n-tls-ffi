# Changelog

## 0.2.0.0 -- 2026-09-08

Corrects four FFI signatures that did not match the s2n-tls C API. These were
found by auditing all 245 wrapped functions against the s2n-tls 1.6.4 header.
`cbits/s2n_wrapper.c` does not include `s2n.h`, so none of them were caught at
compile time.

### Breaking changes

* `s2n_client_hello_has_extension` and `s2n_cert_get_x509_extension_value` take
  `Ptr CBool` for their `bool *` out-parameters, previously `Ptr CInt`. s2n
  writes a single byte, so callers that allocated a `CInt` read three bytes of
  uninitialized memory and could see a nonzero result for an absent extension.
  Callers must switch to `alloca @CBool`.
* `S2nCertTiebreakCallback` is now
  `Ptr S2nCertChainAndKey -> Ptr S2nCertChainAndKey -> Ptr Word8 -> Word32 -> IO (Ptr S2nCertChainAndKey)`.
  The previous type took the certificate name by value instead of by pointer,
  took the name length by pointer instead of by value, and returned `CInt`
  where s2n expects a certificate chain pointer. Installing a tiebreak callback
  built against the old type would have crashed.
* `S2nMemMallocCallback` takes `Ptr Word32` for its `allocated` out-parameter,
  previously `Word32`. A custom allocator had no way to report its allocation
  size back to s2n.

### Fixed

* Missing optional symbols are recorded in `missingSymbols` again. `dlsym`
  throws an `IOError` for an absent symbol rather than returning `nullFunPtr`,
  which made the null checks in the loader dead code -- a missing optional
  symbol escaped `withS2nTlsFfi` as an opaque `user error` and `missingSymbols`
  could never report anything but `[]`.
* A missing error-reporting symbol now raises the typed `RequiredSymbolNotFound`
  instead of an untyped `IOError`.

## 0.1.0.0 -- 2026-04-28

* Initial release
* Support for linked and dynamic loading via `Library` type
