# s2n-tls-sys

Low-level FFI bindings to the [s2n-tls](https://github.com/aws/s2n-tls) library.

This package follows the Rust convention of "sys" packages that provide raw FFI bindings which higher-level packages can build upon.

## Loading Modes

### Linked Bindings

Use `withLinkedTlsSys` when s2n-tls is linked into your executable at compile time. This uses `dlopen(NULL)` to resolve symbols from the running process.

```haskell
import S2nTls.Sys

main :: IO ()
main = withLinkedTlsSys $ \sys -> do
    -- use sys...
```

### Dynamic Bindings

Use `withDynamicTlsSys` to load s2n-tls at runtime via `dlopen`. This enables runtime selection of different library builds - for example, switching between FIPS and non-FIPS crypto backends without recompiling your application.

```haskell
import S2nTls.Sys

main :: IO ()
main = do
    let libPath = if needFips then "libs2n-fips.so" else "libs2n.so"
    withDynamicTlsSys libPath $ \sys -> do
        -- use sys...
```

## Error Handling via C Wrappers

s2n-tls stores error information in thread-local storage (TLS). When a function fails, the error code and debug message are available via `s2n_errno_location()` and `s2n_strerror_debug()`. However, Haskell's FFI provides no guarantee that a subsequent call will execute on the same OS thread, making direct access to thread-local error state unreliable.

To solve this, most s2n functions are called through thin C wrappers that:

1. Call the underlying s2n function
2. If it fails, immediately read the error code and debug string from TLS
3. Copy this information into an output struct with an owned 256-byte buffer
4. Return to Haskell with the error information safely captured

This ensures error information is captured in the same C stack frame before control returns to Haskell. The `S2nTlsSys` record exposes these wrapped functions, which return `Either S2nError result` for functions that can fail.

Note that `s2n_send` and `s2n_recv` have special behavior: if the error was `S2N_ERR_T_BLOCKED`, debug info is not captured because this is a frequent, expected case that doesn't need debug overhead.

### Direct Error Functions

The `s2n_strerror` and `s2n_strerror_name` functions are **not** subject to thread-local storage limitations - they take an error code as input and return static strings. These can be called directly without wrappers if you need to format error messages yourself.

## Missing Symbol Behavior

Symbol loading is forgiving - missing symbols don't cause failure at load time. This allows the bindings to work with different versions of s2n-tls that may not export all functions.

- The `missingSymbols` field of `S2nTlsSys` lists symbol names that couldn't be loaded
- Calling a function for a missing symbol throws a `MissingSymbol` exception
- Check `missingSymbols` at startup if your application requires specific functions

## Tests

The `memory-safety` test suite invokes all FFI functions to detect segfaults and memory errors. It does not verify correct behavior - only that calling each function doesn't crash. Each function name is printed before invocation, so if a crash occurs you can identify the culprit.

Run with:

```
cabal test memory-safety
```

## License

BSD-3-Clause
