# s2n-tls-sys

Low-level FFI bindings to the [s2n-tls](https://github.com/aws/s2n-tls) library.

This package follows the Rust convention of "sys" packages that provide raw FFI bindings which higher-level packages can build upon.

## Features

- **Linked bindings** (`-flinked`, default): Link against the system s2n-tls library at compile time via `getLinkedTlsSys`.
- **Dynamic bindings** (`-fdynamic`): Load s2n-tls at runtime via `dlopen` using `withDynamicTlsSys`.  The use case for this is if you need to switch between FIPS and non-FIPS crypto backends at runtime.

## Usage

### Linked bindings

```haskell
import S2nTls.Sys

main :: IO ()
main = do
    let sys = getLinkedTlsSys
    -- use sys...
```

### Dynamic bindings

Build with `-fdynamic`:

```haskell
import S2nTls.Sys

main :: IO ()
main = withDynamicTlsSys "libs2n.so" $ \sys -> do
    -- use sys...
```

## Adding as a Dependency

In your package's `.cabal` file:

```cabal
build-depends:
    s2n-tls-sys
```

Configure flags in your `cabal.project`:

```cabal
-- Linked bindings (default)
package s2n-tls-sys
  flags: +linked

-- Dynamic bindings
package s2n-tls-sys
  flags: +dynamic

-- Both
package s2n-tls-sys
  flags: +linked +dynamic
```

The `linked` flag requires the s2n-tls library to be installed on your system (via pkg-config).

## License

BSD-3-Clause
