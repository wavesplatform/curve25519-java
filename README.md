# curve25519-java

Curve25519 for Java: X25519 key agreement, XEdDSA signatures and VXEdDSA verifiable random
functions, compatible with Signal's libsignal implementation. Requires Java 17+.

The native provider is a small Rust library on top of
[curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) and
[RustCrypto sha2](https://github.com/RustCrypto/hashes), called through JNI. It picks the
fastest code path for the CPU at runtime:

| CPU | curve arithmetic | SHA-512 |
|---|---|---|
| x86-64 with AVX-512 IFMA (Ice Lake+, Zen 4+) | AVX-512 IFMA | AVX2 |
| x86-64 with AVX2 | AVX2 | AVX2 |
| aarch64 with ARMv8.2 SHA-512 (Apple Silicon, Graviton 3+, Neoverse) | 64-bit scalar | SHA-512 instructions |
| anything else | portable 32/64-bit scalar | portable |

`NativeCurve25519Provider.backend()` reports what was selected, e.g. `curve=avx2 sha512=avx2`.
The pure-Java provider is used when no native library is available for the platform.

The native library reproduces the legacy ref10/donna code it replaces byte for byte: same
public keys, shared secrets and signatures for the same inputs and randomness, and the same
accept/reject decisions for malformed keys and signatures.

Bundled platforms: `linux-{x86-64,aarch64,x86}` (glibc 2.17+), `darwin-{x86-64,aarch64}`,
`win32-{x86-64,x86,aarch64}`.

On JDK 24 and newer, start the JVM with `--enable-native-access=ALL-UNNAMED` (or your module
name) to silence the JVM's warning about native code being loaded.

## Building

Toolchain versions are pinned in `mise.toml` (`mise install` sets them up), but any Rust 1.89+
and JDK 17+ will do.

```
native/build.sh          # builds the native library for this machine into src/main/resources
./mvnw verify            # Java build + tests (pure-Java, native, and a native-vs-Java differential test)
```

The native library can also be loaded from an explicit file with
`-Dcurve25519.library.path=/path/to/libcurve25519.so`.

### Benchmarks

```
./mvnw -Pbench -DskipTests test-compile exec:exec
```

### Releasing

CI (`.github/workflows/build.yaml`) builds the native libraries for all platforms, runs the
tests on Linux/macOS/Windows (x86-64 and arm64) with JDK 17 and 25, and publishes through the
Sonatype Central Portal: tags `vX.Y.Z` publish release `X.Y.Z`, and pushes to `master` publish
the `-SNAPSHOT` from `pom.xml`. Required repository secrets:

* `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`: a user token from central.sonatype.com
* `OSSRH_GPG_KEY_ASCII`, `OSSRH_GPG_PASSPHRASE`: the ASCII-armored signing key and its passphrase

## Using

## Obtaining an instance

The caller needs to specify a `provider` when obtaining a Curve25519 instance. There are
three built in providers:

1. `Curve25519.NATIVE`: the native (curve25519-dalek) provider.
1. `Curve25519.JAVA`: a pure Java provider.
1. `Curve25519.BEST`: uses `NATIVE`, but falls back to `JAVA` if the former is unavailable.

The caller specifies a provider during instance creation:

```
Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);
```

A custom source of randomness can be supplied by implementing `SecureRandomProvider`:

```
Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST, new MySecureRandomProvider());
```

### Generating a Curve25519 keypair:

```
Curve25519KeyPair keyPair = Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
```

### Calculating a shared secret:

```
Curve25519 cipher       = Curve25519.getInstance(Curve25519.BEST);
byte[]     sharedSecret = cipher.calculateAgreement(publicKey, privateKey);
```

### Calculating a signature:

```
Curve25519 cipher    = Curve25519.getInstance(Curve25519.BEST);
byte[]     signature = cipher.calculateSignature(secureRandom, privateKey, message);
```

### Verifying a signature:

```
Curve25519 cipher         = Curve25519.getInstance(Curve25519.BEST);
boolean    validSignature = cipher.verifySignature(publicKey, message, signature);
```

## License

Copyright 2015 Open Whisper Systems

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

Updated by Waves Platform in 2019-2026
