package org.whispersystems.curve25519;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/**
 * JNI bindings to the bundled Rust library (curve25519-dalek + sha2).
 *
 * <p>The library is looked up in this order:
 * <ol>
 *   <li>the file named by the {@code curve25519.library.path} system property;</li>
 *   <li>the copy bundled in this jar under {@code /<os>-<arch>/}, for example
 *       {@code /linux-x86-64/libcurve25519.so}, which is extracted to {@code curve25519.tmpdir}
 *       (default: {@code java.io.tmpdir});</li>
 *   <li>{@code curve25519} on {@code java.library.path}.</li>
 * </ol>
 *
 * <p>On JDK 24 and newer, run with {@code --enable-native-access=ALL-UNNAMED} (or the name of
 * the module containing this library) to silence the JVM's native-access warning.
 */
final class NativeCurve25519 {
    static final int OK = 0;
    static final int ERR_CRYPTO = -1;
    static final int ERR_ARGUMENT = -2;

    private static final String LIBRARY_NAME = "curve25519";
    private static final Throwable LOAD_FAILURE = load();

    private NativeCurve25519() {
    }

    /** @throws NoSuchProviderException if the native library is not available on this platform */
    static void ensureAvailable() {
        if (LOAD_FAILURE != null) throw new NoSuchProviderException(LOAD_FAILURE);
    }

    private static Throwable load() {
        try {
            String explicit = System.getProperty("curve25519.library.path");
            if (explicit != null) {
                System.load(Paths.get(explicit).toAbsolutePath().toString());
            } else if (!loadBundled()) {
                System.loadLibrary(LIBRARY_NAME);
            }
            if (smokeCheck(31337) != 31337) {
                throw new UnsatisfiedLinkError("curve25519 native library smoke check failed");
            }
            return null;
        } catch (Throwable t) {
            return t;
        }
    }

    private static boolean loadBundled() throws IOException {
        String fileName = System.mapLibraryName(LIBRARY_NAME);
        String resource = "/" + resourcePrefix() + "/" + fileName;
        try (InputStream in = NativeCurve25519.class.getResourceAsStream(resource)) {
            if (in == null) return false;
            String tmpDir = System.getProperty("curve25519.tmpdir", System.getProperty("java.io.tmpdir"));
            Path tmp = Files.createTempFile(Paths.get(tmpDir), "curve25519-", "-" + fileName);
            try {
                Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
                System.load(tmp.toAbsolutePath().toString());
            } finally {
                // POSIX systems keep the mapping after unlink; Windows can only delete it at exit.
                try {
                    Files.delete(tmp);
                } catch (IOException e) {
                    tmp.toFile().deleteOnExit();
                }
            }
            return true;
        }
    }

    /** Same layout as JNA's {@code Platform.RESOURCE_PREFIX}, e.g. {@code linux-x86-64}. */
    static String resourcePrefix() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
        String osPrefix;
        if (os.startsWith("windows")) osPrefix = "win32";
        else if (os.startsWith("mac") || os.startsWith("darwin")) osPrefix = "darwin";
        else if (os.startsWith("linux")) osPrefix = "linux";
        else if (os.startsWith("freebsd")) osPrefix = "freebsd";
        else osPrefix = os.replaceAll("\\W+", "");

        String archPrefix;
        switch (arch) {
            case "x86_64":
            case "amd64":
                archPrefix = "x86-64";
                break;
            case "aarch64":
            case "arm64":
                archPrefix = "aarch64";
                break;
            case "x86":
            case "i386":
            case "i486":
            case "i586":
            case "i686":
                archPrefix = "x86";
                break;
            default:
                archPrefix = arch;
        }
        return osPrefix + "-" + archPrefix;
    }

    static native int smokeCheck(int dummy);

    /** Hardware acceleration selected at runtime, e.g. {@code "curve=avx2 sha512=avx2"}. */
    static native String backend();

    static native int generatePublicKey(byte[] publicKeyOut, byte[] privateKey);

    static native int calculateAgreement(byte[] sharedKeyOut, byte[] privateKey, byte[] publicKey);

    static native int calculateSignature(byte[] signatureOut, byte[] random, byte[] privateKey, byte[] message);

    static native int verifySignature(byte[] publicKey, byte[] message, byte[] signature);

    static native int calculateVrfSignature(byte[] signatureOut, byte[] random, byte[] privateKey, byte[] message);

    static native int verifyVrfSignature(byte[] vrfOut, byte[] publicKey, byte[] message, byte[] signature);
}
