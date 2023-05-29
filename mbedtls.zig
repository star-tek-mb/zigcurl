const std = @import("std");

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}

const root_path = root() ++ "/";

pub fn create(b: *std.Build, target: std.zig.CrossTarget) *std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = "mbedtls",
        .root_source_file = null,
        .target = target,
        .optimize = .ReleaseSmall,
    });

    lib.addCSourceFiles(srcs, &.{"-std=c99"});
    lib.addIncludePath(root_path ++ "mbedtls/include");
    lib.addIncludePath(root_path ++ "mbedtls/library");
    lib.linkLibC();
    lib.installHeadersDirectory(root_path ++ "mbedtls/include/mbedtls", "mbedtls");
    lib.installHeadersDirectory(root_path ++ "mbedtls/include/psa", "psa");

    if (target.isWindows()) {
        lib.linkSystemLibrary("ws2_32");
    }
    return lib;
}

const srcs = &.{
    root_path ++ "mbedtls/library/aes.c",
    root_path ++ "mbedtls/library/aesni.c",
    root_path ++ "mbedtls/library/aesce.c",
    root_path ++ "mbedtls/library/aria.c",
    root_path ++ "mbedtls/library/asn1parse.c",
    root_path ++ "mbedtls/library/asn1write.c",
    root_path ++ "mbedtls/library/base64.c",
    root_path ++ "mbedtls/library/bignum.c",
    root_path ++ "mbedtls/library/bignum_core.c",
    root_path ++ "mbedtls/library/bignum_mod.c",
    root_path ++ "mbedtls/library/bignum_mod_raw.c",
    root_path ++ "mbedtls/library/camellia.c",
    root_path ++ "mbedtls/library/ccm.c",
    root_path ++ "mbedtls/library/chacha20.c",
    root_path ++ "mbedtls/library/chachapoly.c",
    root_path ++ "mbedtls/library/cipher.c",
    root_path ++ "mbedtls/library/cipher_wrap.c",
    root_path ++ "mbedtls/library/constant_time.c",
    root_path ++ "mbedtls/library/cmac.c",
    root_path ++ "mbedtls/library/ctr_drbg.c",
    root_path ++ "mbedtls/library/des.c",
    root_path ++ "mbedtls/library/dhm.c",
    root_path ++ "mbedtls/library/ecdh.c",
    root_path ++ "mbedtls/library/ecdsa.c",
    root_path ++ "mbedtls/library/ecjpake.c",
    root_path ++ "mbedtls/library/ecp.c",
    root_path ++ "mbedtls/library/ecp_curves.c",
    root_path ++ "mbedtls/library/entropy.c",
    root_path ++ "mbedtls/library/entropy_poll.c",
    root_path ++ "mbedtls/library/error.c",
    root_path ++ "mbedtls/library/gcm.c",
    root_path ++ "mbedtls/library/hash_info.c",
    root_path ++ "mbedtls/library/hkdf.c",
    root_path ++ "mbedtls/library/hmac_drbg.c",
    root_path ++ "mbedtls/library/lmots.c",
    root_path ++ "mbedtls/library/lms.c",
    root_path ++ "mbedtls/library/md.c",
    root_path ++ "mbedtls/library/md5.c",
    root_path ++ "mbedtls/library/memory_buffer_alloc.c",
    root_path ++ "mbedtls/library/nist_kw.c",
    root_path ++ "mbedtls/library/oid.c",
    root_path ++ "mbedtls/library/padlock.c",
    root_path ++ "mbedtls/library/pem.c",
    root_path ++ "mbedtls/library/pk.c",
    root_path ++ "mbedtls/library/pk_wrap.c",
    root_path ++ "mbedtls/library/pkcs12.c",
    root_path ++ "mbedtls/library/pkcs5.c",
    root_path ++ "mbedtls/library/pkparse.c",
    root_path ++ "mbedtls/library/pkwrite.c",
    root_path ++ "mbedtls/library/platform.c",
    root_path ++ "mbedtls/library/platform_util.c",
    root_path ++ "mbedtls/library/poly1305.c",
    root_path ++ "mbedtls/library/psa_crypto.c",
    root_path ++ "mbedtls/library/psa_crypto_aead.c",
    root_path ++ "mbedtls/library/psa_crypto_cipher.c",
    root_path ++ "mbedtls/library/psa_crypto_client.c",
    root_path ++ "mbedtls/library/psa_crypto_driver_wrappers.c",
    root_path ++ "mbedtls/library/psa_crypto_ecp.c",
    root_path ++ "mbedtls/library/psa_crypto_hash.c",
    root_path ++ "mbedtls/library/psa_crypto_mac.c",
    root_path ++ "mbedtls/library/psa_crypto_pake.c",
    root_path ++ "mbedtls/library/psa_crypto_rsa.c",
    root_path ++ "mbedtls/library/psa_crypto_se.c",
    root_path ++ "mbedtls/library/psa_crypto_slot_management.c",
    root_path ++ "mbedtls/library/psa_crypto_storage.c",
    root_path ++ "mbedtls/library/psa_its_file.c",
    root_path ++ "mbedtls/library/psa_util.c",
    root_path ++ "mbedtls/library/ripemd160.c",
    root_path ++ "mbedtls/library/rsa.c",
    root_path ++ "mbedtls/library/rsa_alt_helpers.c",
    root_path ++ "mbedtls/library/sha1.c",
    root_path ++ "mbedtls/library/sha256.c",
    root_path ++ "mbedtls/library/sha512.c",
    root_path ++ "mbedtls/library/threading.c",
    root_path ++ "mbedtls/library/timing.c",
    root_path ++ "mbedtls/library/version.c",
    root_path ++ "mbedtls/library/version_features.c",
    root_path ++ "mbedtls/library/pkcs7.c",
    root_path ++ "mbedtls/library/x509.c",
    root_path ++ "mbedtls/library/x509_create.c",
    root_path ++ "mbedtls/library/x509_crl.c",
    root_path ++ "mbedtls/library/x509_crt.c",
    root_path ++ "mbedtls/library/x509_csr.c",
    root_path ++ "mbedtls/library/x509write_crt.c",
    root_path ++ "mbedtls/library/x509write_csr.c",
    root_path ++ "mbedtls/library/debug.c",
    root_path ++ "mbedtls/library/mps_reader.c",
    root_path ++ "mbedtls/library/mps_trace.c",
    root_path ++ "mbedtls/library/net_sockets.c",
    root_path ++ "mbedtls/library/ssl_cache.c",
    root_path ++ "mbedtls/library/ssl_ciphersuites.c",
    root_path ++ "mbedtls/library/ssl_client.c",
    root_path ++ "mbedtls/library/ssl_cookie.c",
    root_path ++ "mbedtls/library/ssl_debug_helpers_generated.c",
    root_path ++ "mbedtls/library/ssl_msg.c",
    root_path ++ "mbedtls/library/ssl_ticket.c",
    root_path ++ "mbedtls/library/ssl_tls.c",
    root_path ++ "mbedtls/library/ssl_tls12_client.c",
    root_path ++ "mbedtls/library/ssl_tls12_server.c",
    root_path ++ "mbedtls/library/ssl_tls13_keys.c",
    root_path ++ "mbedtls/library/ssl_tls13_server.c",
    root_path ++ "mbedtls/library/ssl_tls13_client.c",
    root_path ++ "mbedtls/library/ssl_tls13_generic.c",
};
