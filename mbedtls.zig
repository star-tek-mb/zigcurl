const std = @import("std");

pub fn create(b: *std.Build, target: std.zig.CrossTarget) *std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = "mbedtls",
        .root_source_file = null,
        .target = target,
        .optimize = .ReleaseSmall,
    });

    lib.addCSourceFiles(.{ .files = srcs, .flags = &.{"-std=c99"} });
    lib.addIncludePath(.{ .path = "mbedtls/include" });
    lib.addIncludePath(.{ .path = "mbedtls/library" });
    lib.linkLibC();
    lib.installHeadersDirectory("mbedtls/include/mbedtls", "mbedtls");
    lib.installHeadersDirectory("mbedtls/include/psa", "psa");

    if (target.isWindows()) {
        lib.linkSystemLibrary("ws2_32");
    }
    return lib;
}

const srcs = &.{
    "mbedtls/library/aes.c",
    "mbedtls/library/aesni.c",
    "mbedtls/library/aesce.c",
    "mbedtls/library/aria.c",
    "mbedtls/library/asn1parse.c",
    "mbedtls/library/asn1write.c",
    "mbedtls/library/base64.c",
    "mbedtls/library/bignum.c",
    "mbedtls/library/bignum_core.c",
    "mbedtls/library/bignum_mod.c",
    "mbedtls/library/bignum_mod_raw.c",
    "mbedtls/library/camellia.c",
    "mbedtls/library/ccm.c",
    "mbedtls/library/chacha20.c",
    "mbedtls/library/chachapoly.c",
    "mbedtls/library/cipher.c",
    "mbedtls/library/cipher_wrap.c",
    "mbedtls/library/constant_time.c",
    "mbedtls/library/cmac.c",
    "mbedtls/library/ctr_drbg.c",
    "mbedtls/library/des.c",
    "mbedtls/library/dhm.c",
    "mbedtls/library/ecdh.c",
    "mbedtls/library/ecdsa.c",
    "mbedtls/library/ecjpake.c",
    "mbedtls/library/ecp.c",
    "mbedtls/library/ecp_curves.c",
    "mbedtls/library/entropy.c",
    "mbedtls/library/entropy_poll.c",
    "mbedtls/library/error.c",
    "mbedtls/library/gcm.c",
    "mbedtls/library/hash_info.c",
    "mbedtls/library/hkdf.c",
    "mbedtls/library/hmac_drbg.c",
    "mbedtls/library/lmots.c",
    "mbedtls/library/lms.c",
    "mbedtls/library/md.c",
    "mbedtls/library/md5.c",
    "mbedtls/library/memory_buffer_alloc.c",
    "mbedtls/library/nist_kw.c",
    "mbedtls/library/oid.c",
    "mbedtls/library/padlock.c",
    "mbedtls/library/pem.c",
    "mbedtls/library/pk.c",
    "mbedtls/library/pk_wrap.c",
    "mbedtls/library/pkcs12.c",
    "mbedtls/library/pkcs5.c",
    "mbedtls/library/pkparse.c",
    "mbedtls/library/pkwrite.c",
    "mbedtls/library/platform.c",
    "mbedtls/library/platform_util.c",
    "mbedtls/library/poly1305.c",
    "mbedtls/library/psa_crypto.c",
    "mbedtls/library/psa_crypto_aead.c",
    "mbedtls/library/psa_crypto_cipher.c",
    "mbedtls/library/psa_crypto_client.c",
    "mbedtls/library/psa_crypto_driver_wrappers.c",
    "mbedtls/library/psa_crypto_ecp.c",
    "mbedtls/library/psa_crypto_hash.c",
    "mbedtls/library/psa_crypto_mac.c",
    "mbedtls/library/psa_crypto_pake.c",
    "mbedtls/library/psa_crypto_rsa.c",
    "mbedtls/library/psa_crypto_se.c",
    "mbedtls/library/psa_crypto_slot_management.c",
    "mbedtls/library/psa_crypto_storage.c",
    "mbedtls/library/psa_its_file.c",
    "mbedtls/library/psa_util.c",
    "mbedtls/library/ripemd160.c",
    "mbedtls/library/rsa.c",
    "mbedtls/library/rsa_alt_helpers.c",
    "mbedtls/library/sha1.c",
    "mbedtls/library/sha256.c",
    "mbedtls/library/sha512.c",
    "mbedtls/library/threading.c",
    "mbedtls/library/timing.c",
    "mbedtls/library/version.c",
    "mbedtls/library/version_features.c",
    "mbedtls/library/pkcs7.c",
    "mbedtls/library/x509.c",
    "mbedtls/library/x509_create.c",
    "mbedtls/library/x509_crl.c",
    "mbedtls/library/x509_crt.c",
    "mbedtls/library/x509_csr.c",
    "mbedtls/library/x509write_crt.c",
    "mbedtls/library/x509write_csr.c",
    "mbedtls/library/debug.c",
    "mbedtls/library/mps_reader.c",
    "mbedtls/library/mps_trace.c",
    "mbedtls/library/net_sockets.c",
    "mbedtls/library/ssl_cache.c",
    "mbedtls/library/ssl_ciphersuites.c",
    "mbedtls/library/ssl_client.c",
    "mbedtls/library/ssl_cookie.c",
    "mbedtls/library/ssl_debug_helpers_generated.c",
    "mbedtls/library/ssl_msg.c",
    "mbedtls/library/ssl_ticket.c",
    "mbedtls/library/ssl_tls.c",
    "mbedtls/library/ssl_tls12_client.c",
    "mbedtls/library/ssl_tls12_server.c",
    "mbedtls/library/ssl_tls13_keys.c",
    "mbedtls/library/ssl_tls13_server.c",
    "mbedtls/library/ssl_tls13_client.c",
    "mbedtls/library/ssl_tls13_generic.c",
};
