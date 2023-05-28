const std = @import("std");

pub fn create(b: *std.Build, target: std.zig.CrossTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = "curl",
        .target = target,
        .optimize = optimize,
    });
    lib.addCSourceFiles(srcs, &.{});
    lib.addIncludePath("curl/lib");
    lib.addIncludePath("curl/include");
    lib.linkLibC();
    lib.defineCMacro("BUILDING_LIBCURL", null);
    lib.defineCMacro("CURL_STATICLIB", "1");
    lib.defineCMacro("CURL_DISABLE_LDAP", "1");
    lib.defineCMacro("CURL_DISABLE_LDAPS", "1");
    lib.defineCMacro("USE_MBEDTLS", "1");
    lib.defineCMacro("CURL_DISABLE_DICT", "1");
    lib.defineCMacro("CURL_DISABLE_FILE", "1");
    lib.defineCMacro("CURL_DISABLE_FTP", "1");
    lib.defineCMacro("CURL_DISABLE_GOPHER", "1");
    lib.defineCMacro("CURL_DISABLE_IMAP", "1");
    lib.defineCMacro("CURL_DISABLE_MQTT", "1");
    lib.defineCMacro("CURL_DISABLE_POP3", "1");
    lib.defineCMacro("CURL_DISABLE_RTSP", "1");
    lib.defineCMacro("CURL_DISABLE_SMB", "1");
    lib.defineCMacro("CURL_DISABLE_SMTP", "1");
    lib.defineCMacro("CURL_DISABLE_TELNET", "1");
    lib.defineCMacro("CURL_DISABLE_TFTP", "1");
    lib.defineCMacro("HAVE_LIBZ", "1");
    lib.defineCMacro("HAVE_ZLIB_H", "1");
    if (target.isWindows()) {
        return lib;
    }
    lib.defineCMacro("CURL_EXTERN_SYMBOL", "__attribute__ ((__visibility__ (\"default\"))");
    if (!target.isDarwin())
        lib.defineCMacro("ENABLE_IPV6", "1");
    lib.defineCMacro("HAVE_ALARM", "1");
    lib.defineCMacro("HAVE_ALLOCA_H", "1");
    lib.defineCMacro("HAVE_ARPA_INET_H", "1");
    lib.defineCMacro("HAVE_ARPA_TFTP_H", "1");
    lib.defineCMacro("HAVE_ASSERT_H", "1");
    lib.defineCMacro("HAVE_BASENAME", "1");
    lib.defineCMacro("HAVE_BOOL_T", "1");
    lib.defineCMacro("HAVE_BUILTIN_AVAILABLE", "1");
    lib.defineCMacro("HAVE_CLOCK_GETTIME_MONOTONIC", "1");
    lib.defineCMacro("HAVE_DLFCN_H", "1");
    lib.defineCMacro("HAVE_ERRNO_H", "1");
    lib.defineCMacro("HAVE_FCNTL", "1");
    lib.defineCMacro("HAVE_FCNTL_H", "1");
    lib.defineCMacro("HAVE_FCNTL_O_NONBLOCK", "1");
    lib.defineCMacro("HAVE_FREEADDRINFO", "1");
    lib.defineCMacro("HAVE_FTRUNCATE", "1");
    lib.defineCMacro("HAVE_GETADDRINFO", "1");
    lib.defineCMacro("HAVE_GETEUID", "1");
    lib.defineCMacro("HAVE_GETPPID", "1");
    lib.defineCMacro("HAVE_GETHOSTBYNAME", "1");
    if (!target.isDarwin())
        lib.defineCMacro("HAVE_GETHOSTBYNAME_R", "1");
    lib.defineCMacro("HAVE_GETHOSTBYNAME_R_6", "1");
    lib.defineCMacro("HAVE_GETHOSTNAME", "1");
    lib.defineCMacro("HAVE_GETPPID", "1");
    lib.defineCMacro("HAVE_GETPROTOBYNAME", "1");
    lib.defineCMacro("HAVE_GETPEERNAME", "1");
    lib.defineCMacro("HAVE_GETSOCKNAME", "1");
    lib.defineCMacro("HAVE_IF_NAMETOINDEX", "1");
    lib.defineCMacro("HAVE_GETPWUID", "1");
    lib.defineCMacro("HAVE_GETPWUID_R", "1");
    lib.defineCMacro("HAVE_GETRLIMIT", "1");
    lib.defineCMacro("HAVE_GETTIMEOFDAY", "1");
    lib.defineCMacro("HAVE_GMTIME_R", "1");
    lib.defineCMacro("HAVE_IFADDRS_H", "1");
    lib.defineCMacro("HAVE_INET_ADDR", "1");
    lib.defineCMacro("HAVE_INET_PTON", "1");
    lib.defineCMacro("HAVE_SA_FAMILY_T", "1");
    lib.defineCMacro("HAVE_INTTYPES_H", "1");
    lib.defineCMacro("HAVE_IOCTL", "1");
    lib.defineCMacro("HAVE_IOCTL_FIONBIO", "1");
    lib.defineCMacro("HAVE_IOCTL_SIOCGIFADDR", "1");
    lib.defineCMacro("HAVE_LDAP_URL_PARSE", "1");
    lib.defineCMacro("HAVE_LIBGEN_H", "1");
    lib.defineCMacro("HAVE_IDN2_H", "1");
    lib.defineCMacro("HAVE_LL", "1");
    lib.defineCMacro("HAVE_LOCALE_H", "1");
    lib.defineCMacro("HAVE_LOCALTIME_R", "1");
    lib.defineCMacro("HAVE_LONGLONG", "1");
    lib.defineCMacro("HAVE_MALLOC_H", "1");
    lib.defineCMacro("HAVE_MEMORY_H", "1");
    if (!target.isDarwin())
        lib.defineCMacro("HAVE_MSG_NOSIGNAL", "1");
    lib.defineCMacro("HAVE_NETDB_H", "1");
    lib.defineCMacro("HAVE_NETINET_IN_H", "1");
    lib.defineCMacro("HAVE_NETINET_TCP_H", "1");
    if (target.isLinux())
        lib.defineCMacro("HAVE_LINUX_TCP_H", "1");
    lib.defineCMacro("HAVE_NET_IF_H", "1");
    lib.defineCMacro("HAVE_PIPE", "1");
    lib.defineCMacro("HAVE_POLL", "1");
    lib.defineCMacro("HAVE_POLL_FINE", "1");
    lib.defineCMacro("HAVE_POLL_H", "1");
    lib.defineCMacro("HAVE_POSIX_STRERROR_R", "1");
    lib.defineCMacro("HAVE_PTHREAD_H", "1");
    lib.defineCMacro("HAVE_PWD_H", "1");
    lib.defineCMacro("HAVE_RECV", "1");
    lib.defineCMacro("HAVE_SELECT", "1");
    lib.defineCMacro("HAVE_SEND", "1");
    lib.defineCMacro("HAVE_FSETXATTR", "1");
    lib.defineCMacro("HAVE_FSETXATTR_5", "1");
    lib.defineCMacro("HAVE_SETJMP_H", "1");
    lib.defineCMacro("HAVE_SETLOCALE", "1");
    lib.defineCMacro("HAVE_SETRLIMIT", "1");
    lib.defineCMacro("HAVE_SETSOCKOPT", "1");
    lib.defineCMacro("HAVE_SIGACTION", "1");
    lib.defineCMacro("HAVE_SIGINTERRUPT", "1");
    lib.defineCMacro("HAVE_SIGNAL", "1");
    lib.defineCMacro("HAVE_SIGNAL_H", "1");
    lib.defineCMacro("HAVE_SIGSETJMP", "1");
    lib.defineCMacro("HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID", "1");
    lib.defineCMacro("HAVE_SOCKET", "1");
    lib.defineCMacro("HAVE_STDBOOL_H", "1");
    lib.defineCMacro("HAVE_STDINT_H", "1");
    lib.defineCMacro("HAVE_STDIO_H", "1");
    lib.defineCMacro("HAVE_STDLIB_H", "1");
    lib.defineCMacro("HAVE_STRCASECMP", "1");
    lib.defineCMacro("HAVE_STRDUP", "1");
    lib.defineCMacro("HAVE_STRERROR_R", "1");
    lib.defineCMacro("HAVE_STRINGS_H", "1");
    lib.defineCMacro("HAVE_STRING_H", "1");
    lib.defineCMacro("HAVE_STRSTR", "1");
    lib.defineCMacro("HAVE_STRTOK_R", "1");
    lib.defineCMacro("HAVE_STRTOLL", "1");
    lib.defineCMacro("HAVE_STRUCT_SOCKADDR_STORAGE", "1");
    lib.defineCMacro("HAVE_STRUCT_TIMEVAL", "1");
    lib.defineCMacro("HAVE_SYS_IOCTL_H", "1");
    lib.defineCMacro("HAVE_SYS_PARAM_H", "1");
    lib.defineCMacro("HAVE_SYS_POLL_H", "1");
    lib.defineCMacro("HAVE_SYS_RESOURCE_H", "1");
    lib.defineCMacro("HAVE_SYS_SELECT_H", "1");
    lib.defineCMacro("HAVE_SYS_SOCKET_H", "1");
    lib.defineCMacro("HAVE_SYS_STAT_H", "1");
    lib.defineCMacro("HAVE_SYS_TIME_H", "1");
    lib.defineCMacro("HAVE_SYS_TYPES_H", "1");
    lib.defineCMacro("HAVE_SYS_UIO_H", "1");
    lib.defineCMacro("HAVE_SYS_UN_H", "1");
    lib.defineCMacro("HAVE_TERMIOS_H", "1");
    lib.defineCMacro("HAVE_TERMIO_H", "1");
    lib.defineCMacro("HAVE_TIME_H", "1");
    lib.defineCMacro("HAVE_UNAME", "1");
    lib.defineCMacro("HAVE_UNISTD_H", "1");
    lib.defineCMacro("HAVE_UTIME", "1");
    lib.defineCMacro("HAVE_UTIMES", "1");
    lib.defineCMacro("HAVE_UTIME_H", "1");
    lib.defineCMacro("HAVE_VARIADIC_MACROS_C99", "1");
    lib.defineCMacro("HAVE_VARIADIC_MACROS_GCC", "1");
    lib.defineCMacro("OS", "\"Linux\"");
    lib.defineCMacro("RANDOM_FILE", "\"/dev/urandom\"");
    lib.defineCMacro("RECV_TYPE_ARG1", "int");
    lib.defineCMacro("RECV_TYPE_ARG2", "void *");
    lib.defineCMacro("RECV_TYPE_ARG3", "size_t");
    lib.defineCMacro("RECV_TYPE_ARG4", "int");
    lib.defineCMacro("RECV_TYPE_RETV", "ssize_t");
    lib.defineCMacro("SEND_QUAL_ARG2", "const");
    lib.defineCMacro("SEND_TYPE_ARG1", "int");
    lib.defineCMacro("SEND_TYPE_ARG2", "void *");
    lib.defineCMacro("SEND_TYPE_ARG3", "size_t");
    lib.defineCMacro("SEND_TYPE_ARG4", "int");
    lib.defineCMacro("SEND_TYPE_RETV", "ssize_t");
    lib.defineCMacro("SIZEOF_INT", "4");
    lib.defineCMacro("SIZEOF_SHORT", "2");
    lib.defineCMacro("SIZEOF_LONG", "8");
    lib.defineCMacro("SIZEOF_OFF_T", "8");
    lib.defineCMacro("SIZEOF_CURL_OFF_T", "8");
    lib.defineCMacro("SIZEOF_SIZE_T", "8");
    lib.defineCMacro("SIZEOF_TIME_T", "8");
    lib.defineCMacro("STDC_HEADERS", "1");
    lib.defineCMacro("TIME_WITH_SYS_TIME", "1");
    lib.defineCMacro("USE_THREADS_POSIX", "1");
    lib.defineCMacro("USE_UNIX_SOCKETS", null);
    lib.defineCMacro("_FILE_OFFSET_BITS", "64");
    return lib;
}

const srcs = &.{
    "curl/lib/cookie.c",
    "curl/lib/http_chunks.c",
    "curl/lib/escape.c",
    "curl/lib/version_win32.c",
    "curl/lib/url.c",
    "curl/lib/base64.c",
    "curl/lib/mqtt.c",
    "curl/lib/setopt.c",
    "curl/lib/telnet.c",
    "curl/lib/hostip.c",
    "curl/lib/curl_gethostname.c",
    "curl/lib/connect.c",
    "curl/lib/socks_sspi.c",
    "curl/lib/cf-socket.c",
    "curl/lib/curl_fnmatch.c",
    "curl/lib/curl_gssapi.c",
    "curl/lib/http1.c",
    "curl/lib/multi.c",
    "curl/lib/gopher.c",
    "curl/lib/noproxy.c",
    "curl/lib/curl_sasl.c",
    "curl/lib/dict.c",
    "curl/lib/bufref.c",
    "curl/lib/slist.c",
    "curl/lib/curl_log.c",
    "curl/lib/vtls/rustls.c",
    "curl/lib/vtls/mbedtls.c",
    "curl/lib/vtls/wolfssl.c",
    "curl/lib/vtls/schannel.c",
    "curl/lib/vtls/gskit.c",
    "curl/lib/vtls/gtls.c",
    "curl/lib/vtls/sectransp.c",
    "curl/lib/vtls/vtls.c",
    "curl/lib/vtls/mbedtls_threadlock.c",
    "curl/lib/vtls/schannel_verify.c",
    "curl/lib/vtls/hostcheck.c",
    "curl/lib/vtls/bearssl.c",
    "curl/lib/vtls/openssl.c",
    "curl/lib/vtls/x509asn1.c",
    "curl/lib/vtls/keylog.c",
    "curl/lib/vtls/nss.c",
    "curl/lib/file.c",
    "curl/lib/socks_gssapi.c",
    "curl/lib/select.c",
    "curl/lib/socketpair.c",
    "curl/lib/curl_memrchr.c",
    "curl/lib/cfilters.c",
    "curl/lib/strtok.c",
    "curl/lib/version.c",
    "curl/lib/fopen.c",
    "curl/lib/http_aws_sigv4.c",
    "curl/lib/mprintf.c",
    "curl/lib/curl_path.c",
    "curl/lib/parsedate.c",
    "curl/lib/rename.c",
    "curl/lib/ftplistparser.c",
    "curl/lib/content_encoding.c",
    "curl/lib/mime.c",
    "curl/lib/rand.c",
    "curl/lib/curl_des.c",
    "curl/lib/curl_ntlm_core.c",
    "curl/lib/pop3.c",
    "curl/lib/curl_sspi.c",
    "curl/lib/smb.c",
    "curl/lib/conncache.c",
    "curl/lib/inet_pton.c",
    "curl/lib/if2ip.c",
    "curl/lib/openldap.c",
    "curl/lib/http_digest.c",
    "curl/lib/cf-h1-proxy.c",
    "curl/lib/asyn-thread.c",
    "curl/lib/strerror.c",
    "curl/lib/ftp.c",
    "curl/lib/strdup.c",
    "curl/lib/memdebug.c",
    "curl/lib/speedcheck.c",
    "curl/lib/vquic/curl_ngtcp2.c",
    "curl/lib/vquic/curl_msh3.c",
    "curl/lib/vquic/vquic.c",
    "curl/lib/vquic/curl_quiche.c",
    "curl/lib/getinfo.c",
    "curl/lib/http2.c",
    "curl/lib/vauth/oauth2.c",
    "curl/lib/vauth/vauth.c",
    "curl/lib/vauth/digest_sspi.c",
    "curl/lib/vauth/digest.c",
    "curl/lib/vauth/cram.c",
    "curl/lib/vauth/cleartext.c",
    "curl/lib/vauth/krb5_sspi.c",
    "curl/lib/vauth/spnego_sspi.c",
    "curl/lib/vauth/ntlm_sspi.c",
    "curl/lib/vauth/spnego_gssapi.c",
    "curl/lib/vauth/ntlm.c",
    "curl/lib/vauth/krb5_gssapi.c",
    "curl/lib/vauth/gsasl.c",
    "curl/lib/md4.c",
    "curl/lib/bufq.c",
    "curl/lib/curl_get_line.c",
    "curl/lib/hostip4.c",
    "curl/lib/curl_rtmp.c",
    "curl/lib/amigaos.c",
    "curl/lib/share.c",
    "curl/lib/warnless.c",
    "curl/lib/hostsyn.c",
    "curl/lib/md5.c",
    "curl/lib/strtoofft.c",
    "curl/lib/altsvc.c",
    "curl/lib/formdata.c",
    "curl/lib/dynbuf.c",
    "curl/lib/curl_addrinfo.c",
    "curl/lib/hostasyn.c",
    "curl/lib/doh.c",
    "curl/lib/curl_ntlm_wb.c",
    "curl/lib/easygetopt.c",
    "curl/lib/ldap.c",
    "curl/lib/nonblock.c",
    "curl/lib/idn.c",
    "curl/lib/pingpong.c",
    "curl/lib/imap.c",
    "curl/lib/vssh/libssh.c",
    "curl/lib/vssh/wolfssh.c",
    "curl/lib/vssh/libssh2.c",
    "curl/lib/splay.c",
    "curl/lib/krb5.c",
    "curl/lib/progress.c",
    "curl/lib/cf-haproxy.c",
    "curl/lib/easyoptions.c",
    "curl/lib/curl_range.c",
    "curl/lib/curl_endian.c",
    "curl/lib/http_proxy.c",
    "curl/lib/inet_ntop.c",
    "curl/lib/timeval.c",
    "curl/lib/asyn-ares.c",
    "curl/lib/rtsp.c",
    "curl/lib/sha256.c",
    "curl/lib/curl_threads.c",
    "curl/lib/easy.c",
    "curl/lib/dynhds.c",
    "curl/lib/tftp.c",
    "curl/lib/hsts.c",
    "curl/lib/smtp.c",
    "curl/lib/hash.c",
    "curl/lib/cf-https-connect.c",
    "curl/lib/getenv.c",
    "curl/lib/headers.c",
    "curl/lib/system_win32.c",
    "curl/lib/http_ntlm.c",
    "curl/lib/psl.c",
    "curl/lib/ws.c",
    "curl/lib/hostip6.c",
    "curl/lib/curl_multibyte.c",
    "curl/lib/netrc.c",
    "curl/lib/llist.c",
    "curl/lib/urlapi.c",
    "curl/lib/strcase.c",
    "curl/lib/sendf.c",
    "curl/lib/timediff.c",
    "curl/lib/http.c",
    "curl/lib/cf-h2-proxy.c",
    "curl/lib/socks.c",
    "curl/lib/http_negotiate.c",
    "curl/lib/transfer.c",
    "curl/lib/c-hyper.c",
    "curl/lib/hmac.c",
    "curl/lib/fileinfo.c",
};
