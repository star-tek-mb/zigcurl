const std = @import("std");

pub fn create(b: *std.Build, target: std.zig.CrossTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = "curl",
        .target = target,
        .optimize = optimize,
    });
    lib.addCSourceFiles(srcs, &.{});
    lib.addIncludePath(root_path ++ "curl/lib");
    lib.addIncludePath(root_path ++ "curl/include");
    lib.installHeadersDirectory(root_path ++ "curl/include/curl", "curl");
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
        lib.linkSystemLibrary("bcrypt");
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

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}

const root_path = root() ++ "/";

const srcs = &.{
    root_path ++ "curl/lib/cookie.c",
    root_path ++ "curl/lib/http_chunks.c",
    root_path ++ "curl/lib/escape.c",
    root_path ++ "curl/lib/version_win32.c",
    root_path ++ "curl/lib/url.c",
    root_path ++ "curl/lib/base64.c",
    root_path ++ "curl/lib/mqtt.c",
    root_path ++ "curl/lib/setopt.c",
    root_path ++ "curl/lib/telnet.c",
    root_path ++ "curl/lib/hostip.c",
    root_path ++ "curl/lib/curl_gethostname.c",
    root_path ++ "curl/lib/connect.c",
    root_path ++ "curl/lib/socks_sspi.c",
    root_path ++ "curl/lib/cf-socket.c",
    root_path ++ "curl/lib/curl_fnmatch.c",
    root_path ++ "curl/lib/curl_gssapi.c",
    root_path ++ "curl/lib/http1.c",
    root_path ++ "curl/lib/multi.c",
    root_path ++ "curl/lib/gopher.c",
    root_path ++ "curl/lib/noproxy.c",
    root_path ++ "curl/lib/curl_sasl.c",
    root_path ++ "curl/lib/dict.c",
    root_path ++ "curl/lib/bufref.c",
    root_path ++ "curl/lib/slist.c",
    root_path ++ "curl/lib/curl_log.c",
    root_path ++ "curl/lib/vtls/rustls.c",
    root_path ++ "curl/lib/vtls/mbedtls.c",
    root_path ++ "curl/lib/vtls/wolfssl.c",
    root_path ++ "curl/lib/vtls/schannel.c",
    root_path ++ "curl/lib/vtls/gskit.c",
    root_path ++ "curl/lib/vtls/gtls.c",
    root_path ++ "curl/lib/vtls/sectransp.c",
    root_path ++ "curl/lib/vtls/vtls.c",
    root_path ++ "curl/lib/vtls/mbedtls_threadlock.c",
    root_path ++ "curl/lib/vtls/schannel_verify.c",
    root_path ++ "curl/lib/vtls/hostcheck.c",
    root_path ++ "curl/lib/vtls/bearssl.c",
    root_path ++ "curl/lib/vtls/openssl.c",
    root_path ++ "curl/lib/vtls/x509asn1.c",
    root_path ++ "curl/lib/vtls/keylog.c",
    root_path ++ "curl/lib/vtls/nss.c",
    root_path ++ "curl/lib/file.c",
    root_path ++ "curl/lib/socks_gssapi.c",
    root_path ++ "curl/lib/select.c",
    root_path ++ "curl/lib/socketpair.c",
    root_path ++ "curl/lib/curl_memrchr.c",
    root_path ++ "curl/lib/cfilters.c",
    root_path ++ "curl/lib/strtok.c",
    root_path ++ "curl/lib/version.c",
    root_path ++ "curl/lib/fopen.c",
    root_path ++ "curl/lib/http_aws_sigv4.c",
    root_path ++ "curl/lib/mprintf.c",
    root_path ++ "curl/lib/curl_path.c",
    root_path ++ "curl/lib/parsedate.c",
    root_path ++ "curl/lib/rename.c",
    root_path ++ "curl/lib/ftplistparser.c",
    root_path ++ "curl/lib/content_encoding.c",
    root_path ++ "curl/lib/mime.c",
    root_path ++ "curl/lib/rand.c",
    root_path ++ "curl/lib/curl_des.c",
    root_path ++ "curl/lib/curl_ntlm_core.c",
    root_path ++ "curl/lib/pop3.c",
    root_path ++ "curl/lib/curl_sspi.c",
    root_path ++ "curl/lib/smb.c",
    root_path ++ "curl/lib/conncache.c",
    root_path ++ "curl/lib/inet_pton.c",
    root_path ++ "curl/lib/if2ip.c",
    root_path ++ "curl/lib/openldap.c",
    root_path ++ "curl/lib/http_digest.c",
    root_path ++ "curl/lib/cf-h1-proxy.c",
    root_path ++ "curl/lib/asyn-thread.c",
    root_path ++ "curl/lib/strerror.c",
    root_path ++ "curl/lib/ftp.c",
    root_path ++ "curl/lib/strdup.c",
    root_path ++ "curl/lib/memdebug.c",
    root_path ++ "curl/lib/speedcheck.c",
    root_path ++ "curl/lib/vquic/curl_ngtcp2.c",
    root_path ++ "curl/lib/vquic/curl_msh3.c",
    root_path ++ "curl/lib/vquic/vquic.c",
    root_path ++ "curl/lib/vquic/curl_quiche.c",
    root_path ++ "curl/lib/getinfo.c",
    root_path ++ "curl/lib/http2.c",
    root_path ++ "curl/lib/vauth/oauth2.c",
    root_path ++ "curl/lib/vauth/vauth.c",
    root_path ++ "curl/lib/vauth/digest_sspi.c",
    root_path ++ "curl/lib/vauth/digest.c",
    root_path ++ "curl/lib/vauth/cram.c",
    root_path ++ "curl/lib/vauth/cleartext.c",
    root_path ++ "curl/lib/vauth/krb5_sspi.c",
    root_path ++ "curl/lib/vauth/spnego_sspi.c",
    root_path ++ "curl/lib/vauth/ntlm_sspi.c",
    root_path ++ "curl/lib/vauth/spnego_gssapi.c",
    root_path ++ "curl/lib/vauth/ntlm.c",
    root_path ++ "curl/lib/vauth/krb5_gssapi.c",
    root_path ++ "curl/lib/vauth/gsasl.c",
    root_path ++ "curl/lib/md4.c",
    root_path ++ "curl/lib/bufq.c",
    root_path ++ "curl/lib/curl_get_line.c",
    root_path ++ "curl/lib/hostip4.c",
    root_path ++ "curl/lib/curl_rtmp.c",
    root_path ++ "curl/lib/amigaos.c",
    root_path ++ "curl/lib/share.c",
    root_path ++ "curl/lib/warnless.c",
    root_path ++ "curl/lib/hostsyn.c",
    root_path ++ "curl/lib/md5.c",
    root_path ++ "curl/lib/strtoofft.c",
    root_path ++ "curl/lib/altsvc.c",
    root_path ++ "curl/lib/formdata.c",
    root_path ++ "curl/lib/dynbuf.c",
    root_path ++ "curl/lib/curl_addrinfo.c",
    root_path ++ "curl/lib/hostasyn.c",
    root_path ++ "curl/lib/doh.c",
    root_path ++ "curl/lib/curl_ntlm_wb.c",
    root_path ++ "curl/lib/easygetopt.c",
    root_path ++ "curl/lib/ldap.c",
    root_path ++ "curl/lib/nonblock.c",
    root_path ++ "curl/lib/idn.c",
    root_path ++ "curl/lib/pingpong.c",
    root_path ++ "curl/lib/imap.c",
    root_path ++ "curl/lib/vssh/libssh.c",
    root_path ++ "curl/lib/vssh/wolfssh.c",
    root_path ++ "curl/lib/vssh/libssh2.c",
    root_path ++ "curl/lib/splay.c",
    root_path ++ "curl/lib/krb5.c",
    root_path ++ "curl/lib/progress.c",
    root_path ++ "curl/lib/cf-haproxy.c",
    root_path ++ "curl/lib/easyoptions.c",
    root_path ++ "curl/lib/curl_range.c",
    root_path ++ "curl/lib/curl_endian.c",
    root_path ++ "curl/lib/http_proxy.c",
    root_path ++ "curl/lib/inet_ntop.c",
    root_path ++ "curl/lib/timeval.c",
    root_path ++ "curl/lib/asyn-ares.c",
    root_path ++ "curl/lib/rtsp.c",
    root_path ++ "curl/lib/sha256.c",
    root_path ++ "curl/lib/curl_threads.c",
    root_path ++ "curl/lib/easy.c",
    root_path ++ "curl/lib/dynhds.c",
    root_path ++ "curl/lib/tftp.c",
    root_path ++ "curl/lib/hsts.c",
    root_path ++ "curl/lib/smtp.c",
    root_path ++ "curl/lib/hash.c",
    root_path ++ "curl/lib/cf-https-connect.c",
    root_path ++ "curl/lib/getenv.c",
    root_path ++ "curl/lib/headers.c",
    root_path ++ "curl/lib/system_win32.c",
    root_path ++ "curl/lib/http_ntlm.c",
    root_path ++ "curl/lib/psl.c",
    root_path ++ "curl/lib/ws.c",
    root_path ++ "curl/lib/hostip6.c",
    root_path ++ "curl/lib/curl_multibyte.c",
    root_path ++ "curl/lib/netrc.c",
    root_path ++ "curl/lib/llist.c",
    root_path ++ "curl/lib/urlapi.c",
    root_path ++ "curl/lib/strcase.c",
    root_path ++ "curl/lib/sendf.c",
    root_path ++ "curl/lib/timediff.c",
    root_path ++ "curl/lib/http.c",
    root_path ++ "curl/lib/cf-h2-proxy.c",
    root_path ++ "curl/lib/socks.c",
    root_path ++ "curl/lib/http_negotiate.c",
    root_path ++ "curl/lib/transfer.c",
    root_path ++ "curl/lib/c-hyper.c",
    root_path ++ "curl/lib/hmac.c",
    root_path ++ "curl/lib/fileinfo.c",
};
