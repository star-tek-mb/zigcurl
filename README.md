# Overview

libcurl packaged with zig

# Versions

curl 8.1.1
mbedtls 3.4.0
zlib 1.2.13

# Simple usage

```zig
const c = @cImport({
    @cInclude("curl/curl.h");
});

_ = c.curl_global_init(c.CURL_GLOBAL_DEFAULT);
defer c.curl_global_cleanup();
var curl = c.curl_easy_init();
defer c.curl_easy_cleanup(curl);
_ = c.curl_easy_setopt(curl, c.CURLOPT_URL, "https://www.google.com/");
_ = c.curl_easy_setopt(curl, c.CURLOPT_SSL_VERIFYPEER, @as(c_int, 0));
_ = c.curl_easy_setopt(curl, c.CURLOPT_SSL_VERIFYHOST, @as(c_int, 0));
var res = c.curl_easy_perform(curl);
```

# Building and linking example

See `build.zig` and `main_tests` linking example.
