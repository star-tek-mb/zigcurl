const std = @import("std");
const c = @cImport({
    @cInclude("curl/curl.h");
});

test "basic" {
    _ = c.curl_global_init(c.CURL_GLOBAL_DEFAULT);
    defer c.curl_global_cleanup();
    var curl = c.curl_easy_init();
    defer c.curl_easy_cleanup(curl);
    _ = c.curl_easy_setopt(curl, c.CURLOPT_URL, "https://www.google.com/");
    _ = c.curl_easy_setopt(curl, c.CURLOPT_SSL_VERIFYPEER, @as(c_int, 0));
    _ = c.curl_easy_setopt(curl, c.CURLOPT_SSL_VERIFYHOST, @as(c_int, 0));
    var res = c.curl_easy_perform(curl);
    try std.testing.expectEqual(res, c.CURLE_OK);
}
