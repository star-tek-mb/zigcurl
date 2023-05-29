const std = @import("std");
const curl = @import("curl.zig");
const zlib = @import("zlib.zig");
const mbedtls = @import("mbedtls.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const z = zlib.create(b, target, optimize);
    const tls = mbedtls.create(b, target, optimize);
    const lib = curl.create(b, target, optimize);
    lib.linkLibrary(z);
    lib.linkLibrary(tls);
    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .name = "test",
        .root_source_file = .{ .path = "src/test.zig" },
        .target = target,
        .optimize = optimize,
    });
    main_tests.linkLibrary(lib);
    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
