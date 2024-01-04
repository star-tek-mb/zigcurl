const std = @import("std");

pub fn create(b: *std.Build, target: std.zig.CrossTarget) *std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = "z",
        .target = target,
        .optimize = .ReleaseSmall,
    });
    lib.linkLibC();
    lib.addCSourceFiles(.{ .files = srcs, .flags = &.{"-std=c89"} });
    lib.installHeader("zlib/zlib.h", "zlib.h");
    lib.installHeader("zlib/zconf.h", "zconf.h");
    return lib;
}

const srcs = &.{
    "zlib/adler32.c",
    "zlib/compress.c",
    "zlib/crc32.c",
    "zlib/deflate.c",
    "zlib/gzclose.c",
    "zlib/gzlib.c",
    "zlib/gzread.c",
    "zlib/gzwrite.c",
    "zlib/inflate.c",
    "zlib/infback.c",
    "zlib/inftrees.c",
    "zlib/inffast.c",
    "zlib/trees.c",
    "zlib/uncompr.c",
    "zlib/zutil.c",
};
