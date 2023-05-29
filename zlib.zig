const std = @import("std");

fn root() []const u8 {
    return std.fs.path.dirname(@src().file) orelse ".";
}

const root_path = root() ++ "/";

pub fn create(b: *std.Build, target: std.zig.CrossTarget) *std.Build.Step.Compile {
    const lib = b.addStaticLibrary(.{
        .name = "z",
        .target = target,
        .optimize = .ReleaseSmall,
    });
    lib.linkLibC();
    lib.addCSourceFiles(srcs, &.{"-std=c89"});
    lib.installHeader(root_path ++ "zlib/zlib.h", "zlib.h");
    lib.installHeader(root_path ++ "zlib/zconf.h", "zconf.h");
    return lib;
}

const srcs = &.{
    root_path ++ "zlib/adler32.c",
    root_path ++ "zlib/compress.c",
    root_path ++ "zlib/crc32.c",
    root_path ++ "zlib/deflate.c",
    root_path ++ "zlib/gzclose.c",
    root_path ++ "zlib/gzlib.c",
    root_path ++ "zlib/gzread.c",
    root_path ++ "zlib/gzwrite.c",
    root_path ++ "zlib/inflate.c",
    root_path ++ "zlib/infback.c",
    root_path ++ "zlib/inftrees.c",
    root_path ++ "zlib/inffast.c",
    root_path ++ "zlib/trees.c",
    root_path ++ "zlib/uncompr.c",
    root_path ++ "zlib/zutil.c",
};
