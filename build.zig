const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{
        .name = "hexdump-zip",
        .root_source_file = .{
            .path = "src/hexdump-zip.zig"
        },
        .target = target,
        .optimize = optimize,
    });
    exe.linkSystemLibrary("c");
    b.installArtifact(exe);
}
