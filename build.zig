const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const exe = b.addExecutable("hexdump-zip", "src/hexdump-zip.zig");
    exe.setBuildMode(b.standardReleaseOptions());
    exe.linkSystemLibrary("c");
    exe.install();
    b.default_step.dependOn(&exe.step);
}
