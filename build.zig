const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const exe = b.addExecutable("hexdump-zip", "src/hexdump-zip.zig");
    exe.setBuildMode(b.standardReleaseOptions());
    b.default_step.dependOn(&exe.step);
}
