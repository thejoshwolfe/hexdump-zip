const Builder = @import("std").build.Builder;

pub fn build(b: &Builder) void {
    const exe = b.addExecutable("hexdump-zip", "src/hexdump-zip.zig");
    exe.setBuildMode(b.standardReleaseOptions());
    exe.linkSystemLibrary("c");

    b.default_step.dependOn(&exe.step);
    b.installArtifact(exe);

    const test_step = b.step("test", "Run all the tests");
    test_step.dependOn(&b.addTest("test/index.zig").step);
}
