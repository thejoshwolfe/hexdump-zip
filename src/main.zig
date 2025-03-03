const std = @import("std");

const ZipfileDumper = @import("./hexdump-zip.zig").ZipfileDumper;
const StreamingDumper = @import("./streaming.zig").StreamingDumper;

fn usage() !void {
    std.log.err(
        \\usage: [options] INPUT.zip OUTPUT.hex
        \\
        \\options:
        \\  --streaming
        \\    Enable streaming read mode.
    , .{});
    return error.Usage;
}

pub fn main() !void {
    var gpa_instance: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa_instance.deinit();
    const gpa = gpa_instance.allocator();

    var args = try std.process.argsWithAllocator(gpa);
    defer args.deinit();
    _ = args.next() orelse return usage();

    var is_streaming = false;
    var input_path_str = args.next() orelse return usage();
    if (std.mem.eql(u8, input_path_str, "--streaming")) {
        is_streaming = true;
        input_path_str = args.next() orelse return usage();
    }
    const output_path_str = args.next() orelse return usage();
    if (args.next() != null) return usage();

    var input_file = try std.fs.cwd().openFile(input_path_str, .{});
    defer input_file.close();

    var output_file = try std.fs.cwd().createFile(output_path_str, .{});
    defer output_file.close();

    if (is_streaming) {
        var dumper: StreamingDumper = .{
            .input_file = input_file,
            .output_file = output_file,
        };
        try dumper.doIt();
    } else {
        var zipfile_dumper: ZipfileDumper = undefined;
        try zipfile_dumper.init(input_file, output_file, gpa);
        defer zipfile_dumper.deinit();
        try zipfile_dumper.doIt();
    }

    return std.process.cleanExit();
}
