const std = @import("std");

const IncrementingAllocator = std.mem.IncrementingAllocator;
const Dir = std.os.Dir;
const Buffer = std.Buffer;

// This isn't the system limit, just ours.
const file_name_length_limit = 0x1000;
var main_allocator_buffer: [file_name_length_limit]u8 = undefined;
var main_allocator_impl = IncrementingAllocator.initFromBuffer(main_allocator_buffer[0..]);
var main_allocator = &main_allocator_impl.allocator;

pub fn main() -> %void {
    if (std.os.args.count() != 3) return panic_("usage: INPUT.zip OUTPUT.hex");
    const input_path_str = std.os.args.at(1);
    const output_path_str = std.os.args.at(2);

    var tmp_path = %return Buffer.init(main_allocator, output_path_str);
    %return tmp_path.append(".tmp");

    %return ensureDirExists(tmp_path);

    %return cleanOutputDir(&tmp_path);
}

fn ensureDirExists(path: &const Buffer) -> %void {
    var tmp_allocator_buffer: [file_name_length_limit]u8 = undefined;
    var tmp_allocator_impl = IncrementingAllocator.initFromBuffer(tmp_allocator_buffer[0..]);
    var tmp_allocator = &tmp_allocator_impl.allocator;

    std.os.makeDir(tmp_allocator, path.toSliceConst()) %% |err| {
        switch (err) {
            error.PathAlreadyExists => {
                // TODO: But is it really a directory?
                // Otherwise, assume it's all good.
            },
            else => return err,
        }
    };
}

fn cleanOutputDir(path: &Buffer) -> %void {
    var tmp_allocator_buffer: [std.os.page_size]u8 = undefined;
    var tmp_allocator_impl = IncrementingAllocator.initFromBuffer(tmp_allocator_buffer[0..]);
    var tmp_allocator = &tmp_allocator_impl.allocator;

    var dir = %return Dir.open(tmp_allocator, path.toSliceConst());
    defer dir.close();
    // Reset after possibly copying the name to a null-terminated buffer.
    tmp_allocator_impl.reset();
    // Now the allocator will be used to allocate the buffer for the entries.
    // We need the entire std.os.page_size available for this part,
    // so we either need to swap out the allocator live,
    // or reset it reset here.

    const original_path_len = path.len();
    while (dir.next() %% |err| switch (err) {
            // The only reason the allocator fails is if the name of something is too long.
            error.NoMem => return error.NameTooLong,
            else => return err,
        }) |entry| {
        path.appendByte('/');
        path.append(entry.name);
        defer path.resize(original_path_len);

        // Deleting a file requires even more allocations. >_<
        var deleter_allocator_buffer: [file_name_length_limit]u8 = undefined;
        var deleter_allocator_impl = IncrementingAllocator.initFromBuffer(deleter_allocator_buffer[0..]);
        var deleter_allocator = &deleter_allocator_impl.allocator;
        %return std.os.deleteFile(deleter_allocator, path.toSliceConst());
    }
}

error Panic;
fn panic_(msg: []const u8) -> error {
    %return std.io.stderr.printf("{}\n", msg);
    return error.Panic;
}
