const std = @import("std");

const Hexdumper = @import("./Hexdumper.zig");

pub const zip64_eocdr_size = 56;
pub const zip64_eocdl_size = 20;
pub const eocdr_size = 22;
pub const eocdr_search_size: u64 = zip64_eocdl_size + 0xffff + eocdr_size;

/// local file header signature
pub const lfh_signature = 0x04034b50;

/// optional data descriptor optional signature
pub const oddo_signature = 0x08074b50;
pub const oddo_signature_bytes = [4]u8{ 0x50, 0x4b, 0x07, 0x08 };

/// central file header signature
pub const cfh_signature = 0x02014b50;

/// zip64 end of central dir signature
pub const zip64_eocdr_signature = 0x06064b50;

/// zip64 end of central dir locator signature
pub const zip64_eocdl_signature = 0x07064b50;

/// end of central dir signature
pub const eocdr_signature = 0x06054b50;

pub const ExtraFieldIterator = struct {
    extra_fields: []const u8,
    cursor: u16 = 0,
    pub fn next(self: *@This()) !?ExtraField {
        if (self.cursor >= self.extra_fields.len -| 3) return null;
        const tag = readInt16(self.extra_fields, self.cursor);
        const size = readInt16(self.extra_fields, self.cursor + 2);
        if (self.cursor + 4 > self.extra_fields.len -| size) return error.ExtraFieldSizeExceedsExtraFieldsBuffer;
        const entire_buffer = self.extra_fields[self.cursor .. self.cursor + 4 + size];
        self.cursor += 4 + size;
        return .{
            .tag = tag,
            .entire_buffer = entire_buffer,
        };
    }
    pub fn trailingPadding(self: @This()) []const u8 {
        return self.extra_fields[self.cursor..];
    }
};
pub const ExtraField = struct {
    tag: u16,
    entire_buffer: []const u8,
};

fn dumpExtraFieldHeader(dumper: *Hexdumper, entire_buffer: []const u8, cursor: *usize) !void {
    dumper.indent(); // defer outdent after this.
    try dumper.readStructField(entire_buffer, 2, cursor, 2, "Tag");
    try dumper.readStructField(entire_buffer, 2, cursor, 2, "Size");
}

pub fn dumpExtraFields(
    dumper: *Hexdumper,
    offset: u64,
    buffer: []const u8,
    out_is_zip64: ?*bool,
    compressed_size: *u64,
    uncompressed_size: *u64,
    local_file_header_offset: ?*u64,
    disk_number: ?*u32,
) !void {
    var it = ExtraFieldIterator{ .extra_fields = buffer };

    while (try it.next()) |extra_field| {
        const field_buffer = extra_field.entire_buffer;
        const section_offset = offset + @as(u64, @intCast(field_buffer.ptr - buffer.ptr));
        var cursor: usize = 0;
        defer dumper.outdent(); // indented in dumpExtraFieldHeader
        switch (extra_field.tag) {
            0x0001 => {
                try dumper.writeSectionHeader(section_offset, "ZIP64 Extended Information Extra Field (0x{x:0>4})", .{extra_field.tag});
                try dumpExtraFieldHeader(dumper, field_buffer, &cursor);

                if (out_is_zip64) |is_zip64| is_zip64.* = true;
                const max_size = 8;
                if (compressed_size.* == 0xffffffff) {
                    if (cursor + 8 > field_buffer.len) return error.InternalBufferOverflow;
                    compressed_size.* = readInt64(field_buffer, cursor);
                    try dumper.readStructField(field_buffer, max_size, &cursor, 8, "Compressed Size");
                }
                if (uncompressed_size.* == 0xffffffff) {
                    if (cursor + 8 > field_buffer.len) return error.InternalBufferOverflow;
                    uncompressed_size.* = readInt64(field_buffer, cursor);
                    try dumper.readStructField(field_buffer, max_size, &cursor, 8, "Uncompressed Size");
                }
                if (local_file_header_offset != null and local_file_header_offset.?.* == 0xffffffff) {
                    if (cursor + 8 > field_buffer.len) return error.InternalBufferOverflow;
                    local_file_header_offset.?.* = readInt64(field_buffer, cursor);
                    try dumper.readStructField(field_buffer, max_size, &cursor, 8, "Local File Header Offset");
                }
                if (disk_number != null and disk_number.?.* == 0xffffffff) {
                    if (cursor + 4 > field_buffer.len) return error.InternalBufferOverflow;
                    disk_number.?.* = readInt32(field_buffer, cursor);
                    try dumper.readStructField(field_buffer, max_size, &cursor, 4, "Disk Number");
                }
            },
            0x5455 => {
                try dumper.writeSectionHeader(section_offset, "Info-ZIP Universal Time (0x{x:0>4})", .{extra_field.tag});
                try dumpExtraFieldHeader(dumper, field_buffer, &cursor);

                // See the Info-ZIP source code proginfo/extrafld.txt
                const has_mtime = 1;
                if (field_buffer[cursor..].len >= 5 and field_buffer[cursor] & has_mtime != 0) {
                    const max_size = 4;
                    try dumper.readStructField(field_buffer, max_size, &cursor, 1, "flags");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 4, "mtime");
                }
            },
            0x7875 => {
                try dumper.writeSectionHeader(section_offset, "Info-ZIP Unix 32-bit uid/gid (0x{x:0>4})", .{extra_field.tag});
                try dumpExtraFieldHeader(dumper, field_buffer, &cursor);

                // See the Info-ZIP source code proginfo/extrafld.txt
                if (field_buffer[cursor..].len >= 11 and
                    field_buffer[cursor] == 1 and // version
                    field_buffer[cursor + 1] == 4 and // UIDSize
                    field_buffer[cursor + 6] == 4 and // GIDSize
                    true)
                {
                    const max_size = 4;
                    try dumper.readStructField(field_buffer, max_size, &cursor, 1, "version (always 1)");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 1, "UIDSize (always 4)");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 4, "UID");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 1, "GIDSize (always 4)");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 4, "GID");
                }
            },
            0x7075 => {
                try dumper.writeSectionHeader(section_offset, "Info-ZIP Unicode Path (0x{x:0>4})", .{extra_field.tag});
                try dumpExtraFieldHeader(dumper, field_buffer, &cursor);

                // See the Info-ZIP source code proginfo/extrafld.txt
                if (field_buffer[cursor..].len >= 5 and field_buffer[cursor] == 1) {
                    const max_size = 4;
                    try dumper.readStructField(field_buffer, max_size, &cursor, 1, "version (always 1)");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 4, "Old Name CRC32");
                    try dumper.writeBlob(field_buffer[cursor..], .{ .encoding = .utf8 });
                    cursor = field_buffer.len;
                }
            },
            0x000a => {
                try dumper.writeSectionHeader(section_offset, "NTFS (0x{x:0>4})", .{extra_field.tag});
                try dumpExtraFieldHeader(dumper, field_buffer, &cursor);

                // This is documented in APPNOTE since version 4.5.
                if (field_buffer[cursor..].len >= 32 and
                    readInt32(field_buffer, cursor) == 0 and // Reserved
                    readInt16(field_buffer, cursor + 4) == 1 and // Tag for attribute #1
                    readInt16(field_buffer, cursor + 6) == 24 and // Size of attribute #1, in bytes (24)
                    true)
                {
                    const max_size = 8;
                    try dumper.readStructField(field_buffer, max_size, &cursor, 4, "Reserved (always 0)");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 2, "Tag (always 1)");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 2, "Size (always 24)");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 8, "Mtime");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 8, "Atime");
                    try dumper.readStructField(field_buffer, max_size, &cursor, 8, "Ctime");
                }
            },
            else => {
                try dumper.writeSectionHeader(section_offset, "Unknown Extra Field (0x{x:0>4})", .{extra_field.tag});
                try dumpExtraFieldHeader(dumper, field_buffer, &cursor);
            },
        }

        const extra = field_buffer[cursor..];
        if (extra.len > 0) {
            try dumper.writeBlob(extra, .{});
        }
    }

    const padding = it.trailingPadding();
    if (padding.len > 0) {
        const section_offset = offset + @as(u64, @intCast(padding.ptr - buffer.ptr));
        try dumper.writeSectionHeader(section_offset, "(unused space)", .{});
        dumper.indent();
        defer dumper.outdent();
        try dumper.writeBlob(padding, .{});
    }
}

fn readInt16(buffer: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, buffer[offset..][0..2], .little);
}
fn readInt32(buffer: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, buffer[offset..][0..4], .little);
}
fn readInt64(buffer: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, buffer[offset..][0..8], .little);
}
