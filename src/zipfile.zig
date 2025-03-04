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
        const section_offset = offset + @as(u64, @intCast(extra_field.entire_buffer.ptr - buffer.ptr));
        switch (extra_field.tag) {
            0x0001 => try dumper.writeSectionHeader(section_offset, "ZIP64 Extended Information Extra Field (0x{x:0>4})", .{extra_field.tag}),
            else => try dumper.writeSectionHeader(section_offset, "Unknown Extra Field (0x{x:0>4})", .{extra_field.tag}),
        }
        dumper.indent();
        defer dumper.outdent();
        var cursor: usize = 0;
        try dumper.readStructField(extra_field.entire_buffer, 2, &cursor, 2, "Tag");
        try dumper.readStructField(extra_field.entire_buffer, 2, &cursor, 2, "Size");
        switch (extra_field.tag) {
            0x0001 => {
                if (out_is_zip64) |is_zip64| is_zip64.* = true;
                if (compressed_size.* == 0xffffffff) {
                    if (cursor + 8 > extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                    compressed_size.* = readInt64(extra_field.entire_buffer, cursor);
                    try dumper.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Compressed Size");
                }
                if (uncompressed_size.* == 0xffffffff) {
                    if (cursor + 8 > extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                    uncompressed_size.* = readInt64(extra_field.entire_buffer, cursor);
                    try dumper.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Uncompressed Size");
                }
                if (local_file_header_offset != null and local_file_header_offset.?.* == 0xffffffff) {
                    if (cursor + 8 > extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                    local_file_header_offset.?.* = readInt64(extra_field.entire_buffer, cursor);
                    try dumper.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Local File Header Offset");
                }
                if (disk_number != null and disk_number.?.* == 0xffffffff) {
                    if (cursor + 4 > extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                    disk_number.?.* = readInt32(extra_field.entire_buffer, cursor);
                    try dumper.readStructField(extra_field.entire_buffer, 8, &cursor, 4, "Disk Number");
                }
                const extra = extra_field.entire_buffer[cursor..];
                if (extra.len > 0) {
                    try dumper.writeBlob(extra, .{});
                }
            },
            else => {
                try dumper.writeBlob(extra_field.entire_buffer[4..], .{});
            },
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
