const std = @import("std");

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

fn readInt16(buffer: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, buffer[offset..][0..2], .little);
}
