const std = @import("std");
const assert = std.debug.assert;

const Hexdumper = @import("./Hexdumper.zig");
const z = @import("./zipfile.zig");

pub const StreamingDumper = struct {
    input_file: std.fs.File,
    input: @TypeOf(std.io.bufferedReader(@as(std.fs.File.Reader, undefined))) = undefined,
    output_file: std.fs.File,
    output: @TypeOf(std.io.bufferedWriter(@as(std.fs.File.Writer, undefined))) = undefined,
    // have to store this in the struct, because .any() take a pointer to the writer.
    output_writer: @TypeOf(std.io.bufferedWriter(@as(std.fs.File.Writer, undefined))).Writer = undefined,
    dumper: Hexdumper = undefined,
    put_back_signature: ?[4]u8 = null,
    offset: u64 = 0,
    indentation: u2 = 0,

    const Self = @This();

    pub fn doIt(self: *Self) !void {
        self.input = std.io.bufferedReader(self.input_file.reader());
        self.output = std.io.bufferedWriter(self.output_file.writer());
        self.output_writer = self.output.writer();
        self.dumper = .{ .output = self.output_writer.any() };

        // Not sure how to make this an enum.
        var position: enum {
            start,
            local_stuff,
            central_directory,
        } = .start;

        while (true) {
            const signature = try self.peekSignature();
            switch (signature) {
                z.lfh_signature => {
                    if (!(position == .start or position == .local_stuff)) return error.WrongSignature;
                    position = .local_stuff;
                    try self.consumeLocalFile();
                },
                z.cfh_signature => {
                    if (position == .local_stuff) {
                        position = .central_directory;
                    } else if (position != .central_directory) return error.WrongSignature;
                    try self.consumeCentralFileHeader();
                },
                z.zip64_eocdr_signature => {
                    if (!(position == .start or position == .central_directory)) return error.WrongSignature;
                    try self.consumeZip64End();
                    break;
                },
                z.eocdr_signature => {
                    if (!(position == .start or position == .central_directory)) return error.WrongSignature;
                    try self.consumeEnd();
                    break;
                },
                else => return error.WrongSignature,
            }
        }

        // Assert EOF.
        if (self.input.reader().readByte()) |_| return error.ExpectedEof else |err| if (err != error.EndOfStream) return err;

        try self.output.flush();
    }

    fn consumeLocalFile(self: *Self) !void {
        const offset = self.offset;
        var lfh_buffer: [30]u8 = undefined;
        try self.readNoEof(&lfh_buffer);

        // Dump the struct.
        {
            if (offset != 0) try self.dumper.write("\n");
            try self.dumper.writeSectionHeader(offset, "Local File Header", .{});
            var lfh_cursor: usize = 0;
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 4, "Local file header signature");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "Version needed to extract (minimum)");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "General purpose bit flag");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "Compression method");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "File last modification time");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "File last modification date");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 4, "CRC-32");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 4, "Compressed size");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 4, "Uncompressed size");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "File name length (n)");
            try self.dumper.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "Extra field length (m)");
        }

        // Extract meaningful information from the header.
        const general_purpose_bit_flag = readInt16(&lfh_buffer, 6);
        const is_utf8 = general_purpose_bit_flag & 0x800 != 0;
        const is_known_size = general_purpose_bit_flag & 0x8 == 0;
        var compressed_size: u64 = readInt32(&lfh_buffer, 18);
        var uncompressed_size: u64 = readInt32(&lfh_buffer, 22);
        var is_zip64 = false;
        const file_name_length = readInt16(&lfh_buffer, 26);
        const extra_fields_length = readInt16(&lfh_buffer, 28);

        // Variable-sized header components.
        if (file_name_length > 0) {
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.write("\n");
            try self.dumper.writeSectionHeader(self.offset, "File Name", .{});
            try self.dumpBlob(file_name_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
        }
        if (extra_fields_length > 0) {
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.write("\n");
            try self.dumper.writeSectionHeader(self.offset, "Extra Fields", .{});
            try self.consumeExtraFields(extra_fields_length, &is_zip64, &compressed_size, &uncompressed_size, null, null);
        }

        // File contents.
        if (is_known_size) {
            // Known size is easy.
            if (compressed_size > 0) {
                try self.dumper.write("\n");
                try self.dumper.writeSectionHeader(self.offset, "File Contents", .{});
                try self.dumpBlob(compressed_size, compact);
            }

            // Optional data descriptor is optional
            if (z.oddo_signature == try self.peekSignature()) {
                try self.consumeDataDescriptor(is_zip64);
            }
        } else {
            // Search for data descriptor to terminate the file contents.
            try self.dumper.write("\n");
            try self.dumper.writeSectionHeader(self.offset, "File Contents With Unknown Length", .{});

            const row_length = compact.row_length;
            var row_cursor: usize = 0;
            var oddo_signature_cursor: usize = 0;
            while (true) {
                assert(self.put_back_signature == null);
                const b = try self.input.reader().readByte();
                self.offset += 1;
                if (b == z.oddo_signature_bytes[oddo_signature_cursor]) {
                    // Maybe?
                    oddo_signature_cursor += 1;
                    if (oddo_signature_cursor == 4) {
                        // Done.
                        self.put_back_signature = z.oddo_signature_bytes;
                        self.offset -= 4;
                        try self.dumper.write("\n");

                        try self.consumeDataDescriptor(is_zip64);
                        break;
                    }
                } else {
                    // Nope
                    if (oddo_signature_cursor > 0) {
                        // Flush what we've optimistically found so far.
                        const mid_buffer_row_wrap = @min(oddo_signature_cursor, row_length - row_cursor);
                        row_cursor += oddo_signature_cursor;
                        for (z.oddo_signature_bytes[0..mid_buffer_row_wrap]) |b_| {
                            try self.dumper.printf("{x:0>2}", .{b_});
                        }
                        if (row_cursor >= row_length) {
                            row_cursor -= row_length;
                            try self.dumper.printf("\n", .{});
                        }
                        for (z.oddo_signature_bytes[mid_buffer_row_wrap..oddo_signature_cursor]) |b_| {
                            try self.dumper.printf("{x:0>2}", .{b_});
                        }
                        oddo_signature_cursor = 0;
                    }
                    // Write the byte.
                    if (row_cursor >= row_length) {
                        row_cursor -= row_length;
                        try self.dumper.printf("\n", .{});
                    }
                    try self.dumper.printf("{x:0>2}", .{b});
                    row_cursor += 1;
                }
            }
        }

        // Done with Local file header, file contents, and optional data descriptor.
    }

    fn consumeDataDescriptor(self: *Self, is_zip64: bool) !void {
        try self.dumper.write("\n");
        try self.dumper.writeSectionHeader(self.offset, "Optional Data Descriptor", .{});

        var data_descriptor_buffer: [24]u8 = undefined;
        const data_descriptor_len: usize = if (is_zip64) 24 else 16;
        try self.readNoEof(data_descriptor_buffer[0..data_descriptor_len]);
        var data_descriptor_cursor: usize = 0;
        if (is_zip64) {
            try self.dumper.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 4, "optional data descriptor optional signature");
            try self.dumper.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 4, "crc-32");
            try self.dumper.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 8, "compressed size");
            try self.dumper.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 8, "uncompressed size");
        } else {
            try self.dumper.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "optional data descriptor optional signature");
            try self.dumper.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "crc-32");
            try self.dumper.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "compressed size");
            try self.dumper.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "uncompressed size");
        }
    }

    fn consumeCentralFileHeader(self: *Self) !void {
        try self.dumper.write("\n");
        try self.dumper.writeSectionHeader(self.offset, "Central Directory Entry", .{});

        var cdr_buffer: [46]u8 = undefined;
        try self.readNoEof(cdr_buffer[0..]);
        var cdr_cursor: usize = 0;

        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "Central directory file header signature");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Version made by");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Version needed to extract (minimum)");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "General purpose bit flag");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Compression method");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "File last modification time");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "File last modification date");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "CRC-32");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "Compressed size");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "Uncompressed size");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "File name length (n)");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Extra field length (m)");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "File comment length (k)");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Disk number where file starts");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Internal file attributes");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "External file attributes");
        try self.dumper.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "Relative offset of local file header");

        const general_purpose_bit_flag = readInt16(&cdr_buffer, 8);
        const is_utf8 = general_purpose_bit_flag & 0x800 != 0;
        var compressed_size: u64 = readInt32(&cdr_buffer, 20);
        var uncompressed_size: u64 = readInt32(&cdr_buffer, 20);
        var local_file_header_offset: u64 = readInt32(&cdr_buffer, 42);
        var disk_number: u32 = readInt16(&cdr_buffer, 34);
        const file_name_length = readInt16(&cdr_buffer, 28);
        const extra_fields_length = readInt16(&cdr_buffer, 30);
        const file_comment_length = readInt16(&cdr_buffer, 32);

        if (file_name_length > 0) {
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.writeSectionHeader(self.offset, "File name", .{});
            try self.dumpBlob(file_name_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
        }
        if (extra_fields_length > 0) {
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.writeSectionHeader(self.offset, "Extra Fields", .{});
            try self.consumeExtraFields(
                extra_fields_length,
                null,
                &compressed_size,
                &uncompressed_size,
                &local_file_header_offset,
                &disk_number,
            );
        }
        if (file_comment_length > 0) {
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.writeSectionHeader(self.offset, "File Comment", .{});
            try self.dumpBlob(file_comment_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
        }
    }

    fn consumeZip64End(self: *Self) !void {
        try self.dumper.write("\n");
        try self.dumper.writeSectionHeader(self.offset, "zip64 end of central directory record", .{});
        {
            var buffer: [56]u8 = undefined;
            try self.readNoEof(buffer[0..]);

            var cursor: usize = 0;
            const max_size = 8;
            try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "zip64 end of central directory record signature");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 8, "size of zip64 end of central directory record");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 2, "version made by");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 2, "version needed to extract");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "number of this disk");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "number of the disk with the start of the central directory");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 8, "total number of entries in the central directory on this disk");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 8, "total number of entries in the central directory");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 8, "size of the central directory");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 8, "offset of start of central directory with respect to the starting disk number");
            assert(cursor == buffer.len);
            const zip64_extensible_data_sector_size = readInt64(&buffer, 4) -| 44;
            if (zip64_extensible_data_sector_size > 0) {
                self.dumper.indent();
                defer self.dumper.outdent();
                try self.dumper.writeSectionHeader(self.offset, "zip64 extensible data sector", .{});
                try self.dumpBlob(zip64_extensible_data_sector_size, compact);
            }
        }

        if (z.zip64_eocdl_signature != try self.peekSignature()) return error.ExpectedZip64EndOfCentralDirectoryLocator;
        try self.dumper.write("\n");
        try self.dumper.writeSectionHeader(self.offset, "zip64 end of central directory locator", .{});
        {
            var buffer: [20]u8 = undefined;
            try self.readNoEof(buffer[0..]);
            var cursor: usize = 0;

            const max_size = 8;
            try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "zip64 end of central dir locator signature");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "number of the disk with the start of the zip64 end of central directory");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 8, "relative offset of the zip64 end of central directory record");
            try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "total number of disks");
            assert(cursor == buffer.len);
        }

        if (z.eocdr_signature != try self.peekSignature()) return error.ExpectedEndOfCentralDirectoryRecord;
        try self.consumeEnd();
    }

    fn consumeEnd(self: *Self) !void {
        try self.dumper.write("\n");
        try self.dumper.writeSectionHeader(self.offset, "End of central directory record", .{});

        var buffer: [22]u8 = undefined;
        try self.readNoEof(buffer[0..]);
        var cursor: usize = 0;

        const max_size = 4;
        try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "End of central directory signature");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 2, "Number of this disk");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 2, "Disk where central directory starts");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 2, "Number of central directory records on this disk");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 2, "Total number of central directory records");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "Size of central directory (bytes)");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "Offset of start of central directory, relative to start of archive");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 2, "Comment Length");
        assert(cursor == buffer.len);

        const comment_length = readInt16(&buffer, 20);
        if (comment_length > 0) {
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.writeSectionHeader(self.offset, ".ZIP file comment", .{});
            try self.dumpBlob(comment_length, .{ .encoding = .cp437 });
        }
    }

    const compact = Hexdumper.BlobConfig{
        .row_length = 512,
        .spaces = false,
    };

    fn dumpBlob(self: *Self, length: u64, config: Hexdumper.BlobConfig) !void {
        var partial_utf8_state = Hexdumper.PartialUtf8State{};
        var cursor: u64 = 0;
        while (cursor < length) {
            var buffer: [0x1000]u8 = undefined;
            const buffer_len = @min(buffer.len, length - cursor);
            try self.readNoEof(buffer[0..buffer_len]);
            const is_end = cursor + buffer_len == length;

            try self.dumper.writeBlobPart(buffer[0..buffer_len], config, cursor == 0, is_end, &partial_utf8_state);

            cursor += buffer_len;
        }
    }

    fn consumeExtraFields(
        self: *Self,
        extra_fields_length: u16,
        out_is_zip64: ?*bool,
        compressed_size: *u64,
        uncompressed_size: *u64,
        local_file_header_offset: ?*u64,
        disk_number: ?*u32,
    ) !void {
        const offset = self.offset;
        var buf: [0xffff]u8 = undefined;
        const buffer = buf[0..extra_fields_length];
        try self.readNoEof(buffer);
        var it = z.ExtraFieldIterator{ .extra_fields = buffer };

        while (try it.next()) |extra_field| {
            const section_offset = offset + @as(u64, @intCast(extra_field.entire_buffer.ptr - buffer.ptr));
            switch (extra_field.tag) {
                0x0001 => try self.dumper.writeSectionHeader(section_offset, "ZIP64 Extended Information Extra Field (0x{x:0>4})", .{extra_field.tag}),
                else => try self.dumper.writeSectionHeader(section_offset, "Unknown Extra Field (0x{x:0>4})", .{extra_field.tag}),
            }
            self.dumper.indent();
            defer self.dumper.outdent();
            var cursor: usize = 0;
            try self.dumper.readStructField(extra_field.entire_buffer, 2, &cursor, 2, "Tag");
            try self.dumper.readStructField(extra_field.entire_buffer, 2, &cursor, 2, "Size");
            switch (extra_field.tag) {
                0x0001 => {
                    if (out_is_zip64) |is_zip64| is_zip64.* = true;
                    if (compressed_size.* == 0xffffffff) {
                        if (cursor + 8 < extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                        compressed_size.* = readInt64(extra_field.entire_buffer, cursor);
                        try self.dumper.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Compressed Size");
                    }
                    if (uncompressed_size.* == 0xffffffff) {
                        if (cursor + 8 < extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                        uncompressed_size.* = readInt64(extra_field.entire_buffer, cursor);
                        try self.dumper.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Uncompressed Size");
                    }
                    if (local_file_header_offset != null and local_file_header_offset.?.* == 0xffffffff) {
                        if (cursor + 8 < extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                        local_file_header_offset.?.* = readInt64(extra_field.entire_buffer, cursor);
                        try self.dumper.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Local File Header Offset");
                    }
                    if (disk_number != null and disk_number.?.* == 0xffffffff) {
                        if (cursor + 4 < extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                        disk_number.?.* = readInt32(extra_field.entire_buffer, cursor);
                        try self.dumper.readStructField(extra_field.entire_buffer, 8, &cursor, 4, "Disk Number");
                    }
                    const extra = extra_field.entire_buffer[cursor..];
                    if (extra.len > 0) {
                        try self.dumper.writeBlob(extra, .{});
                    }
                },
                else => {
                    try self.dumper.writeBlob(extra_field.entire_buffer[4..], .{});
                },
            }
        }

        const padding = it.trailingPadding();
        if (padding.len > 0) {
            const section_offset = offset + @as(u64, @intCast(padding.ptr - buffer.ptr));
            try self.dumper.writeSectionHeader(section_offset, "(unused space)", .{});
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.writeBlob(padding, .{});
        }
    }

    fn peekSignature(self: *Self) !u32 {
        var sig_buf: [4]u8 = undefined;
        try self.readNoEof(&sig_buf);
        const signature = std.mem.readInt(u32, &sig_buf, .little);
        self.put_back_signature = sig_buf;
        self.offset -= 4;
        return signature;
    }

    fn readNoEof(self: *Self, buffer: []u8) !void {
        if (self.put_back_signature) |sig_buf| {
            @memcpy(buffer[0..4], &sig_buf);
            self.put_back_signature = null;
            try self.input.reader().readNoEof(buffer[4..]);
        } else {
            try self.input.reader().readNoEof(buffer);
        }
        self.offset += buffer.len;
    }
};

fn readInt16(buffer: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, buffer[offset..][0..2], .little);
}
fn readInt32(buffer: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, buffer[offset..][0..4], .little);
}
fn readInt64(buffer: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, buffer[offset..][0..8], .little);
}
