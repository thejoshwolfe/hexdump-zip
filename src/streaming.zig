const std = @import("std");
const assert = std.debug.assert;

fn usage() !void {
    std.log.err("usage: INPUT.zip OUTPUT.hex", .{});
    return error.Usage;
}

pub fn main() !void {
    var gpa_instance: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa_instance.deinit();
    const gpa = gpa_instance.allocator();

    var args = try std.process.argsWithAllocator(gpa);
    defer args.deinit();
    _ = args.next() orelse return usage();
    const input_path_str = args.next() orelse return usage();
    const output_path_str = args.next() orelse return usage();
    if (args.next() != null) return usage();

    var input_file = try std.fs.cwd().openFile(input_path_str, .{});
    defer input_file.close();

    var output_file = try std.fs.cwd().createFile(output_path_str, .{});
    defer output_file.close();

    var dumper: StreamingDumper = .{
        .input_file = input_file,
        .output_file = output_file,
    };
    try dumper.doIt();

    return std.process.cleanExit();
}

const error_character = "\xef\xbf\xbd";

const zip64_eocdr_size = 56;
const zip64_eocdl_size = 20;
const eocdr_size = 22;
const eocdr_search_size: u64 = zip64_eocdl_size + 0xffff + eocdr_size;

/// local file header signature
const lfh_signature = 0x04034b50;

/// optional data descriptor optional signature
const oddo_signature = 0x08074b50;
const oddo_signature_bytes = [4]u8{ 0x50, 0x4b, 0x07, 0x08 };

/// central file header signature
const cfh_signature = 0x02014b50;

/// zip64 end of central dir signature
const zip64_eocdr_signature = 0x06064b50;

/// zip64 end of central dir locator signature
const zip64_eocdl_signature = 0x07064b50;

/// end of central dir signature
const eocdr_signature = 0x06054b50;

const StreamingDumper = struct {
    input_file: std.fs.File,
    input: @TypeOf(std.io.bufferedReader(@as(std.fs.File.Reader, undefined))) = undefined,
    output_file: std.fs.File,
    output: @TypeOf(std.io.bufferedWriter(@as(std.fs.File.Writer, undefined))) = undefined,
    put_back_signature: ?[4]u8 = null,
    offset: u64 = 0,
    indentation: u2 = 0,

    const Self = @This();

    pub fn doIt(self: *Self) !void {
        self.input = std.io.bufferedReader(self.input_file.reader());
        self.output = std.io.bufferedWriter(self.output_file.writer());

        // Not sure how to make this an enum.
        var position: enum {
            start,
            local_stuff,
            central_directory,
        } = .start;

        while (true) {
            const signature = try self.peekSignature();
            switch (signature) {
                lfh_signature => {
                    if (!(position == .start or position == .local_stuff)) return error.WrongSignature;
                    position = .local_stuff;
                    try self.consumeLocalFile();
                },
                cfh_signature => {
                    if (position == .local_stuff) {
                        position = .central_directory;
                    } else if (position != .central_directory) return error.WrongSignature;
                    try self.consumeCentralFileHeader();
                },
                zip64_eocdr_signature => {
                    if (!(position == .start or position == .central_directory)) return error.WrongSignature;
                    try self.consumeZip64End();
                    break;
                },
                eocdr_signature => {
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
            if (offset != 0) try self.write("\n");
            try self.writeSectionHeader(offset, "Local File Header", .{});
            var lfh_cursor: usize = 0;
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 4, "Local file header signature");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "Version needed to extract (minimum)");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "General purpose bit flag");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "Compression method");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "File last modification time");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "File last modification date");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 4, "CRC-32");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 4, "Compressed size");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 4, "Uncompressed size");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "File name length (n)");
            try self.readStructField(&lfh_buffer, 4, &lfh_cursor, 2, "Extra field length (m)");
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
            self.indent();
            defer self.outdent();
            try self.write("\n");
            try self.writeSectionHeader(self.offset, "File Name", .{});
            try self.dumpBlob(file_name_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
        }
        if (extra_fields_length > 0) {
            self.indent();
            defer self.outdent();
            try self.write("\n");
            try self.writeSectionHeader(self.offset, "Extra Fields", .{});
            try self.consumeExtraFields(extra_fields_length, &is_zip64, &compressed_size, &uncompressed_size, null, null);
        }

        // File contents.
        if (is_known_size) {
            // Known size is easy.
            if (compressed_size > 0) {
                try self.write("\n");
                try self.writeSectionHeader(self.offset, "File Contents", .{});
                try self.dumpBlob(compressed_size, compact);
            }

            // Optional data descriptor is optional
            if (oddo_signature == try self.peekSignature()) {
                try self.consumeDataDescriptor(is_zip64);
            }
        } else {
            // Search for data descriptor to terminate the file contents.
            try self.write("\n");
            try self.writeSectionHeader(self.offset, "File Contents With Unknown Length", .{});

            const row_length = compact.row_length;
            var row_cursor: usize = 0;
            var oddo_signature_cursor: usize = 0;
            while (true) {
                assert(self.put_back_signature == null);
                const b = try self.input.reader().readByte();
                self.offset += 1;
                if (b == oddo_signature_bytes[oddo_signature_cursor]) {
                    // Maybe?
                    oddo_signature_cursor += 1;
                    if (oddo_signature_cursor == 4) {
                        // Done.
                        self.put_back_signature = oddo_signature_bytes;
                        self.offset -= 4;
                        try self.write("\n");

                        try self.consumeDataDescriptor(is_zip64);
                        break;
                    }
                } else {
                    // Nope
                    if (oddo_signature_cursor > 0) {
                        // Flush what we've optimistically found so far.
                        const mid_buffer_row_wrap = @min(oddo_signature_cursor, row_length - row_cursor);
                        row_cursor += oddo_signature_cursor;
                        for (oddo_signature_bytes[0..mid_buffer_row_wrap]) |b_| {
                            try self.printf("{x:0>2}", .{b_});
                        }
                        if (row_cursor >= row_length) {
                            row_cursor -= row_length;
                            try self.printf("\n", .{});
                        }
                        for (oddo_signature_bytes[mid_buffer_row_wrap..oddo_signature_cursor]) |b_| {
                            try self.printf("{x:0>2}", .{b_});
                        }
                        oddo_signature_cursor = 0;
                    }
                    // Write the byte.
                    if (row_cursor >= row_length) {
                        row_cursor -= row_length;
                        try self.printf("\n", .{});
                    }
                    try self.printf("{x:0>2}", .{b});
                    row_cursor += 1;
                }
            }
        }

        // Done with Local file header, file contents, and optional data descriptor.
    }

    fn consumeDataDescriptor(self: *Self, is_zip64: bool) !void {
        try self.write("\n");
        try self.writeSectionHeader(self.offset, "Optional Data Descriptor", .{});

        var data_descriptor_buffer: [24]u8 = undefined;
        const data_descriptor_len: usize = if (is_zip64) 24 else 16;
        try self.readNoEof(data_descriptor_buffer[0..data_descriptor_len]);
        var data_descriptor_cursor: usize = 0;
        if (is_zip64) {
            try self.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 4, "optional data descriptor optional signature");
            try self.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 4, "crc-32");
            try self.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 8, "compressed size");
            try self.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 8, "uncompressed size");
        } else {
            try self.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "optional data descriptor optional signature");
            try self.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "crc-32");
            try self.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "compressed size");
            try self.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "uncompressed size");
        }
    }

    fn consumeCentralFileHeader(self: *Self) !void {
        try self.write("\n");
        try self.writeSectionHeader(self.offset, "Central Directory Entry", .{});

        var cdr_buffer: [46]u8 = undefined;
        try self.readNoEof(cdr_buffer[0..]);
        var cdr_cursor: usize = 0;

        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "Central directory file header signature");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Version made by");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Version needed to extract (minimum)");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "General purpose bit flag");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Compression method");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "File last modification time");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "File last modification date");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "CRC-32");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "Compressed size");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "Uncompressed size");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "File name length (n)");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Extra field length (m)");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "File comment length (k)");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Disk number where file starts");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 2, "Internal file attributes");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "External file attributes");
        try self.readStructField(&cdr_buffer, 4, &cdr_cursor, 4, "Relative offset of local file header");

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
            self.indent();
            defer self.outdent();
            try self.writeSectionHeader(self.offset, "File name", .{});
            try self.dumpBlob(file_name_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
        }
        if (extra_fields_length > 0) {
            self.indent();
            defer self.outdent();
            try self.writeSectionHeader(self.offset, "Extra Fields", .{});
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
            self.indent();
            defer self.outdent();
            try self.writeSectionHeader(self.offset, "File Comment", .{});
            try self.dumpBlob(file_comment_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
        }
    }

    fn consumeZip64End(self: *Self) !void {
        try self.write("\n");
        try self.writeSectionHeader(self.offset, "zip64 end of central directory record", .{});
        {
            var buffer: [56]u8 = undefined;
            try self.readNoEof(buffer[0..]);

            var cursor: usize = 0;
            const max_size = 8;
            try self.readStructField(&buffer, max_size, &cursor, 4, "zip64 end of central directory record signature");
            try self.readStructField(&buffer, max_size, &cursor, 8, "size of zip64 end of central directory record");
            try self.readStructField(&buffer, max_size, &cursor, 2, "version made by");
            try self.readStructField(&buffer, max_size, &cursor, 2, "version needed to extract");
            try self.readStructField(&buffer, max_size, &cursor, 4, "number of this disk");
            try self.readStructField(&buffer, max_size, &cursor, 4, "number of the disk with the start of the central directory");
            try self.readStructField(&buffer, max_size, &cursor, 8, "total number of entries in the central directory on this disk");
            try self.readStructField(&buffer, max_size, &cursor, 8, "total number of entries in the central directory");
            try self.readStructField(&buffer, max_size, &cursor, 8, "size of the central directory");
            try self.readStructField(&buffer, max_size, &cursor, 8, "offset of start of central directory with respect to the starting disk number");
            assert(cursor == buffer.len);
            const zip64_extensible_data_sector_size = readInt64(&buffer, 4) -| 44;
            if (zip64_extensible_data_sector_size > 0) {
                self.indent();
                defer self.outdent();
                try self.writeSectionHeader(self.offset, "zip64 extensible data sector", .{});
                try self.dumpBlob(zip64_extensible_data_sector_size, compact);
            }
        }

        if (zip64_eocdl_signature != try self.peekSignature()) return error.ExpectedZip64EndOfCentralDirectoryLocator;
        try self.write("\n");
        try self.writeSectionHeader(self.offset, "zip64 end of central directory locator", .{});
        {
            var buffer: [20]u8 = undefined;
            try self.readNoEof(buffer[0..]);
            var cursor: usize = 0;

            const max_size = 8;
            try self.readStructField(&buffer, max_size, &cursor, 4, "zip64 end of central dir locator signature");
            try self.readStructField(&buffer, max_size, &cursor, 4, "number of the disk with the start of the zip64 end of central directory");
            try self.readStructField(&buffer, max_size, &cursor, 8, "relative offset of the zip64 end of central directory record");
            try self.readStructField(&buffer, max_size, &cursor, 4, "total number of disks");
            assert(cursor == buffer.len);
        }

        if (eocdr_signature != try self.peekSignature()) return error.ExpectedEndOfCentralDirectoryRecord;
        try self.consumeEnd();
    }

    fn consumeEnd(self: *Self) !void {
        try self.write("\n");
        try self.writeSectionHeader(self.offset, "End of central directory record", .{});

        var buffer: [22]u8 = undefined;
        try self.readNoEof(buffer[0..]);
        var cursor: usize = 0;

        const max_size = 4;
        try self.readStructField(&buffer, max_size, &cursor, 4, "End of central directory signature");
        try self.readStructField(&buffer, max_size, &cursor, 2, "Number of this disk");
        try self.readStructField(&buffer, max_size, &cursor, 2, "Disk where central directory starts");
        try self.readStructField(&buffer, max_size, &cursor, 2, "Number of central directory records on this disk");
        try self.readStructField(&buffer, max_size, &cursor, 2, "Total number of central directory records");
        try self.readStructField(&buffer, max_size, &cursor, 4, "Size of central directory (bytes)");
        try self.readStructField(&buffer, max_size, &cursor, 4, "Offset of start of central directory, relative to start of archive");
        try self.readStructField(&buffer, max_size, &cursor, 2, "Comment Length");
        assert(cursor == buffer.len);

        const comment_length = readInt16(&buffer, 20);
        if (comment_length > 0) {
            self.indent();
            defer self.outdent();
            try self.writeSectionHeader(self.offset, ".ZIP file comment", .{});
            try self.dumpBlob(comment_length, .{ .encoding = .cp437 });
        }
    }

    const PartialUtf8State = struct {
        codepoint: [4]u8 = undefined,
        bytes_saved: u2 = 0,
        bytes_remaining: u2 = 0,
    };
    const BlobConfig = struct {
        row_length: u16 = 16,
        spaces: bool = true,
        encoding: enum {
            none,
            cp437,
            utf8,
        } = .none,
    };
    const compact = BlobConfig{
        .row_length = 512,
        .spaces = false,
    };

    fn dumpBlob(self: *Self, length: u64, config: BlobConfig) !void {
        var partial_utf8_state = PartialUtf8State{};
        var cursor: u64 = 0;
        while (cursor < length) {
            var buffer: [0x1000]u8 = undefined;
            const buffer_len = @min(buffer.len, length - cursor);
            try self.readNoEof(buffer[0..buffer_len]);
            const is_end = cursor + buffer_len == length;

            try self.writeBlobPart(buffer[0..buffer_len], config, cursor == 0, is_end, &partial_utf8_state);

            cursor += buffer_len;
        }
    }

    fn writeBlob(self: *Self, buffer: []const u8, config: BlobConfig) !void {
        var partial_utf8_state = PartialUtf8State{};
        try self.writeBlobPart(buffer, config, true, true, &partial_utf8_state);
    }
    fn writeBlobPart(self: *Self, buffer: []const u8, config: BlobConfig, is_beginning: bool, is_end: bool, partial_utf8_state: *PartialUtf8State) !void {
        var cursor: usize = 0;
        while (cursor < buffer.len) : (cursor += config.row_length) {
            const row_end = @min(cursor + config.row_length, buffer.len);
            try self.writeBlobRow(
                buffer[cursor..row_end],
                config,
                is_beginning and cursor == 0,
                is_end and row_end == buffer.len,
                partial_utf8_state,
            );
        }
    }

    fn writeBlobRow(self: *Self, row: []const u8, config: BlobConfig, is_beginning: bool, is_end: bool, partial_utf8_state: *PartialUtf8State) !void {
        assert(row.len > 0);

        try self.printIndentation();

        // Hex representation.
        for (row, 0..) |b, i| {
            if (config.spaces and i > 0) try self.write(" ");
            try self.printf("{x:0>2}", .{b});
        }

        if (!is_beginning and config.encoding != .none) {
            // Fill out the end of the last row with spaces.
            var i: usize = row.len;
            while (i < config.row_length) : (i += 1) {
                assert(is_end);
                try self.write("   ");
            }
        }
        switch (config.encoding) {
            .none => {},
            .cp437 => {
                try self.write(" ; cp437\"");
                for (row) |c| {
                    switch (c) {
                        '"', '\\' => {
                            const content = [2]u8{ '\\', c };
                            try self.write(&content);
                        },
                        else => {
                            try self.write(cp437[c]);
                        },
                    }
                }
                try self.write("\"");
            },
            .utf8 => {
                try self.write(" ; utf8\"");

                // Input is utf8; output is utf8.
                var i: usize = 0;
                if (partial_utf8_state.bytes_remaining > 0) {
                    // Finish writing partial codepoint.
                    while (i < partial_utf8_state.bytes_remaining) : (i += 1) {
                        partial_utf8_state.codepoint[partial_utf8_state.bytes_saved + i] = row[i];
                    }
                    try self.writeEscapedCodepoint(partial_utf8_state.codepoint[0 .. partial_utf8_state.bytes_saved + partial_utf8_state.bytes_remaining]);
                    partial_utf8_state.bytes_saved = 0;
                    partial_utf8_state.bytes_remaining = 0;
                }

                while (i < row.len) : (i += 1) {
                    const utf8_length = std.unicode.utf8ByteSequenceLength(row[i]) catch {
                        // Invalid utf8 start byte.
                        try self.write(error_character);
                        continue;
                    };

                    if (i + utf8_length > row.len) {
                        // Save partial codepoint for next row.
                        if (is_end) {
                            // There is no next row.
                            try self.write(error_character);
                            break;
                        }
                        var j: usize = 0;
                        while (j < row.len - i) : (j += 1) {
                            partial_utf8_state.codepoint[j] = row[i + j];
                        }
                        partial_utf8_state.bytes_saved = @intCast(j);
                        partial_utf8_state.bytes_remaining = @intCast(utf8_length - j);
                        break;
                    }

                    // We have a complete codepoint on this row.
                    try self.writeEscapedCodepoint(row[i .. i + utf8_length]);
                    i += utf8_length - 1;
                }
                try self.write("\"");
            },
        }
        try self.write("\n");
    }

    fn writeEscapedCodepoint(self: *Self, byte_sequence: []const u8) !void {
        const codepoint = std.unicode.utf8Decode(byte_sequence) catch {
            // invalid utf8 sequence becomes a single error character.
            return self.write(error_character);
        };
        // some special escapes
        switch (codepoint) {
            '\n' => return self.write("\\n"),
            '\r' => return self.write("\\r"),
            '\t' => return self.write("\\t"),
            '"' => return self.write("\\\""),
            '\\' => return self.write("\\\\"),
            else => {},
        }
        // numeric escapes
        switch (codepoint) {
            // ascii control codes
            0...0x1f, 0x7f => return self.printf("\\x{x:0>2}", .{codepoint}),
            // unicode newline characters
            0x805, 0x2028, 0x2029 => return self.printf("\\u{x:0>4}", .{codepoint}),
            else => {},
        }
        // literal character
        return self.write(byte_sequence);
    }

    fn writeSectionHeader(self: *Self, offset: u64, comptime fmt: []const u8, args: anytype) !void {
        try self.printIndentation();
        try self.printf(":0x{x} ; ", .{offset});
        try self.printf(fmt, args);
        try self.write("\n");
    }

    fn readStructField(
        self: *Self,
        buffer: []const u8,
        comptime max_size: usize,
        cursor: *usize,
        comptime size: usize,
        name: []const u8,
    ) !void {
        comptime std.debug.assert(size <= max_size);
        const decimal_width_str = comptime switch (max_size) {
            2 => "5",
            4 => "10",
            8 => "20",
            else => unreachable,
        };

        try self.printIndentation();
        switch (size) {
            2 => {
                const value = readInt16(buffer, cursor.*);
                try self.printf( //
                    "{x:0>2} {x:0>2}" ++ ("   " ** (max_size - size)) ++
                    " ; \"{s}{s}\"" ++ (" " ** (max_size - size)) ++
                    " ; {d:0>" ++ decimal_width_str ++ "}" ++
                    " ; 0x{x:0>4}" ++ ("  " ** (max_size - size)) ++
                    " ; {s}" ++
                    "\n", .{
                    buffer[cursor.* + 0],
                    buffer[cursor.* + 1],
                    cp437[buffer[cursor.* + 0]],
                    cp437[buffer[cursor.* + 1]],
                    value,
                    value,
                    name,
                });
            },
            4 => {
                const value = readInt32(buffer, cursor.*);
                try self.printf( //
                    "{x:0>2} {x:0>2} {x:0>2} {x:0>2}" ++ ("   " ** (max_size - size)) ++
                    " ; \"{s}{s}{s}{s}\"" ++ (" " ** (max_size - size)) ++
                    " ; {d:0>" ++ decimal_width_str ++ "}" ++
                    " ; 0x{x:0>8}" ++ ("  " ** (max_size - size)) ++
                    " ; {s}" ++
                    "\n", .{
                    buffer[cursor.* + 0],
                    buffer[cursor.* + 1],
                    buffer[cursor.* + 2],
                    buffer[cursor.* + 3],
                    cp437[buffer[cursor.* + 0]],
                    cp437[buffer[cursor.* + 1]],
                    cp437[buffer[cursor.* + 2]],
                    cp437[buffer[cursor.* + 3]],
                    value,
                    value,
                    name,
                });
            },
            8 => {
                const value = readInt64(buffer, cursor.*);
                try self.printf( //
                    "{x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2} {x:0>2}" ++ ("   " ** (max_size - size)) ++
                    " ; \"{s}{s}{s}{s}{s}{s}{s}{s}\"" ++ (" " ** (max_size - size)) ++
                    " ; {d:0>" ++ decimal_width_str ++ "}" ++
                    " ; 0x{x:0>16}" ++ ("  " ** (max_size - size)) ++
                    " ; {s}" ++
                    "\n", .{
                    buffer[cursor.* + 0],
                    buffer[cursor.* + 1],
                    buffer[cursor.* + 2],
                    buffer[cursor.* + 3],
                    buffer[cursor.* + 4],
                    buffer[cursor.* + 5],
                    buffer[cursor.* + 6],
                    buffer[cursor.* + 7],
                    cp437[buffer[cursor.* + 0]],
                    cp437[buffer[cursor.* + 1]],
                    cp437[buffer[cursor.* + 2]],
                    cp437[buffer[cursor.* + 3]],
                    cp437[buffer[cursor.* + 4]],
                    cp437[buffer[cursor.* + 5]],
                    cp437[buffer[cursor.* + 6]],
                    cp437[buffer[cursor.* + 7]],
                    value,
                    value,
                    name,
                });
            },
            else => unreachable,
        }
        cursor.* += size;
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
        var it = ExtraFieldIterator{ .extra_fields = buffer };

        while (try it.next()) |extra_field| {
            const section_offset = offset + @as(u64, @intCast(extra_field.entire_buffer.ptr - buffer.ptr));
            switch (extra_field.tag) {
                0x0001 => try self.writeSectionHeader(section_offset, "ZIP64 Extended Information Extra Field (0x{x:0>4})", .{extra_field.tag}),
                else => try self.writeSectionHeader(section_offset, "Unknown Extra Field (0x{x:0>4})", .{extra_field.tag}),
            }
            self.indent();
            defer self.outdent();
            var cursor: usize = 0;
            try self.readStructField(extra_field.entire_buffer, 2, &cursor, 2, "Tag");
            try self.readStructField(extra_field.entire_buffer, 2, &cursor, 2, "Size");
            switch (extra_field.tag) {
                0x0001 => {
                    if (out_is_zip64) |is_zip64| is_zip64.* = true;
                    if (compressed_size.* == 0xffffffff) {
                        if (cursor + 8 < extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                        compressed_size.* = readInt64(extra_field.entire_buffer, cursor);
                        try self.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Compressed Size");
                    }
                    if (uncompressed_size.* == 0xffffffff) {
                        if (cursor + 8 < extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                        uncompressed_size.* = readInt64(extra_field.entire_buffer, cursor);
                        try self.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Uncompressed Size");
                    }
                    if (local_file_header_offset != null and local_file_header_offset.?.* == 0xffffffff) {
                        if (cursor + 8 < extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                        local_file_header_offset.?.* = readInt64(extra_field.entire_buffer, cursor);
                        try self.readStructField(extra_field.entire_buffer, 8, &cursor, 8, "Local File Header Offset");
                    }
                    if (disk_number != null and disk_number.?.* == 0xffffffff) {
                        if (cursor + 4 < extra_field.entire_buffer.len) return error.InternalBufferOverflow;
                        disk_number.?.* = readInt32(extra_field.entire_buffer, cursor);
                        try self.readStructField(extra_field.entire_buffer, 8, &cursor, 4, "Disk Number");
                    }
                    const extra = extra_field.entire_buffer[cursor..];
                    if (extra.len > 0) {
                        try self.writeBlob(extra, .{});
                    }
                },
                else => {
                    try self.writeBlob(extra_field.entire_buffer[4..], .{});
                },
            }
        }

        const padding = it.trailingPadding();
        if (padding.len > 0) {
            const section_offset = offset + @as(u64, @intCast(padding.ptr - buffer.ptr));
            try self.writeSectionHeader(section_offset, "(unused space)", .{});
            self.indent();
            defer self.outdent();
            try self.writeBlob(padding, .{});
        }
    }

    const ExtraFieldIterator = struct {
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
    const ExtraField = struct {
        tag: u16,
        entire_buffer: []const u8,
    };

    fn indent(self: *Self) void {
        self.indentation += 1;
    }
    fn outdent(self: *Self) void {
        self.indentation -= 1;
    }
    fn printIndentation(self: *Self) !void {
        {
            var i: u2 = 0;
            while (i < self.indentation) : (i += 1) {
                try self.write("  ");
            }
        }
    }
    fn write(self: *Self, str: []const u8) !void {
        try self.output.writer().writeAll(str);
    }
    fn printf(self: *Self, comptime fmt: []const u8, args: anytype) !void {
        try self.output.writer().print(fmt, args);
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

const cp437 = [_][]const u8{
    "�", "☺", "☻", "♥", "♦", "♣", "♠", "•", "◘", "○", "◙", "♂", "♀", "♪", "♫", "☼",
    "►", "◄", "↕", "‼", "¶",  "§",  "▬", "↨", "↑", "↓", "→", "←", "∟", "↔", "▲", "▼",
    " ",   "!",   "\"",  "#",   "$",   "%",   "&",   "'",   "(",   ")",   "*",   "+",   ",",   "-",   ".",   "/",
    "0",   "1",   "2",   "3",   "4",   "5",   "6",   "7",   "8",   "9",   ":",   ";",   "<",   "=",   ">",   "?",
    "@",   "A",   "B",   "C",   "D",   "E",   "F",   "G",   "H",   "I",   "J",   "K",   "L",   "M",   "N",   "O",
    "P",   "Q",   "R",   "S",   "T",   "U",   "V",   "W",   "X",   "Y",   "Z",   "[",   "\\",  "]",   "^",   "_",
    "`",   "a",   "b",   "c",   "d",   "e",   "f",   "g",   "h",   "i",   "j",   "k",   "l",   "m",   "n",   "o",
    "p",   "q",   "r",   "s",   "t",   "u",   "v",   "w",   "x",   "y",   "z",   "{",   "|",   "}",   "~",   "⌂",
    "Ç",  "ü",  "é",  "â",  "ä",  "à",  "å",  "ç",  "ê",  "ë",  "è",  "ï",  "î",  "ì",  "Ä",  "Å",
    "É",  "æ",  "Æ",  "ô",  "ö",  "ò",  "û",  "ù",  "ÿ",  "Ö",  "Ü",  "¢",  "£",  "¥",  "₧", "ƒ",
    "á",  "í",  "ó",  "ú",  "ñ",  "Ñ",  "ª",  "º",  "¿",  "⌐", "¬",  "½",  "¼",  "¡",  "«",  "»",
    "░", "▒", "▓", "│", "┤", "╡", "╢", "╖", "╕", "╣", "║", "╗", "╝", "╜", "╛", "┐",
    "└", "┴", "┬", "├", "─", "┼", "╞", "╟", "╚", "╔", "╩", "╦", "╠", "═", "╬", "╧",
    "╨", "╤", "╥", "╙", "╘", "╒", "╓", "╫", "╪", "┘", "┌", "█", "▄", "▌", "▐", "▀",
    "α",  "ß",  "Γ",  "π",  "Σ",  "σ",  "µ",  "τ",  "Φ",  "Θ",  "Ω",  "δ",  "∞", "φ",  "ε",  "∩",
    "≡", "±",  "≥", "≤", "⌠", "⌡", "÷",  "≈", "°",  "∙", "·",  "√", "ⁿ", "²",  "■", " ",
};
