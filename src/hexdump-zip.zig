const std = @import("std");
const assert = std.debug.assert;

const Hexdumper = @import("./Hexdumper.zig");
const z = @import("./zipfile.zig");

const SegmentList = std.ArrayList(Segment);
const SegmentKind = union(enum) {
    local_file: LocalFileInfo,
    central_directory_entries: CentralDirectoryEntriesInfo,
    zip64_eocdr,
    zip64_eocdl,
    eocdr,
};
const Segment = struct {
    offset: u64,
    kind: SegmentKind,
};
const LocalFileInfo = struct {
    entry_index: u32,
    compressed_size: u64,
    is_zip64: bool,
};
const CentralDirectoryEntriesInfo = struct {
    entry_count: u32,
    central_directory_size: u64,
};
fn segmentLessThan(_: void, a: Segment, b: Segment) bool {
    return a.offset < b.offset;
}

pub const ZipfileDumper = struct {
    input_file: std.fs.File,
    file_size: u64,
    output_file: std.fs.File,
    output: @TypeOf(std.io.bufferedWriter(@as(std.fs.File.Writer, undefined))),
    // have to store this in the struct, because .any() take a pointer to the writer.
    output_writer: @TypeOf(std.io.bufferedWriter(@as(std.fs.File.Writer, undefined))).Writer,
    dumper: Hexdumper,
    segments: SegmentList,

    const Self = @This();

    pub fn init(self: *Self, input_file: std.fs.File, output_file: std.fs.File, allocator: std.mem.Allocator) !void {
        self.input_file = input_file;
        self.file_size = try self.input_file.getEndPos();
        // this limit eliminates most silly overflow checks on the file offset.
        if (self.file_size > 0x7fffffffffffffff) return error.FileTooBig;

        self.output_file = output_file;
        self.output = std.io.bufferedWriter(self.output_file.writer());
        self.output_writer = self.output.writer();
        self.dumper = .{ .output = self.output_writer.any() };

        self.segments = SegmentList.init(allocator);
    }

    pub fn deinit(self: *Self) void {
        self.segments.deinit();
        self.* = undefined;
    }

    pub fn doIt(self: *Self) !void {
        try self.findSegments();
        try self.dumpSegments();
        try self.output.flush();
    }

    fn findSegments(self: *Self) !void {
        // find the eocdr
        if (self.file_size < z.eocdr_size) return error.NotAZipFile;
        // This buffer can contain:
        //  * the zip64 end of central dir locator,
        //  * the end of central directory record,
        //  * and a 0xffff size zip file comment.
        var eocdr_search_buffer: [z.eocdr_search_size]u8 = undefined;
        const eocdr_search_slice = eocdr_search_buffer[0..@min(self.file_size, z.eocdr_search_size)];
        const eocdr_search_slice_offset = self.file_size - eocdr_search_slice.len;
        try self.readNoEof(eocdr_search_slice_offset, eocdr_search_slice);
        // seek backward over the comment looking for the signature
        var eocdr_offset: u64 = undefined;
        var comment_length: u16 = 0;
        while (true) : (comment_length += 1) {
            eocdr_offset = self.file_size - (z.eocdr_size + comment_length);
            if (readInt32(eocdr_search_slice, eocdr_offset - eocdr_search_slice_offset) == z.eocdr_signature) {
                // found it
                break;
            }
            if (eocdr_offset == 0 or comment_length == 0xffff) return error.NotAZipFile;
        }
        const eocdr = eocdr_search_slice[eocdr_offset - eocdr_search_slice_offset .. eocdr_offset - eocdr_search_slice_offset + z.eocdr_size];

        var disk_number: u32 = readInt16(eocdr, 4);
        var entry_count: u32 = readInt16(eocdr, 10);
        var central_directory_size: u64 = readInt32(eocdr, 12);
        var central_directory_offset: u64 = readInt32(eocdr, 16);

        // ZIP64
        const is_zip64 = eocdr_offset >= z.zip64_eocdl_size and readInt32(eocdr_search_slice, eocdr_offset - z.zip64_eocdl_size - eocdr_search_slice_offset) == z.zip64_eocdl_signature;
        if (is_zip64) {
            const zip64_eocdl_offset = eocdr_offset - z.zip64_eocdl_size;
            const zip64_eocdl = eocdr_search_slice[zip64_eocdl_offset - eocdr_search_slice_offset .. zip64_eocdl_offset + z.zip64_eocdl_size - eocdr_search_slice_offset];
            const total_number_of_disks = readInt32(zip64_eocdl, 16);
            if (total_number_of_disks != 1) return error.MultiDiskZipfileNotSupported;
            const zip64_eocdr_offset = readInt64(zip64_eocdl, 8);

            var zip64_eocdr_buffer: [z.zip64_eocdr_size]u8 = undefined;
            try self.readNoEof(zip64_eocdr_offset, zip64_eocdr_buffer[0..]);
            const zip64_eocdr = zip64_eocdr_buffer[0..];

            disk_number = readInt32(zip64_eocdr, 16);
            entry_count = readInt32(zip64_eocdr, 32);
            central_directory_size = readInt64(zip64_eocdr, 40);
            central_directory_offset = readInt64(zip64_eocdr, 48);

            try self.segments.append(Segment{
                .offset = zip64_eocdr_offset,
                .kind = .zip64_eocdr,
            });
            try self.segments.append(Segment{
                .offset = zip64_eocdl_offset,
                .kind = .zip64_eocdl,
            });
        }

        if (disk_number != 0) return error.MultiDiskZipfileNotSupported;
        const central_directory_end = central_directory_offset +| central_directory_size;
        if (central_directory_end > self.file_size) return error.CentralDirectorySizeExceedsFileBounds;

        var central_directory_cursor: u64 = central_directory_offset;
        {
            var entry_index: u32 = 0;
            while (entry_index < entry_count and central_directory_cursor + 46 <= central_directory_end) : (entry_index += 1) {
                // TODO: generalize not exceeding the central_directory_size
                var cfh_buffer: [46]u8 = undefined;
                try self.readNoEof(central_directory_cursor, cfh_buffer[0..]);

                var compressed_size: u64 = readInt32(&cfh_buffer, 20);
                var uncompressed_size: u64 = readInt32(&cfh_buffer, 24);
                const file_name_length = readInt16(&cfh_buffer, 28);
                const extra_fields_length = readInt16(&cfh_buffer, 30);
                const file_comment_length = readInt16(&cfh_buffer, 32);
                var local_header_offset: u64 = readInt32(&cfh_buffer, 42);

                central_directory_cursor += 46;
                central_directory_cursor += file_name_length;

                // ZIP64
                var found_zip64_extended_information = false;
                var extra_fields_buffer: [0xffff]u8 = undefined;
                const extra_fields = extra_fields_buffer[0..extra_fields_length];
                try self.readNoEof(central_directory_cursor, extra_fields);
                var extra_fields_cursor: u32 = 0;
                while (extra_fields_cursor + 3 < extra_fields_length) {
                    const tag = readInt16(extra_fields, extra_fields_cursor);
                    extra_fields_cursor += 2;
                    const size = readInt16(extra_fields, extra_fields_cursor);
                    extra_fields_cursor += 2;
                    if (extra_fields_cursor + size > extra_fields_length) return error.ExtraFieldSizeExceedsExtraFieldsBuffer;
                    const extra_field = extra_fields[extra_fields_cursor .. extra_fields_cursor + size];
                    extra_fields_cursor += size;

                    switch (tag) {
                        0x0001 => {
                            // ZIP64
                            if (found_zip64_extended_information) return error.DuplicateZip64ExtendedInformation;
                            found_zip64_extended_information = true;
                            var cursor: u16 = 0;
                            if (uncompressed_size == 0xffffffff) {
                                if (cursor + 8 > extra_field.len) return error.Zip64ExtendedInformationTruncated;
                                uncompressed_size = readInt64(extra_field, cursor);
                                cursor += 8;
                            }
                            if (compressed_size == 0xffffffff) {
                                if (cursor + 8 > extra_field.len) return error.Zip64ExtendedInformationTruncated;
                                compressed_size = readInt64(extra_field, cursor);
                                cursor += 8;
                            }
                            if (local_header_offset == 0xffffffff) {
                                if (cursor + 8 > extra_field.len) return error.Zip64ExtendedInformationTruncated;
                                local_header_offset = readInt64(extra_field, cursor);
                                cursor += 8;
                            }
                            // ignore the disk number
                        },
                        else => {},
                    }
                }

                central_directory_cursor += extra_fields_length;
                central_directory_cursor += file_comment_length;

                try self.segments.append(Segment{
                    .offset = local_header_offset,
                    .kind = .{ .local_file = .{
                        .entry_index = entry_index,
                        .is_zip64 = found_zip64_extended_information,
                        .compressed_size = compressed_size,
                    } },
                });
            }
        }

        if (entry_count > 0) {
            try self.segments.append(Segment{
                .offset = central_directory_offset,
                .kind = .{ .central_directory_entries = .{
                    .entry_count = entry_count,
                    .central_directory_size = central_directory_size,
                } },
            });
        }

        try self.segments.append(Segment{
            .offset = eocdr_offset,
            .kind = .eocdr,
        });
    }

    fn dumpSegments(self: *Self) !void {
        std.sort.insertion(Segment, self.segments.items, {}, segmentLessThan);

        var cursor: u64 = 0;
        for (self.segments.items, 0..) |segment, i| {
            if (i != 0) {
                try self.dumper.write("\n");
            }

            if (segment.offset > cursor) {
                try self.dumper.writeSectionHeader(cursor, "(unused space)", .{});
                try self.dumpBlob(cursor, segment.offset - cursor, .{
                    .row_length = 512,
                    .spaces = false,
                });
                try self.dumper.write("\n");
                cursor = segment.offset;
            } else if (segment.offset < cursor) {
                try self.dumper.printf("#seek -0x{x}\n\n", .{cursor - segment.offset});
                cursor = segment.offset;
            }

            const length = switch (segment.kind) {
                .local_file => |info| try self.dumpLocalFile(segment.offset, info),
                .central_directory_entries => |info| try self.dumpCentralDirectoryEntries(segment.offset, info),
                .zip64_eocdr => try self.dumpZip64EndOfCentralDirectoryRecord(segment.offset),
                .zip64_eocdl => try self.dumpZip64EndOfCentralDirectoryLocator(segment.offset),
                .eocdr => try self.dumpEndOfCentralDirectory(segment.offset),
            };
            cursor += length;
        }
    }

    fn dumpLocalFile(self: *Self, offset: u64, info: LocalFileInfo) !u64 {
        var cursor = offset;
        var lfh_buffer: [30]u8 = undefined;
        try self.readNoEof(cursor, lfh_buffer[0..]);
        if (readInt32(&lfh_buffer, 0) != z.lfh_signature) {
            try self.dumper.writeSectionHeader(offset, "WARNING: invalid local file header signature", .{});
            try self.dumper.write("\n");
            // if this isn't a local file, idk what it is.
            // call it unknown
            return 0;
        }

        try self.dumper.writeSectionHeader(offset, "Local File Header (#{})", .{info.entry_index});
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
        cursor += lfh_cursor;

        const file_name_length = readInt16(&lfh_buffer, 26);
        const general_purpose_bit_flag = readInt16(&lfh_buffer, 6);
        const is_utf8 = general_purpose_bit_flag & 0x800 != 0;
        const extra_fields_length = readInt16(&lfh_buffer, 28);

        var compressed_size: u64 = readInt32(&lfh_buffer, 18);
        var uncompressed_size: u64 = readInt32(&lfh_buffer, 22);

        if (file_name_length > 0) {
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.writeSectionHeader(cursor, "File Name", .{});
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumpBlob(cursor, file_name_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
            cursor += file_name_length;
        }
        if (extra_fields_length > 0) {
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumper.writeSectionHeader(cursor, "Extra Fields", .{});
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.readExtraFields(cursor, extra_fields_length, null, &compressed_size, &uncompressed_size, null, null);
            cursor += extra_fields_length;
        }

        if (info.compressed_size > 0) {
            try self.dumper.writeSectionHeader(cursor, "File Contents", .{});
            try self.dumpBlob(cursor, info.compressed_size, .{
                .row_length = 512,
                .spaces = false,
            });
            cursor += info.compressed_size;
        }

        // check for the optional data descriptor
        var data_descriptor_buffer: [24]u8 = undefined;
        const data_descriptor_len: usize = if (info.is_zip64) 24 else 16;
        if (self.readNoEof(cursor, data_descriptor_buffer[0..data_descriptor_len])) {
            if (readInt32(&data_descriptor_buffer, 0) == z.oddo_signature) {
                // this is a data descriptor
                try self.dumper.write("\n");
                try self.dumper.writeSectionHeader(cursor, "Optional Data Descriptor", .{});
                var data_descriptor_cursor: usize = 0;
                if (info.is_zip64) {
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
                cursor += data_descriptor_cursor;
            }
        } else |_| {
            // ok, so there's no optional data descriptor here
        }

        return cursor - offset;
    }

    fn dumpCentralDirectoryEntries(self: *Self, offset: u64, info: CentralDirectoryEntriesInfo) !u64 {
        const central_directory_end = offset + info.central_directory_size;
        var cursor = offset;
        {
            var i: u32 = 0;
            while (i < info.entry_count and cursor + 46 <= central_directory_end) : (i += 1) {
                // TODO: generalize not exceeding the central_directory_size
                if (i > 0) try self.dumper.write("\n");

                var cdr_buffer: [46]u8 = undefined;
                try self.readNoEof(cursor, cdr_buffer[0..]);
                if (readInt32(&cdr_buffer, 0) != z.cfh_signature) {
                    try self.dumper.writeSectionHeader(cursor, "WARNING: invalid central file header signature", .{});
                    try self.dumper.write("\n");
                    return 0;
                }

                try self.dumper.writeSectionHeader(cursor, "Central Directory Entry (#{})", .{i});
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
                cursor += cdr_cursor;

                const general_purpose_bit_flag = readInt16(&cdr_buffer, 8);
                const is_utf8 = general_purpose_bit_flag & 0x800 != 0;
                const file_name_length = readInt16(&cdr_buffer, 28);
                const extra_fields_length = readInt16(&cdr_buffer, 30);
                const file_comment_length = readInt16(&cdr_buffer, 32);

                var is_zip64 = false;
                var compressed_size: u64 = readInt32(&cdr_buffer, 20);
                var uncompressed_size: u64 = readInt32(&cdr_buffer, 20);
                var local_file_header_offset: u64 = readInt32(&cdr_buffer, 42);
                var disk_number: u32 = readInt16(&cdr_buffer, 34);

                if (file_name_length > 0) {
                    self.dumper.indent();
                    defer self.dumper.outdent();
                    try self.dumper.writeSectionHeader(cursor, "File name", .{});
                    self.dumper.indent();
                    defer self.dumper.outdent();
                    try self.dumpBlob(cursor, file_name_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
                    cursor += file_name_length;
                }
                if (extra_fields_length > 0) {
                    self.dumper.indent();
                    defer self.dumper.outdent();
                    try self.dumper.writeSectionHeader(cursor, "Extra Fields", .{});
                    self.dumper.indent();
                    defer self.dumper.outdent();
                    try self.readExtraFields(cursor, extra_fields_length, &is_zip64, &compressed_size, &uncompressed_size, &local_file_header_offset, &disk_number);
                    cursor += extra_fields_length;
                }
                if (file_comment_length > 0) {
                    self.dumper.indent();
                    defer self.dumper.outdent();
                    try self.dumper.writeSectionHeader(cursor, "File Comment", .{});
                    self.dumper.indent();
                    defer self.dumper.outdent();
                    try self.dumpBlob(cursor, file_comment_length, .{ .encoding = if (is_utf8) .utf8 else .cp437 });
                    cursor += file_comment_length;
                }
            }
        }

        return cursor - offset;
    }

    fn dumpZip64EndOfCentralDirectoryRecord(self: *Self, offset: u64) !u64 {
        var buffer: [56]u8 = undefined;
        try self.readNoEof(offset, buffer[0..]);
        var cursor: usize = 0;

        const max_size = 8;
        try self.dumper.writeSectionHeader(offset, "zip64 end of central directory record", .{});
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
            try self.dumper.writeSectionHeader(offset + cursor, "zip64 extensible data sector", .{});
            try self.dumpBlob(offset + cursor, zip64_extensible_data_sector_size, .{});
            cursor += zip64_extensible_data_sector_size;
        }

        return cursor;
    }

    fn dumpZip64EndOfCentralDirectoryLocator(self: *Self, offset: u64) !u64 {
        var buffer: [20]u8 = undefined;
        try self.readNoEof(offset, buffer[0..]);
        var cursor: usize = 0;

        const max_size = 8;
        try self.dumper.writeSectionHeader(offset, "zip64 end of central directory locator", .{});
        try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "zip64 end of central dir locator signature");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "number of the disk with the start of the zip64 end of central directory");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 8, "relative offset of the zip64 end of central directory record");
        try self.dumper.readStructField(&buffer, max_size, &cursor, 4, "total number of disks");
        assert(cursor == buffer.len);

        return cursor;
    }

    fn dumpEndOfCentralDirectory(self: *Self, offset: u64) !u64 {
        var buffer: [22]u8 = undefined;
        try self.readNoEof(offset, buffer[0..]);
        var cursor: usize = 0;

        const max_size = 4;
        try self.dumper.writeSectionHeader(offset, "End of central directory record", .{});
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
            try self.dumper.writeSectionHeader(offset + cursor, ".ZIP file comment", .{});
            self.dumper.indent();
            defer self.dumper.outdent();
            try self.dumpBlob(offset + cursor, comment_length, .{ .encoding = .cp437 });
            cursor += comment_length;
        }

        return cursor;
    }

    fn dumpBlob(self: *Self, offset: u64, length: u64, config: Hexdumper.BlobConfig) !void {
        var partial_utf8_state = Hexdumper.PartialUtf8State{};
        var cursor: u64 = 0;
        while (cursor < length) {
            var buffer: [0x1000]u8 = undefined;
            const buffer_offset = offset + cursor;
            const buffer_len = @min(buffer.len, length - cursor);
            try self.readNoEof(buffer_offset, buffer[0..buffer_len]);
            const is_end = cursor + buffer_len == length;

            try self.dumper.writeBlobPart(buffer[0..buffer_len], config, cursor == 0, is_end, &partial_utf8_state);

            cursor += buffer_len;
        }
    }

    fn readExtraFields(
        self: *Self,
        offset: u64,
        extra_fields_length: u16,
        out_is_zip64: ?*bool,
        compressed_size: *u64,
        uncompressed_size: *u64,
        local_file_header_offset: ?*u64,
        disk_number: ?*u32,
    ) !void {
        var buf: [0xffff]u8 = undefined;
        const buffer = buf[0..extra_fields_length];
        try self.readNoEof(offset, buffer);

        return z.dumpExtraFields(&self.dumper, offset, buffer, out_is_zip64, compressed_size, uncompressed_size, local_file_header_offset, disk_number);
    }

    fn readNoEof(self: *Self, offset: u64, buffer: []u8) !void {
        try self.input_file.seekTo(offset);
        try self.input_file.reader().readNoEof(buffer);
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
