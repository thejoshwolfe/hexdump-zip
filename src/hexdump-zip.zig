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

    var zipfile_dumper: ZipfileDumper = undefined;
    try zipfile_dumper.init(input_file, output_file, gpa);
    defer zipfile_dumper.deinit();
    try zipfile_dumper.doIt();

    return std.process.cleanExit();
}

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

const Encoding = enum {
    none,
    cp437,
    utf8,
};

const error_character = "\xef\xbf\xbd";

const zip64_eocdr_size = 56;
const zip64_eocdl_size = 20;
const eocdr_size = 22;
const eocdr_search_size: u64 = zip64_eocdl_size + 0xffff + eocdr_size;

/// local file header signature
const lfh_signature = 0x04034b50;

/// optional data descriptor optional signature
const oddo_signature = 0x08074b50;

/// central file header signature
const cfh_signature = 0x02014b50;

/// zip64 end of central dir signature
const zip64_eocdr_signature = 0x06064b50;

/// zip64 end of central dir locator signature
const zip64_eocdl_signature = 0x07064b50;

/// end of central dir signature
const eocdr_signature = 0x06054b50;

const ZipfileDumper = struct {
    input_file: std.fs.File,
    file_size: u64,
    offset_padding: usize,
    output_file: std.fs.File,
    output: @TypeOf(std.io.bufferedWriter(@as(std.fs.File.Writer, undefined))),
    segments: SegmentList,
    indentation: u2,

    const Self = @This();

    pub fn init(self: *Self, input_file: std.fs.File, output_file: std.fs.File, allocator: std.mem.Allocator) !void {
        self.input_file = input_file;
        self.file_size = try self.input_file.getEndPos();
        // this limit eliminates most silly overflow checks on the file offset.
        if (self.file_size > 0x7fffffffffffffff) return error.FileTooBig;

        {
            var tmp: [16]u8 = undefined;
            self.offset_padding = std.fmt.formatIntBuf(tmp[0..], self.file_size, 16, .lower, .{});
        }

        self.output_file = output_file;
        self.output = std.io.bufferedWriter(self.output_file.writer());

        self.segments = SegmentList.init(allocator);
        self.indentation = 0;
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
        if (self.file_size < eocdr_size) return error.NotAZipFile;
        // This buffer can contain:
        //  * the zip64 end of central dir locator,
        //  * the end of central directory record,
        //  * and a 0xffff size zip file comment.
        var eocdr_search_buffer: [eocdr_search_size]u8 = undefined;
        const eocdr_search_slice = eocdr_search_buffer[0..@min(self.file_size, eocdr_search_size)];
        const eocdr_search_slice_offset = self.file_size - eocdr_search_slice.len;
        try self.readNoEof(eocdr_search_slice_offset, eocdr_search_slice);
        // seek backward over the comment looking for the signature
        var eocdr_offset: u64 = undefined;
        var comment_length: u16 = 0;
        while (true) : (comment_length += 1) {
            eocdr_offset = self.file_size - (eocdr_size + comment_length);
            if (readInt32(eocdr_search_slice, eocdr_offset - eocdr_search_slice_offset) == eocdr_signature) {
                // found it
                break;
            }
            if (eocdr_offset == 0 or comment_length == 0xffff) return error.NotAZipFile;
        }
        const eocdr = eocdr_search_slice[eocdr_offset - eocdr_search_slice_offset .. eocdr_offset - eocdr_search_slice_offset + eocdr_size];

        var disk_number: u32 = readInt16(eocdr, 4);
        var entry_count: u32 = readInt16(eocdr, 10);
        var central_directory_size: u64 = readInt32(eocdr, 12);
        var central_directory_offset: u64 = readInt32(eocdr, 16);

        // ZIP64
        const is_zip64 = eocdr_offset >= zip64_eocdl_size and readInt32(eocdr_search_slice, eocdr_offset - zip64_eocdl_size - eocdr_search_slice_offset) == zip64_eocdl_signature;
        if (is_zip64) {
            const zip64_eocdl_offset = eocdr_offset - zip64_eocdl_size;
            const zip64_eocdl = eocdr_search_slice[zip64_eocdl_offset - eocdr_search_slice_offset .. zip64_eocdl_offset + zip64_eocdl_size - eocdr_search_slice_offset];
            const total_number_of_disks = readInt32(zip64_eocdl, 16);
            if (total_number_of_disks != 1) return error.MultiDiskZipfileNotSupported;
            const zip64_eocdr_offset = readInt64(zip64_eocdl, 8);

            var zip64_eocdr_buffer: [zip64_eocdr_size]u8 = undefined;
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
                try self.write("\n");
            }

            if (segment.offset > cursor) {
                try self.writeSectionHeader(cursor, "Unused space", .{});
                try self.dumpBlobContents(cursor, segment.offset - cursor, .none);
                try self.write("\n");
                cursor = segment.offset;
            } else if (segment.offset < cursor) {
                cursor = segment.offset;
                @panic("TODO: overlapping regions");
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
        if (readInt32(&lfh_buffer, 0) != lfh_signature) {
            try self.writeSectionHeader(offset, "WARNING: invalid local file header signature", .{});
            try self.write("\n");
            // if this isn't a local file, idk what it is.
            // call it unknown
            return 0;
        }

        try self.writeSectionHeader(offset, "Local File Header (#{})", .{info.entry_index});
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
        cursor += lfh_cursor;

        const file_name_length = readInt16(&lfh_buffer, 26);
        const general_purpose_bit_flag = readInt16(&lfh_buffer, 6);
        const is_utf8 = general_purpose_bit_flag & 0x800 != 0;
        const extra_fields_length = readInt16(&lfh_buffer, 28);

        if (file_name_length > 0) {
            self.indent();
            defer self.outdent();
            try self.write("\n");
            try self.writeSectionHeader(cursor, "File Name", .{});
            try self.dumpBlobContents(cursor, file_name_length, if (is_utf8) .utf8 else .cp437);
            cursor += file_name_length;
        }
        if (extra_fields_length > 0) {
            self.indent();
            defer self.outdent();
            try self.write("\n");
            try self.writeSectionHeader(cursor, "Extra Fields", .{});
            try self.dumpBlobContents(cursor, extra_fields_length, .none);
            cursor += extra_fields_length;
        }

        if (info.compressed_size > 0) {
            try self.write("\n");
            try self.writeSectionHeader(cursor, "File Contents", .{});
            try self.dumpBlobContents(cursor, info.compressed_size, .none);
            cursor += info.compressed_size;
        }

        // check for the optional data descriptor
        var data_descriptor_buffer: [24]u8 = undefined;
        const data_descriptor_len: usize = if (info.is_zip64) 24 else 16;
        if (self.readNoEof(cursor, data_descriptor_buffer[0..data_descriptor_len])) {
            if (readInt32(&data_descriptor_buffer, 0) == oddo_signature) {
                // this is a data descriptor
                try self.write("\n");
                try self.writeSectionHeader(cursor, "Optional Data Descriptor", .{});
                var data_descriptor_cursor: usize = 0;
                if (info.is_zip64) {
                    try self.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 4, "optional data descriptor signature");
                    try self.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 4, "crc-32");
                    try self.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 8, "compressed size");
                    try self.readStructField(&data_descriptor_buffer, 8, &data_descriptor_cursor, 8, "uncompressed size");
                } else {
                    try self.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "optional data descriptor signature");
                    try self.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "crc-32");
                    try self.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "compressed size");
                    try self.readStructField(&data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "uncompressed size");
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
                if (i > 0) try self.write("\n");

                var cdr_buffer: [46]u8 = undefined;
                try self.readNoEof(cursor, cdr_buffer[0..]);
                if (readInt32(&cdr_buffer, 0) != cfh_signature) {
                    try self.writeSectionHeader(cursor, "WARNING: invalid central file header signature", .{});
                    try self.write("\n");
                    return 0;
                }

                try self.writeSectionHeader(cursor, "Central Directory Entry (#{})", .{i});
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
                cursor += cdr_cursor;

                const general_purpose_bit_flag = readInt16(&cdr_buffer, 8);
                const is_utf8 = general_purpose_bit_flag & 0x800 != 0;
                const file_name_length = readInt16(&cdr_buffer, 28);
                const extra_fields_length = readInt16(&cdr_buffer, 30);
                const file_comment_length = readInt16(&cdr_buffer, 32);

                if (file_name_length > 0) {
                    self.indent();
                    defer self.outdent();
                    try self.writeSectionHeader(cursor, "File name", .{});
                    try self.dumpBlobContents(cursor, file_name_length, if (is_utf8) .utf8 else .cp437);
                    cursor += file_name_length;
                }
                if (extra_fields_length > 0) {
                    self.indent();
                    defer self.outdent();
                    try self.writeSectionHeader(cursor, "Extra Fields", .{});
                    try self.dumpBlobContents(cursor, extra_fields_length, .none);
                    cursor += extra_fields_length;
                }
                if (file_comment_length > 0) {
                    self.indent();
                    defer self.outdent();
                    try self.writeSectionHeader(cursor, "File Comment", .{});
                    try self.dumpBlobContents(cursor, file_comment_length, .cp437);
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
        try self.writeSectionHeader(offset, "zip64 end of central directory record", .{});
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
            try self.writeSectionHeader(offset + cursor, "zip64 extensible data sector", .{});
            try self.dumpBlobContents(offset + cursor, zip64_extensible_data_sector_size, .none);
            cursor += zip64_extensible_data_sector_size;
        }

        return cursor;
    }

    fn dumpZip64EndOfCentralDirectoryLocator(self: *Self, offset: u64) !u64 {
        var buffer: [20]u8 = undefined;
        try self.readNoEof(offset, buffer[0..]);
        var cursor: usize = 0;

        const max_size = 8;
        try self.writeSectionHeader(offset, "zip64 end of central directory locator", .{});
        try self.readStructField(&buffer, max_size, &cursor, 4, "zip64 end of central dir locator signature");
        try self.readStructField(&buffer, max_size, &cursor, 4, "number of the disk with the start of the zip64 end of central directory");
        try self.readStructField(&buffer, max_size, &cursor, 8, "relative offset of the zip64 end of central directory record");
        try self.readStructField(&buffer, max_size, &cursor, 4, "total number of disks");
        assert(cursor == buffer.len);

        return cursor;
    }

    fn dumpEndOfCentralDirectory(self: *Self, offset: u64) !u64 {
        var buffer: [22]u8 = undefined;
        try self.readNoEof(offset, buffer[0..]);
        var cursor: usize = 0;

        const max_size = 4;
        try self.writeSectionHeader(offset, "End of central directory record", .{});
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
            try self.writeSectionHeader(offset + cursor, ".ZIP file comment", .{});
            try self.dumpBlobContents(offset + cursor, comment_length, .cp437);
            cursor += comment_length;
        }

        return cursor;
    }

    fn dumpBlobContents(self: *Self, offset: u64, length: u64, encoding: Encoding) !void {
        var buffer: [0x1000]u8 = undefined;
        const row_length = 16;

        var utf8_byte_sequence_buffer: [4]u8 = undefined;
        var utf8_bytes_saved: usize = 0;
        var utf8_bytes_remaining: usize = 0;

        var cursor: u64 = 0;
        while (cursor < length) {
            const buffer_offset = offset + cursor;
            try self.readNoEof(buffer_offset, buffer[0..@min(buffer.len, length - cursor)]);
            try self.printIndentation();
            const row_start = offset + cursor - buffer_offset;
            {
                var i: usize = 0;
                while (i < row_length - 1 and cursor < length - 1) : (i += 1) {
                    try self.printf("{x:0>2} ", .{buffer[offset + cursor - buffer_offset]});
                    cursor += 1;
                }
            }
            try self.printf("{x:0>2}", .{buffer[offset + cursor - buffer_offset]});
            cursor += 1;

            var row = buffer[row_start .. offset + cursor - buffer_offset];
            switch (encoding) {
                .none => {},
                .cp437 => {
                    if (length > row_length) {
                        var i: usize = row.len;
                        while (i < row_length) : (i += 1) {
                            try self.write("   ");
                        }
                    }
                    try self.write(" ; cp437\"");
                    for (row) |c| {
                        try self.write(cp437[c]);
                    }
                    try self.write("\"");
                },
                .utf8 => {
                    if (length > row_length) {
                        var i: usize = row.len;
                        while (i < row_length) : (i += 1) {
                            try self.write("   ");
                        }
                    }
                    try self.write(" ; utf8\"");

                    // input is utf8; output is utf8.
                    var i: usize = 0;
                    if (utf8_bytes_remaining > 0) {
                        while (i < utf8_bytes_remaining) : (i += 1) {
                            utf8_byte_sequence_buffer[utf8_bytes_saved + i] = row[i];
                        }
                        try self.dumpUtf8Codepoint(utf8_byte_sequence_buffer[0 .. utf8_bytes_saved + utf8_bytes_remaining]);
                        utf8_bytes_saved = 0;
                        utf8_bytes_remaining = 0;
                    }

                    while (i < row.len) : (i += 1) {
                        const utf8_length = std.unicode.utf8ByteSequenceLength(row[i]) catch {
                            // invalid utf8 start byte. replace with the error character.
                            try self.write(error_character);
                            continue;
                        };

                        if (i + utf8_length > row.len) {
                            // this sequence wraps onto the next line.
                            if (i + utf8_length - row.len > length - cursor) {
                                // there is no next line. unexpected eof.
                                try self.write(error_character);
                                break;
                            }
                            var j: usize = 0;
                            while (j < row.len - i) : (j += 1) {
                                utf8_byte_sequence_buffer[j] = row[i + j];
                            }
                            utf8_bytes_saved = j;
                            utf8_bytes_remaining = utf8_length - j;
                            break;
                        }

                        // we have a complete codepoint on this row
                        try self.dumpUtf8Codepoint(row[i .. i + utf8_length]);
                        i += utf8_length - 1;
                    }
                    try self.write("\"");
                },
            }
            try self.write("\n");
        }
    }

    fn dumpUtf8Codepoint(self: *Self, byte_sequence: []const u8) !void {
        const codepoint = std.unicode.utf8Decode(byte_sequence) catch {
            // invalid utf8 seequcne becomes a single error character.
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
        var offset_str_buf: [16]u8 = undefined;
        const offset_str = offset_str_buf[0..std.fmt.formatIntBuf(offset_str_buf[0..], offset, 16, .lower, .{ .width = self.offset_padding, .fill = '0' })];

        try self.printIndentation();
        try self.printf(":0x{s} ; ", .{offset_str});
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

    fn readNoEof(self: *Self, offset: u64, buffer: []u8) !void {
        try self.input_file.seekTo(offset);
        try self.input_file.reader().readNoEof(buffer);
    }
    fn readInt32At(self: *Self, offset: u64) !u32 {
        var buffer: [4]u8 = undefined;
        try self.readNoEof(offset, buffer[0..]);
        return readInt32(&buffer, 0);
    }
    fn isSignatureAt(self: *Self, offset: u64, signature: u32) bool {
        return signature == (self.readInt32At(offset) catch return false);
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
