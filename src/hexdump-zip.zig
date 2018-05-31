const std = @import("std");

const general_allocator = std.heap.c_allocator;

fn usage() !void {
    std.debug.warn("usage: INPUT.zip OUTPUT.hex\n");
    return error.Usage;
}

pub fn main() !void {
    var args = std.os.args();
    _ = args.nextPosix() ?? return usage();
    const input_path_str = args.nextPosix() ?? return usage();
    const output_path_str = args.nextPosix() ?? return usage();
    if (args.nextPosix() != null) return usage();

    var input_file = try std.os.File.openRead(general_allocator, input_path_str);
    defer input_file.close();

    var output_file = try std.os.File.openWrite(general_allocator, output_path_str);
    defer output_file.close();

    var zipfile_dumper: ZipfileDumper = undefined;
    try zipfile_dumper.init(&input_file, &output_file, general_allocator);
    try zipfile_dumper.doIt();
}

const SegmentList = std.ArrayList(Segment);
const SegmentKind = union(enum) {
    LocalFile: LocalFileInfo,
    CentralDirectoryEntries: CentralDirectoryEntriesInfo,
    EndOfCentralDirectory: EndOfCentralDirectoryInfo,
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
const EndOfCentralDirectoryInfo = struct {
    eocdr_offset: u64,
};
const CentralDirectoryEntriesInfo = struct {
    entry_count: u32,
};
fn segmentLessThan(a: &const Segment, b: &const Segment) bool {
    return a.offset < b.offset;
}

const Encoding = enum {
    None,
    Cp437,
    Utf8,
};

const error_character = "\xef\xbf\xbd";

const eocdr_size = 22;
const eocdr_search_size: u64 = 0xffff + eocdr_size;

/// end of central dir signature
const eocdr_signature = 0x06054b50;
/// central file header signature
const cfh_signature = 0x02014b50;
/// local file header signature
const lfh_signature = 0x04034b50;
/// optional data descriptor optional signature
const oddo_signature = 0x08074b50;

const ZipfileDumper = struct {
    const Self = this;

    input_file: &std.os.File,
    input_file_stream: std.io.FileInStream,
    input: &std.io.InStream(std.io.FileInStream.Error),
    file_size: u64,
    offset_padding: usize,
    output_file: &std.os.File,
    output_file_stream: std.io.FileOutStream,
    buffered_output_stream: std.io.BufferedOutStream(std.io.FileOutStream.Error),
    output: &std.io.OutStream(std.io.FileOutStream.Error),
    allocator: &std.mem.Allocator,
    segments: SegmentList,
    indentation: u2,
    mac_archive_utility_overflow_recovery_cursor: ?u64,

    pub fn init(self: &Self, input_file: &std.os.File, output_file: &std.os.File, allocator: &std.mem.Allocator) !void {
        // FIXME: return a new object once we have https://github.com/zig-lang/zig/issues/287

        self.input_file = input_file;
        self.input_file_stream = std.io.FileInStream.init(self.input_file);
        self.input = &self.input_file_stream.stream;
        self.file_size = u64(try self.input_file.getEndPos()); // FIXME: shouldn't need cast: https://github.com/zig-lang/zig/issues/637
        // this limit eliminates most silly overflow checks on the file offset.
        if (self.file_size > 0x7fffffffffffffff) return error.FileTooBig;

        {
            var tmp: [16]u8 = undefined;
            self.offset_padding = std.fmt.formatIntBuf(tmp[0..], self.file_size, 16, false, 0);
        }

        self.output_file = output_file;
        self.output_file_stream = std.io.FileOutStream.init(self.output_file);
        self.buffered_output_stream = std.io.BufferedOutStream(std.io.FileOutStream.Error).init(&self.output_file_stream.stream);
        self.output = &self.buffered_output_stream.stream;

        self.allocator = allocator;
        self.segments = SegmentList.init(allocator);
        self.indentation = 0;
        self.mac_archive_utility_overflow_recovery_cursor = 0;
    }

    pub fn doIt(self: &Self) !void {
        try self.findSegments();
        try self.dumpSegments();
        try self.buffered_output_stream.flush();
    }

    fn findSegments(self: &Self) !void {
        // find the eocdr
        if (self.file_size < eocdr_size) return error.NotAZipFile;
        var eocdr_search_buffer: [eocdr_search_size]u8 = undefined;
        const eocdr_search_slice = eocdr_search_buffer[0..usize(std.math.min(self.file_size, eocdr_search_size))];
        try self.readNoEof(self.file_size - eocdr_search_slice.len, eocdr_search_slice);
        // seek backward over the comment looking for the signature
        var comment_length: u16 = 0;
        var eocdr_buffer: []const u8 = undefined;
        while (true) : (comment_length += 1) {
            var cursor = eocdr_search_slice.len - comment_length - eocdr_size;
            if (readInt32(eocdr_search_slice, cursor) == eocdr_signature) {
                // found it
                eocdr_buffer = eocdr_search_slice[cursor..cursor + eocdr_size];
                break;
            }
            if (cursor == 0) return error.NotAZipFile;
        }
        const eocdr_offset = self.file_size - comment_length - eocdr_size;

        const disk_number = readInt16(eocdr_buffer, 4);
        if (disk_number != 0) return error.MultiDiskZipfileNotSupported;

        var entry_count: u32 = readInt16(eocdr_buffer, 10);
        var size_of_central_directory: u64 = readInt32(eocdr_buffer, 12);
        var central_directory_offset: u64 = readInt32(eocdr_buffer, 16);

        // TODO: check for ZIP64 format

        // check for Mac Archive Utility corruption in the central directory location and size
        if (eocdr_offset > 0xffffffff) {
            var calculated_central_directory_offset = std.math.sub(u64, eocdr_offset, size_of_central_directory) catch return error.SizeOfCentralDirectoryOverflow;
            if (central_directory_offset != calculated_central_directory_offset and 
                central_directory_offset == calculated_central_directory_offset & 0xffffffff)
            {
                // Uh oh.
                // The alleged size and location of the central appear to have
                // been corrupted by the mac archive utility overflow bug.

                // Where does the central directory really start?
                // Assume it's smaller than 4GB, and search backwards.
                central_directory_offset = calculated_central_directory_offset;
                while (true) {
                    if (self.isSignatureAt(central_directory_offset, cfh_signature)) {
                        // found it.
                        var warning_count: u2 = 0;
                        if (central_directory_offset > 0xffffffff) {
                            self.detectedMauCorruption("offset of start of central directory with respect to the starting disk number");
                            warning_count += 1;
                        }
                        if (central_directory_offset < calculated_central_directory_offset) {
                            self.detectedMauCorruption("size of the central directory");
                            warning_count += 1;
                        }
                        std.debug.assert(warning_count > 0);
                        break;
                    }
                    central_directory_offset = std.math.sub(u64, central_directory_offset, 0x100000000) catch return error.CentralDirectoryNotFound;
                }
            }
        }


        var central_directory_cursor: u64 = central_directory_offset;
        {var entry_index: u32 = 0; while (entry_index < entry_count) : (entry_index += 1) {
            var cfh_buffer: [46]u8 = undefined;
            try self.readNoEof(central_directory_cursor, cfh_buffer[0..]);

            var compressed_size: u64 = readInt32(cfh_buffer, 20);
            const file_name_length = readInt16(cfh_buffer, 28);
            const extra_fields_length = readInt16(cfh_buffer, 30);
            const file_comment_length = readInt16(cfh_buffer, 32);
            var local_header_offset: u64 = readInt32(cfh_buffer, 42);

            // TODO: check for ZIP64 format
            var is_zip64 = false;

            central_directory_cursor += 46;
            central_directory_cursor += file_name_length;
            central_directory_cursor += extra_fields_length;
            central_directory_cursor += file_comment_length;

            // check mac stuff
            if (self.mac_archive_utility_overflow_recovery_cursor) |*mac_archive_utility_overflow_recovery_cursor| mac_stuff: {
                // There might be something fishy going on with overflow.
                // Check if the local header is really where it's supposed to be.
                if (local_header_offset != mac_archive_utility_overflow_recovery_cursor.* & 0xffffffff) {
                    // Non-contiguous entries. This is definitely not a mac zip.
                    self.mac_archive_utility_overflow_recovery_cursor = null;
                    break :mac_stuff;
                }
                if (local_header_offset != mac_archive_utility_overflow_recovery_cursor.*) {
                    // this really looks like corruption.
                    // peek and see if there's a signature where we suspect.
                    if (self.isSignatureAt(mac_archive_utility_overflow_recovery_cursor.*, lfh_signature)) {
                        // ok *maybe* this is a coincidence, but it really looks like corruption.
                        self.detectedMauCorruption("relative offset of local header");
                        local_header_offset = mac_archive_utility_overflow_recovery_cursor.*;
                    }
                }
                // ok. we've found the local file header.

                // now what's the compressed size really?

                // peek at the local file header's fields
                var lfh_buffer: [30]u8 = undefined;
                try self.readNoEof(local_header_offset, lfh_buffer[0..]);
                const local_file_name_length = readInt16(lfh_buffer, 26);
                const local_extra_fields_length = readInt16(lfh_buffer, 28);
                mac_archive_utility_overflow_recovery_cursor.* += 30;
                mac_archive_utility_overflow_recovery_cursor.* += local_file_name_length;
                mac_archive_utility_overflow_recovery_cursor.* += local_extra_fields_length;
                mac_archive_utility_overflow_recovery_cursor.* += compressed_size;
                // allegedly the cursor is now pointing to the end of the data

                var next_thing_start_offset = next_thing_start_offset: {
                    if (entry_index == entry_count - 1) {
                        // Supposedly this is the last entry.
                        if (central_directory_cursor < eocdr_offset) {
                            // There's apparently unused space in the central directory.
                            // I wonder if there's actually more entries here.
                            if (self.isSignatureAt(central_directory_cursor, cfh_signature)) {
                                // Yep. There's more entries.
                                self.detectedMauCorruption("total number of entries in the central directory");
                                entry_count += 0x10000;
                            }
                        }
                    }
                    if (entry_index == entry_count - 1) {
                        // This is the last entry.
                        break :next_thing_start_offset central_directory_offset;
                    }
                    // This is not the last entry.
                    // Read the relative offset of local header for the *next* entry.
                    // Note that this value itself might be affected by overflow corruption.
                    break :next_thing_start_offset self.readInt32At(central_directory_cursor + 42) catch {
                        // There're not enough entries in here.
                        // This will be an error elsewhere.
                        self.mac_archive_utility_overflow_recovery_cursor = null;
                        break :mac_stuff;
                    };
                };

                // Mac Archive Utility sometimes includes a 16-byte data descriptor,
                // and then the next thing starts immediately afterward.
                const distance_to_next_thing = (next_thing_start_offset & 0xffffffff) -% (mac_archive_utility_overflow_recovery_cursor.* & 0xffffffff);
                const expect_oddo = if (distance_to_next_thing == 0) false
                        else if (distance_to_next_thing == 16) true else {
                    // This is not the work of the Mac Archive Utility.
                    self.mac_archive_utility_overflow_recovery_cursor = null;
                    break :mac_stuff;
                };

                // We're reasonably certain we're dealing with mac archive utility.
                // Go searching for the signature of the next thing to find the end of this thing.
                while (true) {
                    const possible_signature = self.readInt32At(mac_archive_utility_overflow_recovery_cursor.*) catch {
                        // Didn't find the signature?
                        // I guess this isn't a Mac Archive Utility zip file.
                        self.mac_archive_utility_overflow_recovery_cursor = null;
                        break :mac_stuff;
                    };
                    if (possible_signature == if (expect_oddo) oddo_signature
                            else if (entry_index == entry_count - 1) cfh_signature else u32(lfh_signature)) {
                        // This is *probably* the end of the file contents.
                        // Or maybe this signature just happens to show up in the file contents.
                        // It's impossible to avoid ambiguities like this when trying to recover from the corruption,
                        // so let's just charge ahead with our heuristic.
                        if (expect_oddo) {
                            mac_archive_utility_overflow_recovery_cursor.* += 16;
                        }
                        break;
                    }
                    // Assume we're dealing with overflow.
                    mac_archive_utility_overflow_recovery_cursor.* += 0x100000000;
                    compressed_size += 0x100000000;
                }

                if (compressed_size > 0xffffffff) {
                    self.detectedMauCorruption("compressed size");
                }
            }

            try self.segments.append(Segment{
                .offset = local_header_offset,
                .kind = SegmentKind{.LocalFile = LocalFileInfo{
                    .entry_index = entry_index,
                    .is_zip64 = false,
                    .compressed_size = compressed_size,
                }},
            });
        }}

        if (entry_count > 0) {
            try self.segments.append(Segment{
                .offset = central_directory_offset,
                .kind = SegmentKind{.CentralDirectoryEntries = CentralDirectoryEntriesInfo{
                    .entry_count = entry_count,
                }},
            });
        }

        try self.segments.append(Segment{
            .offset = eocdr_offset,
            .kind = SegmentKind{.EndOfCentralDirectory = EndOfCentralDirectoryInfo{
                .eocdr_offset = eocdr_offset,
            }},
        });
    }

    fn dumpSegments(self: &Self) !void {
        std.sort.insertionSort(Segment, self.segments.toSlice(), segmentLessThan);

        var cursor: u64 = 0;
        for (self.segments.toSliceConst()) |segment, i| {
            if (i != 0) {
                try self.output.print("\n");
            }

            if (segment.offset > cursor) {
                try self.writeSectionHeader(cursor, "Unused space");
                try self.dumpBlobContents(cursor, segment.offset - cursor, Encoding.None);
                try self.output.print("\n");
                cursor = segment.offset;
            } else if (segment.offset < cursor) {
                cursor = segment.offset;
                @panic("TODO: overlapping regions");
            }

            const length = switch (segment.kind) {
                SegmentKind.LocalFile => |info| try self.dumpLocalFile(segment.offset, info),
                SegmentKind.CentralDirectoryEntries => |info| try self.dumpCentralDirectoryEntries(segment.offset, info),
                SegmentKind.EndOfCentralDirectory => |info| try self.dumpEndOfCentralDirectory(segment.offset, info),
            };
            cursor += length;
        }
    }

    fn dumpLocalFile(self: &Self, offset: u64, info: &const LocalFileInfo) !u64 {
        var cursor = offset;
        var lfh_buffer: [30]u8 = undefined;
        try self.readNoEof(cursor, lfh_buffer[0..]);
        if (readInt32(lfh_buffer, 0) != lfh_signature) {
            try self.writeSectionHeader(offset, "WARNING: invalid local file header signature");
            try self.output.print("\n");
            // if this isn't a local file, idk what it is.
            // call it unknown
            return 0;
        }

        try self.writeSectionHeader(offset, "Local File Header (#{})", info.entry_index);
        var lfh_cursor: usize = 0;
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 4, "Local file header signature");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 2, "Version needed to extract (minimum)");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 2, "General purpose bit flag");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 2, "Compression method");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 2, "File last modification time");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 2, "File last modification date");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 4, "CRC-32");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 4, "Compressed size");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 4, "Uncompressed size");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 2, "File name length (n)");
        try self.readStructField(lfh_buffer, 4, &lfh_cursor, 2, "Extra field length (m)");
        cursor += lfh_cursor;

        const file_name_length = readInt16(lfh_buffer, 26);
        const general_purpose_bit_flag = readInt16(lfh_buffer, 6);
        const is_utf8 = general_purpose_bit_flag & 0x800 != 0;
        const extra_fields_length = readInt16(lfh_buffer, 28);

        if (file_name_length > 0) {
            self.indent(); defer self.outdent();
            try self.output.print("\n");
            try self.writeSectionHeader(cursor, "File Name");
            try self.dumpBlobContents(cursor, file_name_length, if (is_utf8) Encoding.Utf8 else Encoding.Cp437);
            cursor += file_name_length;
        }
        if (extra_fields_length > 0) {
            self.indent(); defer self.outdent();
            try self.output.print("\n");
            try self.writeSectionHeader(cursor, "Extra Fields");
            try self.dumpBlobContents(cursor, extra_fields_length, Encoding.None);
            cursor += extra_fields_length;
        }

        if (info.compressed_size > 0) {
            try self.output.print("\n");
            try self.writeSectionHeader(cursor, "File Contents");
            try self.dumpBlobContents(cursor, info.compressed_size, Encoding.None);
            cursor += info.compressed_size;
        }

        // check for the optional data descriptor
        var data_descriptor_buffer: [16]u8 = undefined;
        if (self.readNoEof(cursor, data_descriptor_buffer[0..])) {
            if (readInt32(data_descriptor_buffer, 0) == oddo_signature) {
                // this is a data descriptor
                try self.output.print("\n");
                try self.writeSectionHeader(cursor, "Optional Data Descriptor");
                var data_descriptor_cursor: usize = 0;
                try self.readStructField(data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "optional data descriptor signature");
                try self.readStructField(data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "crc-32");
                try self.readStructField(data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "compressed size");
                try self.readStructField(data_descriptor_buffer, 4, &data_descriptor_cursor, 4, "uncompressed size");
                cursor += data_descriptor_cursor;
            }
        } else |err| {
            // ok, so there's no optional data descriptor here
        }

        return cursor - offset;
    }

    fn dumpCentralDirectoryEntries(self: &Self, offset: u64, info: &const CentralDirectoryEntriesInfo) !u64 {
        var cursor = offset;
        {var i: u32 = 0; while (i < info.entry_count) : (i += 1) {
            if (i > 0) try self.output.print("\n");

            var cdr_buffer: [46]u8 = undefined;
            try self.readNoEof(cursor, cdr_buffer[0..]);
            if (readInt32(cdr_buffer, 0) != cfh_signature) {
                try self.writeSectionHeader(cursor, "WARNING: invalid central file header signature");
                try self.output.print("\n");
                return 0;
            }

            try self.writeSectionHeader(cursor, "Central Directory Entry (#{})", i);
            var cdr_cursor: usize = 0;
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 4, "Central directory file header signature");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "Version made by");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "Version needed to extract (minimum)");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "General purpose bit flag");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "Compression method");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "File last modification time");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "File last modification date");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 4, "CRC-32");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 4, "Compressed size");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 4, "Uncompressed size");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "File name length (n)");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "Extra field length (m)");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "File comment length (k)");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "Disk number where file starts");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 2, "Internal file attributes");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 4, "External file attributes");
            try self.readStructField(cdr_buffer, 4, &cdr_cursor, 4, "Relative offset of local file header");
            cursor += cdr_cursor;

            const general_purpose_bit_flag = readInt16(cdr_buffer, 8);
            const is_utf8 = general_purpose_bit_flag & 0x800 != 0;
            const file_name_length = readInt16(cdr_buffer, 28);
            const extra_fields_length = readInt16(cdr_buffer, 30);
            const file_comment_length = readInt16(cdr_buffer, 32);

            if (file_name_length > 0) {
                self.indent(); defer self.outdent();
                try self.writeSectionHeader(cursor, "File name");
                try self.dumpBlobContents(cursor, file_name_length, if (is_utf8) Encoding.Utf8 else Encoding.Cp437);
                cursor += file_name_length;
            }
            if (extra_fields_length > 0) {
                self.indent(); defer self.outdent();
                try self.writeSectionHeader(cursor, "Extra Fields");
                try self.dumpBlobContents(cursor, extra_fields_length, Encoding.None);
                cursor += extra_fields_length;
            }
            if (file_comment_length > 0) {
                self.indent(); defer self.outdent();
                try self.writeSectionHeader(cursor, "File Comment");
                try self.dumpBlobContents(cursor, file_comment_length, Encoding.Cp437);
                cursor += file_comment_length;
            }
        }}

        return cursor - offset;
    }

    fn dumpEndOfCentralDirectory(self: &Self, offset: u64, info: &const EndOfCentralDirectoryInfo) !u64 {
        var total_length: u64 = 0;
        if (offset != info.eocdr_offset) {
            const zip64_eocdl_offset = info.eocdr_offset - 20;
            try self.writeSectionHeader(offset, "Zip64 end of central directory record");

            try self.writeSectionHeader(zip64_eocdl_offset, "Zip64 end of central directory locator");

            total_length = info.eocdr_offset - offset;
            @panic("TODO");
        }

        try self.writeSectionHeader(offset + total_length, "End of central directory record");
        var eocdr_buffer: [22]u8 = undefined;
        try self.readNoEof(offset, eocdr_buffer[0..]);
        var eocdr_cursor: usize = 0;
        try self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 4, "End of central directory signature");
        try self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Number of this disk");
        try self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Disk where central directory starts");
        try self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Number of central directory records on this disk");
        try self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Total number of central directory records");
        try self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 4, "Size of central directory (bytes)");
        try self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 4, "Offset of start of central directory, relative to start of archive");
        try self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Comment Length");
        const comment_length = readInt16(eocdr_buffer, 20);
        total_length += 22;

        if (comment_length > 0) {
            self.indent(); defer self.outdent();
            try self.writeSectionHeader(offset + total_length, ".ZIP file comment");
            try self.dumpBlobContents(offset + total_length, comment_length, Encoding.Cp437);
            total_length += comment_length;
        }

        return total_length;
    }

    fn dumpBlobContents(self: &Self, offset: u64, length: u64, encoding: Encoding) !void {
        var buffer: [0x1000]u8 = undefined;
        const row_length = 16;

        var utf8_byte_sequence_buffer: [4]u8 = undefined;
        var utf8_bytes_saved: usize = 0;
        var utf8_bytes_remaining: usize = 0;

        var cursor: u64 = 0;
        while (cursor < length) {
            const buffer_offset = offset + cursor;
            try self.readNoEof(buffer_offset, buffer[0..std.math.min(buffer.len, length - cursor)]);
            try self.printIndentation();
            const row_start = offset + cursor - buffer_offset;
            {var i: usize = 0; while (i < row_length - 1 and cursor < length - 1) : (i += 1) {
                try self.output.print("{x2} ", buffer[offset + cursor - buffer_offset]);
                cursor += 1;
            }}
            try self.output.print("{x2}", buffer[offset + cursor - buffer_offset]);
            cursor += 1;

            var row = buffer[row_start..offset + cursor - buffer_offset];
            switch (encoding) {
                Encoding.None => {},
                Encoding.Cp437 => {
                    if (length > row_length) {
                        var i: usize = row.len;
                        while (i < row_length) : (i += 1) {
                            try self.output.print("   ");
                        }
                    }
                    try self.output.print(" ; cp437\"");
                    for (row) |c| {
                        try self.output.write(cp437[c]);
                    }
                    try self.output.print("\"");
                },
                Encoding.Utf8 => {
                    if (length > row_length) {
                        var i: usize = row.len;
                        while (i < row_length) : (i += 1) {
                            try self.output.print("   ");
                        }
                    }
                    try self.output.print(" ; utf8\"");

                    // input is utf8; output is utf8.
                    var i: usize = 0;
                    if (utf8_bytes_remaining > 0) {
                        while (i < utf8_bytes_remaining) : (i += 1) {
                            utf8_byte_sequence_buffer[utf8_bytes_saved + i] = row[i];
                        }
                        try self.dumpUtf8Codepoint(utf8_byte_sequence_buffer[0..utf8_bytes_saved + utf8_bytes_remaining]);
                        utf8_bytes_saved = 0;
                        utf8_bytes_remaining = 0;
                    }

                    while (i < row.len) : (i += 1) {
                        const utf8_length = std.unicode.utf8ByteSequenceLength(row[i]) catch {
                            // invalid utf8 start byte. replace with the error character.
                            try self.output.write(error_character);
                            continue;
                        };

                        if (i + utf8_length > row.len) {
                            // this sequence wraps onto the next line.
                            if (i + utf8_length - row.len > length - cursor) {
                                // there is no next line. unexpected eof.
                                try self.output.write(error_character);
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
                        try self.dumpUtf8Codepoint(row[i..i + utf8_length]);
                        i += utf8_length - 1;
                    }
                    try self.output.print("\"");
                },
            }
            try self.output.print("\n");
        }
    }

    fn dumpUtf8Codepoint(self: &Self, byte_sequence: []const u8) !void {
        const codepoint = std.unicode.utf8Decode(byte_sequence) catch {
            // invalid utf8 seequcne becomes a single error character.
            return self.output.write(error_character);
        };
        // some special escapes
        switch (codepoint) {
            '\n' => return self.output.write("\\n"),
            '\r' => return self.output.write("\\r"),
            '\t' => return self.output.write("\\t"),
            '"'  => return self.output.write("\\\""),
            '\\' => return self.output.write("\\\\"),
            else => {},
        }
        // numeric escapes
        switch (codepoint) {
            // ascii control codes
            0...0x1f, 0x7f => return self.output.print("\\x{x2}", codepoint),
            // unicode newline characters
            0x805, 0x2028, 0x2029 => return self.output.print("\\u{x4}", codepoint),
            else => {},
        }
        // literal character
        return self.output.write(byte_sequence);
    }

    fn writeSectionHeader(self: &Self, offset: u64, comptime fmt: []const u8, args: ...) !void {
        var offset_str_buf: [16]u8 = undefined;
        const offset_str = offset_str_buf[0..std.fmt.formatIntBuf(offset_str_buf[0..], offset, 16, false, self.offset_padding)];

        try self.printIndentation();
        try self.output.print(":0x{} ; ", offset_str);
        try self.output.print(fmt, args);
        try self.output.print("\n");
    }

    fn readStructField(self: &Self, buffer: []const u8, comptime max_size: usize, cursor: &usize,
        comptime size: usize, name: []const u8) !void
    {
        comptime std.debug.assert(size <= max_size);
        comptime const decimal_width_str = switch (max_size) {
            2 => "5",
            4 => "10",
            8 => "20",
            else => unreachable,
        };

        try self.printIndentation();
        switch (size) {
            2 => {
                var value = readInt16(buffer, cursor.*);
                try self.output.print(
                    "{x2} {x2}" ++ ("   " ** (max_size - size)) ++
                    " ; \"{}{}\"" ++ (" " ** (max_size - size)) ++
                    " ; {d" ++ decimal_width_str ++ "}" ++
                    " ; 0x{x4}" ++ ("  " ** (max_size - size)) ++
                    " ; {}" ++
                    "\n",
                    buffer[cursor.* + 0], buffer[cursor.* + 1],
                    cp437[buffer[cursor.* + 0]], cp437[buffer[cursor.* + 1]],
                    value,
                    value,
                    name,
                );
            },
            4 => {
                var value = readInt32(buffer, cursor.*);
                try self.output.print(
                    "{x2} {x2} {x2} {x2}" ++ ("   " ** (max_size - size)) ++
                    " ; \"{}{}{}{}\"" ++ (" " ** (max_size - size)) ++
                    " ; {d" ++ decimal_width_str ++ "}" ++
                    " ; 0x{x8}" ++ ("  " ** (max_size - size)) ++
                    " ; {}" ++
                    "\n",
                    buffer[cursor.* + 0], buffer[cursor.* + 1], buffer[cursor.* + 2], buffer[cursor.* + 3],
                    cp437[buffer[cursor.* + 0]], cp437[buffer[cursor.* + 1]], cp437[buffer[cursor.* + 2]], cp437[buffer[cursor.* + 3]],
                    value,
                    value,
                    name,
                );
            },
            8 => @panic("TODO"),
            else => unreachable,
        }
        cursor.* += size;
    }

    fn detectedMauCorruption(self: &Self, field_name: []const u8) void {
        std.debug.warn("WARNING: detected Mac Archive Utility corruption in field: {}\n", field_name);
    }

    fn indent(self: &Self) void {
        self.indentation += 1;
    }
    fn outdent(self: &Self) void {
        self.indentation -= 1;
    }
    fn printIndentation(self: &Self) !void {
        {var i: u2 = 0; while (i < self.indentation) : (i += 1) {
            try self.output.print("  ");
        }}
    }

    fn readNoEof(self: &Self, offset: u64, buffer: []u8) !void {
        try self.input_file.seekTo(usize(offset)); // FIXME: shouldn't need cast: https://github.com/zig-lang/zig/issues/637
        try self.input.readNoEof(buffer);
    }
    fn readByteAt(self: &Self, offset: u64) !u8 {
        var buffer: [1]u8 = undefined;
        try self.readNoEof(offset, buffer[0..]);
        return buffer[0];
    }
    fn readInt32At(self: &Self, offset: u64) !u32 {
        var buffer: [4]u8 = undefined;
        try self.readNoEof(offset, buffer[0..]);
        return readInt32(buffer, 0);
    }
    fn isSignatureAt(self: &Self, offset: u64, signature: u32) bool {
        return signature == (self.readInt32At(offset) catch return false);
    }
};

fn readInt16(buffer: []const u8, offset: usize) u16 {
    return std.mem.readIntLE(u16, buffer[offset..offset+2]);
}
fn readInt32(buffer: []const u8, offset: usize) u32 {
    return std.mem.readIntLE(u32, buffer[offset..offset+4]);
}
fn readInt64(buffer: []const u8, offset: usize) u64 {
    return std.mem.readIntLE(u64, buffer[offset..offset+8]);
}

const cp437 = [][]const u8{
    "�","☺","☻", "♥","♦","♣","♠","•","◘","○","◙","♂","♀", "♪","♫","☼",
    "►","◄","↕", "‼","¶","§","▬","↨","↑","↓","→","←","∟", "↔","▲","▼",
    " ","!","\"","#","$","%","&","'","(",")","*","+",",", "-",".","/",
    "0","1","2", "3","4","5","6","7","8","9",":",";","<", "=",">","?",
    "@","A","B", "C","D","E","F","G","H","I","J","K","L", "M","N","O",
    "P","Q","R", "S","T","U","V","W","X","Y","Z","[","\\","]","^","_",
    "`","a","b", "c","d","e","f","g","h","i","j","k","l", "m","n","o",
    "p","q","r", "s","t","u","v","w","x","y","z","{","|", "}","~","⌂",
    "Ç","ü","é", "â","ä","à","å","ç","ê","ë","è","ï","î", "ì","Ä","Å",
    "É","æ","Æ", "ô","ö","ò","û","ù","ÿ","Ö","Ü","¢","£", "¥","₧","ƒ",
    "á","í","ó", "ú","ñ","Ñ","ª","º","¿","⌐","¬","½","¼", "¡","«","»",
    "░","▒","▓", "│","┤","╡","╢","╖","╕","╣","║","╗","╝", "╜","╛","┐",
    "└","┴","┬", "├","─","┼","╞","╟","╚","╔","╩","╦","╠", "═","╬","╧",
    "╨","╤","╥", "╙","╘","╒","╓","╫","╪","┘","┌","█","▄", "▌","▐","▀",
    "α","ß","Γ", "π","Σ","σ","µ","τ","Φ","Θ","Ω","δ","∞", "φ","ε","∩",
    "≡","±","≥", "≤","⌠","⌡","÷","≈","°","∙","·","√","ⁿ", "²","■"," ",
};
