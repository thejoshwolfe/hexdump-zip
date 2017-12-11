const std = @import("std");

const general_allocator = &std.heap.c_allocator;

error Usage;
fn usage() -> error {
    std.debug.warn("usage: INPUT.zip OUTPUT.hex\n");
    return error.Usage;
}

error NotAZipFile;
error FileTooBig;
error MultiDiskZipfileNotSupported;

pub fn main() -> %void {
    var args = std.os.args();
    _ = args.nextPosix() ?? return usage();
    const input_path_str = args.nextPosix() ?? return usage();
    const output_path_str = args.nextPosix() ?? return usage();
    if (args.nextPosix() != null) return usage();

    var input_file = %return std.io.File.openRead(input_path_str, general_allocator);
    defer input_file.close();

    var output_file = %return std.io.File.openWrite(output_path_str, general_allocator);
    defer output_file.close();

    var zipfile_dumper: ZipfileDumper = undefined;
    %return zipfile_dumper.init(&input_file, &output_file, general_allocator);
    %return zipfile_dumper.doIt();
}

const SegmentList = std.ArrayList(Segment);
const SegmentKind = union(enum) {
    LocalFile: LocalFileInfo,
    CentralDirectoryEntries,
    EndOfCentralDirectory: EndOfCentralDirectoryInfo,
};
const Segment = struct {
    offset: u64,
    kind: SegmentKind,
};
const LocalFileInfo = struct {
    compressed_size: u64,
    is_zip64: bool,
};
const EndOfCentralDirectoryInfo = struct {
    eocdr_offset: u64,
};
fn segmentLessThan(a: &const Segment, b: &const Segment) -> bool {
    return a.offset < b.offset;
}


const eocdr_size = 22;
const eocdr_search_size: u64 = 0xffff + eocdr_size;

const ZipfileDumper = struct {
    const Self = this;

    input_file: &std.io.File,
    input_file_stream: std.io.FileInStream,
    input: &std.io.InStream,
    file_size: u64,
    output_file: &std.io.File,
    output_file_stream: std.io.FileOutStream,
    buffered_output_stream: std.io.BufferedOutStream,
    output: &std.io.OutStream,
    allocator: &std.mem.Allocator,
    segments: SegmentList,

    pub fn init(self: &Self, input_file: &std.io.File, output_file: &std.io.File, allocator: &std.mem.Allocator) -> %void {
        // TODO: return a new object once we have https://github.com/zig-lang/zig/issues/287

        self.input_file = input_file;
        self.input_file_stream = std.io.FileInStream.init(self.input_file);
        self.input = &self.input_file_stream.stream;
        self.file_size = u64(%return self.input_file.getEndPos()); // TODO: shouldn't need cast: https://github.com/zig-lang/zig/issues/637
        // this limit eliminates most silly overflow checks on the file offset.
        if (self.file_size > 0x7fffffffffffffff) return error.FileTooBig;

        self.output_file = output_file;
        self.output_file_stream = std.io.FileOutStream.init(self.output_file);
        self.buffered_output_stream = std.io.BufferedOutStream.init(&self.output_file_stream.stream);
        self.output = &self.buffered_output_stream.stream;

        self.allocator = allocator;
        self.segments = SegmentList.init(allocator);
    }

    pub fn doIt(self: &Self) -> %void {
        %return self.findSegments();
        %return self.dumpSegments();
        %return self.buffered_output_stream.flush();
    }

    fn findSegments(self: &Self) -> %void {
        // find the eocdr
        if (self.file_size < eocdr_size) return error.NotAZipFile;
        var eocdr_search_buffer: [eocdr_search_size]u8 = undefined;
        const eocdr_search_slice = eocdr_search_buffer[0..usize(std.math.min(self.file_size, eocdr_search_size))];
        %return self.readNoEof(self.file_size - eocdr_search_slice.len, eocdr_search_slice);
        // seek backward over the comment looking for the signature
        var comment_length: u16 = 0;
        var eocdr_buffer: []const u8 = undefined;
        while (true) : (comment_length += 1) {
            var cursor = eocdr_search_slice.len - comment_length - eocdr_size;
            if (readInt32(eocdr_search_slice, cursor) == 0x06054b50) {
                // found it
                eocdr_buffer = eocdr_search_slice[cursor..cursor + eocdr_size];
                break;
            }
            if (cursor == 0) return error.NotAZipFile;
        }
        const eocdr_offset = self.file_size - comment_length - eocdr_size;

        const signature = readInt32(eocdr_buffer, 0);
        if (signature != 0x06054b50) return error.NotAZipFile;
        %return self.segments.append(Segment{
            .offset = eocdr_offset,
            .kind = SegmentKind{.EndOfCentralDirectory = EndOfCentralDirectoryInfo{
                .eocdr_offset = eocdr_offset,
            }},
        });

        const disk_number = readInt16(eocdr_buffer, 4);
        if (disk_number != 0) return error.MultiDiskZipfileNotSupported;

        var entry_count: u32 = readInt16(eocdr_buffer, 10);
        var central_directory_offset: u64 = readInt32(eocdr_buffer, 16);
        // TODO: check for ZIP64 format

        if (entry_count > 0) {
            %return self.segments.append(Segment{
                .offset = central_directory_offset,
                .kind = SegmentKind.CentralDirectoryEntries,
            });
        }

        var central_directory_cursor: u64 = central_directory_offset;
        {var remaining_entries: u32 = entry_count; while (remaining_entries > 0) : (remaining_entries -= 1) {
            var cdr_buffer: [46]u8 = undefined;
            %return self.readNoEof(central_directory_cursor, cdr_buffer[0..]);

            var compressed_size: u64 = readInt32(cdr_buffer, 20);
            const file_name_length = readInt16(cdr_buffer, 28);
            const extra_fields_length = readInt16(cdr_buffer, 30);
            const file_comment_length = readInt16(cdr_buffer, 32);
            var relative_offset_of_local_header: u64 = readInt32(cdr_buffer, 42);

            // TODO: check for ZIP64 format
            var is_zip64 = false;

            %return self.segments.append(Segment{
                .offset = relative_offset_of_local_header,
                .kind = SegmentKind{.LocalFile = LocalFileInfo{
                    .is_zip64 = false,
                    .compressed_size = compressed_size,
                }},
            });

            central_directory_cursor += 46;
            central_directory_cursor += file_name_length;
            central_directory_cursor += extra_fields_length;
            central_directory_cursor += file_comment_length;
        }}
    }

    fn dumpSegments(self: &Self) -> %void {
        std.sort.insertionSort(Segment, self.segments.toSlice(), segmentLessThan);

        var cursor: u64 = 0;
        for (self.segments.toSliceConst()) |segment, i| {
            if (i != 0) {
                %return self.output.print("\n");
            }

            if (segment.offset > cursor) {
                // TODO: unused space
                cursor = segment.offset;
            } else if (segment.offset < cursor) {
                // TODO: overlapping regions
                cursor = segment.offset;
            }

            const length = switch (segment.kind) {
                SegmentKind.LocalFile => |info| %return self.dumpLocalFile(segment.offset, info),
                SegmentKind.CentralDirectoryEntries => %return self.dumpCentralDirectoryEntries(segment.offset),
                SegmentKind.EndOfCentralDirectory => |info| %return self.dumpEndOfCentralDirectory(segment.offset, info),
            };
            cursor += length;
        }
    }

    fn dumpLocalFile(self: &Self, offset: u64, info: &const LocalFileInfo) -> %u64 {
        // TODO
        return 0;
    }

    fn dumpCentralDirectoryEntries(self: &Self, offset: u64) -> %u64 {
        // TODO
        return 0;
    }

    fn dumpEndOfCentralDirectory(self: &Self, offset: u64, info: &const EndOfCentralDirectoryInfo) -> %u64 {
        var total_length: u64 = 0;
        if (offset != info.eocdr_offset) {
            const zip64_eocdl_offset = info.eocdr_offset - 20;
            %return self.writeSectionHeader(offset, "Zip64 end of central directory record");
            // TODO

            %return self.writeSectionHeader(zip64_eocdl_offset, "Zip64 end of central directory locator");
            // TODO

            total_length = info.eocdr_offset - offset;
        }

        %return self.writeSectionHeader(offset + total_length, "End of central directory record");
        var eocdr_buffer: [22]u8 = undefined;
        %return self.readNoEof(offset, eocdr_buffer[0..]);
        var eocdr_cursor: usize = 0;
        %return self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 4, "End of central directory signature");
        %return self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Number of this disk");
        %return self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Disk where central directory starts");
        %return self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Number of central directory records on this disk");
        %return self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Total number of central directory records");
        %return self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 4, "Size of central directory (bytes)");
        %return self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 4, "Offset of start of central directory, relative to start of archive");
        %return self.readStructField(eocdr_buffer, 4, &eocdr_cursor, 2, "Comment Length");
        const comment_length = readInt16(eocdr_buffer, 20);
        total_length += 22;

        if (comment_length > 0) {
            %return self.writeSectionHeader(offset + total_length, ".ZIP file comment");
            // TODO: self.dumpCp437Blob(offset + total_length, comment_length);
            total_length += comment_length;
        }

        return total_length;
    }

    fn writeSectionHeader(self: &Self, offset: u64, name: []const u8) -> %void {
        %return self.output.print(":0x{x16} ; {}\n", offset, name);
    }

    fn readStructField(self: &Self, buffer: []const u8, comptime max_size: usize, cursor: &usize,
        comptime size: usize, name: []const u8) -> %void
    {
        comptime std.debug.assert(size <= max_size);
        comptime const decimal_width_str = switch (max_size) {
            2 => "5",
            4 => "10",
            8 => "20",
            else => unreachable,
        };
        switch (size) {
            2 => {
                var value = readInt16(buffer, *cursor);
                %return self.output.print(
                    "{x2} {x2}" ++ ("   " ** (max_size - size)) ++
                    " ; \"{}{}\"" ++ (" " ** (max_size - size)) ++
                    " ; {d" ++ decimal_width_str ++ "}" ++
                    " ; 0x{x4}" ++ ("  " ** (max_size - size)) ++
                    " ; {}" ++
                    "\n",
                    buffer[*cursor + 0], buffer[*cursor + 1],
                    cp437[buffer[*cursor + 0]], cp437[buffer[*cursor + 1]],
                    value,
                    value,
                    name,
                );
            },
            4 => {
                var value = readInt32(buffer, *cursor);
                %return self.output.print(
                    "{x2} {x2} {x2} {x2}" ++ ("   " ** (max_size - size)) ++
                    " ; \"{}{}{}{}\"" ++ (" " ** (max_size - size)) ++
                    " ; {d" ++ decimal_width_str ++ "}" ++
                    " ; 0x{x8}" ++ ("  " ** (max_size - size)) ++
                    " ; {}" ++
                    "\n",
                    buffer[*cursor + 0], buffer[*cursor + 1], buffer[*cursor + 2], buffer[*cursor + 3],
                    cp437[buffer[*cursor + 0]], cp437[buffer[*cursor + 1]], cp437[buffer[*cursor + 2]], cp437[buffer[*cursor + 3]],
                    value,
                    value,
                    name,
                );
            },
            8 => {
                unreachable; // TODO
            },
            else => unreachable,
        }
        *cursor += size;
    }

    fn readNoEof(self: &Self, offset: u64, buffer: []u8) -> %void {
        %return self.input_file.seekTo(usize(offset)); // TODO: shouldn't need cast: https://github.com/zig-lang/zig/issues/637
        %return self.input.readNoEof(buffer);
    }
};

fn readInt16(buffer: []const u8, offset: usize) -> u16 {
    return std.mem.readIntLE(u16, buffer[offset..offset+2]);
}
fn readInt32(buffer: []const u8, offset: usize) -> u32 {
    return std.mem.readIntLE(u32, buffer[offset..offset+4]);
}
fn readInt64(buffer: []const u8, offset: usize) -> u64 {
    return std.mem.readIntLE(u64, buffer[offset..offset+8]);
}
fn reprChar(c: u8) -> []const u8 {
    return cp437[c];
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
