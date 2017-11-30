const std = @import("std");

const general_allocator = &std.heap.c_allocator;
const Dir = std.os.Dir;
const Buffer = std.Buffer;

error Usage;
fn usage() -> error {
    std.debug.warn("usage: INPUT.zip OUTPUT.hex\n");
    return error.Usage;
}

error NotAZipFile;

pub fn main() -> %void {
    var args = std.os.args();
    _ = args.nextPosix() ?? return usage();
    const input_path_str = args.nextPosix() ?? return usage();
    const output_path_str = args.nextPosix() ?? return usage();
    if (args.nextPosix() != null) return usage();

    var tmp_path = %return Buffer.init(general_allocator, output_path_str);
    %return tmp_path.append(".tmp");

    %return cleanOutputDir(&tmp_path);
    %return ensureDirExists(tmp_path);

    var input_file = %return std.io.File.openRead(input_path_str, general_allocator);
    defer input_file.close();

    var zipfile_reader = ZipfileReader.init(&input_file, &tmp_path, general_allocator);
    %return zipfile_reader.doIt();

    //%return cleanOutputDir(&tmp_path);
}

const ZipfileReader = struct {
    input_file: &std.io.File,
    input_file_stream_impl: std.io.FileInStream,
    tmp_path: &Buffer,
    allocator: &std.mem.Allocator,
    segment_count: usize,

    pub fn init(input_file: &std.io.File, tmp_path: &Buffer, allocator: &std.mem.Allocator) -> ZipfileReader {
        return ZipfileReader {
            .input_file = input_file,
            .input_file_stream_impl = std.io.FileInStream.init(input_file),
            .tmp_path = tmp_path,
            .allocator = allocator,
            .segment_count = 0,
        };
    }

    pub fn doIt(self: &ZipfileReader) -> %void {
        const file_size = u64(%return self.input_file.getEndPos()); // TODO: shouldn't need cast: https://github.com/zig-lang/zig/issues/637

        if (file_size < 22) return error.NotAZipFile;
        var eocdr_offset = file_size - 22;
        %return self.input_file.seekTo(usize(eocdr_offset)); // TODO: shouldn't need cast: https://github.com/zig-lang/zig/issues/637
        var eocdr_buffer: [22]u8 = undefined;
        %return self.readNoEof(eocdr_buffer[0..]);

        const signature = readInt32(eocdr_buffer, 0);
        if (signature != 0x06054b50) return error.NotAZipFile;
        // TODO: search backwards over the comment

        {
            var segment: Segment = undefined;
            %return self.openSegment(&segment, eocdr_offset);
            defer segment.file.close();

            %return self.readEocdr(&segment, "End of Central Directory Record", eocdr_buffer[0..]);

            %return segment.buffered_output_stream.flush();
        }
    }

    fn writeSegmentHeader(self: &ZipfileReader, segment: &Segment, name: []const u8) -> %void {
        %return segment.buffered_output_stream.stream.print(":0x{x16} ; {}\n", segment.offset, name);
    }

    fn readEocdr(self: &ZipfileReader, segment: &Segment, name: []const u8, buffer: []const u8) -> %void {
        %return self.writeSegmentHeader(segment, name);

        var cursor: usize = 0;
        %return self.readStructField(segment, buffer, 4, &cursor, 4, "End of central directory signature");
        %return self.readStructField(segment, buffer, 4, &cursor, 2, "Number of this disk");
        %return self.readStructField(segment, buffer, 4, &cursor, 2, "Disk where central directory starts");
        %return self.readStructField(segment, buffer, 4, &cursor, 2, "Number of central directory records on this disk");
        %return self.readStructField(segment, buffer, 4, &cursor, 2, "Total number of central directory records");
        %return self.readStructField(segment, buffer, 4, &cursor, 4, "Size of central directory (bytes)");
        %return self.readStructField(segment, buffer, 4, &cursor, 4, "Offset of start of central directory, relative to start of archive");
        %return self.readStructField(segment, buffer, 4, &cursor, 2, "Comment Length");
    }

    fn readStructField(self: &ZipfileReader, segment: &Segment, buffer: []const u8, comptime max_size: usize, cursor: &usize,
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
                %return segment.buffered_output_stream.stream.print(
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
                %return segment.buffered_output_stream.stream.print(
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

    const Segment = struct {
        offset: u64,
        length: u64,
        file: std.io.File,
        file_stream: std.io.FileOutStream,
        buffered_output_stream: std.io.BufferedOutStream,
    };

    fn openSegment(self: &ZipfileReader, segment: &Segment, offset: u64) -> %void {
        const original_path_len = self.tmp_path.len();
        %return self.tmp_path.appendFormat("/{}", self.segment_count);
        self.segment_count += 1;
        defer self.tmp_path.shrink(original_path_len);

        // TODO: refeactor once we have https://github.com/zig-lang/zig/issues/287
        segment.offset = offset;
        segment.length = 0;
        segment.file = %return std.io.File.openWrite(self.tmp_path.toSliceConst(), self.allocator);
        segment.file_stream = std.io.FileOutStream.init(&segment.file);
        segment.buffered_output_stream = std.io.BufferedOutStream.init(&segment.file_stream.stream);
    }

    fn readNoEof(self: &ZipfileReader, buffer: []u8) -> %void {
        return self.input_file_stream_impl.stream.readNoEof(buffer);
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

fn ensureDirExists(path: &const Buffer) -> %void {
    std.os.makeDir(general_allocator, path.toSliceConst()) %% |err| {
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
    {
        var dir = Dir.open(general_allocator, path.toSliceConst()) %% |err| switch (err) {
            error.PathNotFound => return,
            else => return err,
        };
        defer dir.close();

        const original_path_len = path.len();
        while (%return dir.next()) |entry| {
            %return path.appendByte('/');
            %return path.append(entry.name);
            defer path.shrink(original_path_len);

            %return std.os.deleteFile(general_allocator, path.toSliceConst());
        }
    }

    %return std.os.deleteDir(general_allocator, path.toSliceConst());
}

