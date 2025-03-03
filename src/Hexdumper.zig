output: std.io.AnyWriter,
indentation: u8 = 0,

const std = @import("std");
const assert = std.debug.assert;
const Hexdumper = @This();

pub fn writeSectionHeader(self: *Hexdumper, offset: u64, comptime fmt: []const u8, args: anytype) !void {
    try self.printIndentation();
    try self.printf(":0x{x} ; ", .{offset});
    try self.printf(fmt, args);
    try self.write("\n");
}

pub fn readStructField(
    self: *Hexdumper,
    buffer: []const u8,
    comptime max_size: usize,
    cursor: *usize,
    comptime size: usize,
    name: []const u8,
) !void {
    comptime assert(size <= max_size);
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

pub fn indent(self: *Hexdumper) void {
    self.indentation += 1;
}
pub fn outdent(self: *Hexdumper) void {
    self.indentation -= 1;
}
pub fn printIndentation(self: *Hexdumper) !void {
    var i: u8 = 0;
    while (i < self.indentation) : (i += 1) {
        try self.write("  ");
    }
}
pub fn write(self: *Hexdumper, str: []const u8) !void {
    try self.output.writeAll(str);
}
pub fn printf(self: *Hexdumper, comptime fmt: []const u8, args: anytype) !void {
    try self.output.print(fmt, args);
}

pub const PartialUtf8State = struct {
    codepoint: [4]u8 = undefined,
    bytes_saved: u2 = 0,
    bytes_remaining: u2 = 0,
};
pub const BlobConfig = struct {
    row_length: u16 = 16,
    spaces: bool = true,
    encoding: enum {
        none,
        cp437,
        utf8,
    } = .none,
};

pub fn writeBlob(self: *Hexdumper, buffer: []const u8, config: BlobConfig) !void {
    var partial_utf8_state = PartialUtf8State{};
    try self.writeBlobPart(buffer, config, true, true, &partial_utf8_state);
}
pub fn writeBlobPart(self: *Hexdumper, buffer: []const u8, config: BlobConfig, is_beginning: bool, is_end: bool, partial_utf8_state: *PartialUtf8State) !void {
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

fn writeBlobRow(self: *Hexdumper, row: []const u8, config: BlobConfig, is_beginning: bool, is_end: bool, partial_utf8_state: *PartialUtf8State) !void {
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

fn writeEscapedCodepoint(self: *Hexdumper, byte_sequence: []const u8) !void {
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

fn readInt16(buffer: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, buffer[offset..][0..2], .little);
}
fn readInt32(buffer: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, buffer[offset..][0..4], .little);
}
fn readInt64(buffer: []const u8, offset: usize) u64 {
    return std.mem.readInt(u64, buffer[offset..][0..8], .little);
}

const error_character = "\xef\xbf\xbd";

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
