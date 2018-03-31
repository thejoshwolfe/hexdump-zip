# hexdump-zip
produce an annotated hexdump of a zipfile

## Build

Install [zig](http://ziglang.org/).

```
$ mkdir build && cd build
$ zig build-exe --library c ../src/hexdump-zip.zig
```

Executable binary is at `build/hexdump-zip`.

## Run

```
hexdump-zip INPUT.zip OUTPUT.hex
```
