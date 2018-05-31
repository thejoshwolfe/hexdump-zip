# hexdump-zip

produce an annotated hexdump of a zipfile

## Build

Install [zig](http://ziglang.org/).

```
$ zig build
```

Executable binary is at `zig-cache/hexdump-zip`.

## Run

```
hexdump-zip INPUT.zip OUTPUT.hex
```

## Test

This project uses git submodules:

```
$ git submodule update --init --recursive
```

Then:

```
$ zig build test
```
