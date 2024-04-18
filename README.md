# hexdump-zip
produce an annotated hexdump of a zipfile

## Build

Download or install [zig](http://ziglang.org/).
(Check the commit log of this repo to see which version was used recently.)

```
zig build
```

Executable binary is at `./zig-out/bin/hexdump-zip`.

## Run

```
hexdump-zip INPUT.zip OUTPUT.hex
```

To print to stdout, you can give `/dev/stdout` as the output path.
