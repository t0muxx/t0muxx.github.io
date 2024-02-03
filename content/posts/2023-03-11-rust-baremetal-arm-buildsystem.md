+++
author = "t0muxx"
categories = ["RRK"]
date = "2023-03-11T00:00:00Z"
tags = ["rust", "ARM baremetal", "OSdev","kernel"]
title = "Rust bare metal build system adventures"
+++

During the developpment of my Raspberry Rust Kernel (RRK), I wanted to compile a bare-metal firmware for the `Raspberry Pi 3 b`
After tried using `cargo xbuild` I switched to classic cargo cross-compilation.
Let's use the easiest solution using `rustup` to install the correct target for the cross-compilation.

(This blogpost is related to my custom Raspberry pi3 kernel : https://github.com/t0muxx/RRK_raspberry_rust_kernel. It contains some informations that i found useful and wanted to share.)

<!--more-->

## Install target with rustup

First I assume the rustup setup has been done. I use the default x86_64 nigthly toolchain.
We will use the target : `aarch64-unknown-none`. The target format is `machine-vendor-operatingsystem`.

- `aarch64` : because RPi 3 runs aarch64.
- `unkown` : because vendor is irrelevant here.
- `none` : because our custom OS is not yet a popular target :D

Now to install the target we want :
- `rustup target add aarch64-unknown-none`

## Specifiy target for our project

We use a `.cargo/config.toml` file in the project to specify the compilation target.
```toml
[build]
target = "aarch64-unknown-none"
```

Another possibility is to specify target using `--target` option.

## Command line 

I uses this command line to compile the project :
- `RUSTFLAGS='-C link-arg=--script=aarch64-rasp3b.ld' cargo rustc --features qemu --release --manifest-path crates/kernel/Cargo.toml`

In the `RUSTFLAGS` env variable I set the linker script that will be used by the linker. 
I also specify  `--manifest-path` of my kernel crate. I need to specify it because the root `Cargo.toml` of the project is a virtual manifest (i use `workspace` with two crates atm).

It's possible to specify the `RUSTFLAGS` in the file `.cargo/config.toml` :

```toml
[target.aarch64-unknown-none]
rustflags = [
    "-C" , "link-arg=--script=aarch64-rasp3b.ld",
]

[build]
target = "aarch64-unknown-none"
```

## Linker file

A linker file is required as for bare-metal developpment we need to specify the memory layout and to specify an entrypoint for our compiled firmware.
I use a pretty simple linker file.

```c
/* Declare the entrypoint */
ENTRY(_start)

SECTIONS
{
    . = 0x80000;
    /* Set _start to 0x80000 */
    __start = .; 
    .text :
    {
        /* KEEP means no linker optimization */
        KEEP(*(.text.boot))
        KEEP(*(.text*))                 /* Everything else */
    } :segment_code
 
    .rodata ALIGN(16) : { 
        *(.rodata*) 
    } 
 
    .data ALIGN(16) : { 
        *(.data*) 
    } 
 
    _bss_start = .;
    .bss (NOLOAD) : { 
        *(.bss*) 
    } 
    _bss_end = .;
}

```

The `_start` symbol corespond to an assembler function that is executed first.
The `.text.boot` section is defined and contains bootcode. (see [start.s](https://github.com/t0muxx/RRK_raspberry_rust_kernel/blob/main/crates/kernel/src/start.s))

## Elf to firmware blob

The rust compiler generated an ELF file from our code. The raspberry pi does not load an ELF file but a data blob, so we need to transform our ELF file.
To achieve that I use the command :
- `aarch64-buildroot-linux-uclibc/bin/objcopy -O binary target/aarch64-unknown-none/release/kernel kernel8.img`

The `-O binary` allows to generate a raw binary file.

(Yes it requires an aarch64 toolchain. Mine has been build using [buildroot](https://buildroot.org/))

From now, It's should be possible to load the firmware.
