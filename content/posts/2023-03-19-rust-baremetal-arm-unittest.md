+++
author = "t0muxx"
categories = ["RRK"]
date = "2023-03-19T00:00:00Z"
tags = ["rust", "ARM baremetal", "OSdev","kernel"]
title = "Rust bare metal unit test with Qemu"
+++

(This blogpost is related to my custom Raspberry Pi 3b kernel : [RRK](https://github.com/t0muxx/RRK_raspberry_rust_kernel). It contains some information that I found useful and wanted to share.)

DISCLAIMER : most of this content is ~~stolen~~ gracefully inspired from : https://github.com/rust-embedded/rust-raspberrypi-OS-tutorials/tree/master/12_integrated_testing. I just think that it can be quite dense to understand so I wanted to summarize it here.

<!--more-->

## Unit testing

Rust unit testing is a really useful functionality. I will not cover basic rust testing here if you want to know more about basic unit testing with rust : https://doc.rust-lang.org/book/ch11-01-writing-tests.html.

In the case of a bare metal kernel, it's impossible to use standard rust tests mainly because :
- it's compiled with `#![_no_std_]` attribute
- the code is made for running on a different architecture and machine.

But by using some rust functionalities, it's possible to implements unit tests. I will describe how I implemented this in `RRK`.

## Compiling as a library

Firstly, I implemented the possibility to compile my crate as a library in the `Cargo.tom`
```toml
[lib]
name = "libkernel"
test = true

[[bin]]
name = "kernel"
test = false

```

The `test` attribute indicate whether or not the target is tested by `cargo test`.
This compilation as a library will helps to have two different `entrypoint` :
- One when compiling for tests
- One when compiling normally.

In the file `lib.rs` I wrote a specific entrypoint used for tests :

```rust
#[cfg(test)]
global_asm!(include_str!("start.s"));

#[cfg(test)]
#[no_mangle]
pub extern "C" fn entry() {
    let drivers = drivers::Drivers::new();
    drivers.init();
    test_main();
    cpu::qemu::exit_success();
}
```

The conditional compilation `#[cfg(test)]` specify the compiler to compile this function only when `test` is set (aka when running `cargo test`).

This library will also be used for integration testing.

## Custom test configuration - Conditional compilation

Now I have to make some configuration for the rust compiler in the `lib.rs`.

First thing to specify is to tell the compiler to not create a `main` when it compile the tests.
This is done using [conditional compilation](https://doc.rust-lang.org/reference/conditional-compilation.html) :
```rust
// No main when cargo test is run.
#![cfg_attr(test, no_main)]
```

After that I need to specify that I want to enable the [custom_test_frameworks](https://doc.rust-lang.org/beta/unstable-book/language-features/custom-test-frameworks.html) feature :
```rust
// Enable custom test frameworks
#![feature(custom_test_frameworks)]
```

Now I can specify the name of the `test_harness_main`. This is the tests's main that needs to be called for the tests to be executed. I call the function `test_main` in tests `entry()` function.
```rust
// We change the name of the test main function.
#![reexport_test_harness_main = "test_main"]
```

Last things I had to setup is to declare my custom test runner :

```rust
// we set this runner
#![test_runner(crate::test_runner)]
```

I will show the `test_runner` code in the next part.

To summarize, at this moment I have :
- Specific part of code only compiled that defines a specific entrypoint.
- Enabled the `custom_test_frameworks` feature
- specified a custom `test_runner` (named `test_runner`)

## Custom panic\_handler and ARM semihosting Qemu emulation

I wants to return a specific code if a tests has failed, or it will be impossible for the tests runner to know if a tests failed or not.
This will be possible using Qemu's emulation of ARM semihosting :

```
Semihosting is a mechanism that enables code running on an Embedded System (also called the target) to communicate with and use the I/O of the host computer. This is done by halting the target program, in most cases using some sort of a breakpoint instruction at a certain point in the code, or a mode switch (supervisor mode for legacy ARM devices or Cortex A/R)
```
(source : https://wiki.segger.com/Semihosting)

When generating `ADP_Stopped_ApplicationExit`, qemu will exit with specified exit code.
`1` is used for an `EXIT_FAILURE`.
`0` is used for `EXIT_SUCCESS`.

```rust

const EXIT_SUCCESS: u32 = 0;
const EXIT_FAILURE: u32 = 1;

#[allow(non_upper_case_globals)]
const ADP_Stopped_ApplicationExit: u64 = 0x20026;

/// The parameter block layout that is expected by QEMU.
///
/// If QEMU finds `ADP_Stopped_ApplicationExit` in the first parameter, it uses the second parameter
/// as exit code.
///
/// If first parameter != `ADP_Stopped_ApplicationExit`, exit code `1` is used.
#[repr(C)]
struct QEMUParameterBlock {
    arg0: u64,
    arg1: u64,
}

fn exit(code: u32) -> ! {
    let block = QEMUParameterBlock {
        arg0: ADP_Stopped_ApplicationExit,
        arg1: code as u64,
    };

    unsafe {
        asm!(
            "hlt #0xF000",
            in("x0") 0x18,
            in("x1") &block as *const _ as u64,
            options(nostack)
        );
    };

    loop {
        unsafe {
            asm!("wfe");
        }
    }
}

pub fn exit_success() -> ! {
    exit(EXIT_SUCCESS)
}

```

This function is called in a custom `panic_handler` that will call `qemu::exit_failure()` if it's a test build. This panic handler will be called if, by example, an assertion fails.

```rust
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
        #[cfg(test)]
    {
        qemu::exit_failure()
    }
    loop {
        println!("panic");
    }
}
```

## Tests definition - Structure, proc macro, test runner

I created a struct that will contains my tests :
```rust
#![no_std]

/// Unit test container.
pub struct UnitTest {
    /// Name of the test.
    pub name: &'static str,

    /// Function pointer to the test.
    pub test_func: fn(),
}

```

This struct is located in another crates in the workspace named `test_types`

This struct is "filled" using a `proc_macro` located in another crate named `test_macro` :
```rust
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Ident, ItemFn};

#[proc_macro_attribute]
pub fn kernel_test(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let f = parse_macro_input!(input as ItemFn);

    let test_name = &format!("{}", f.sig.ident);
    let test_ident = Ident::new(
        &format!("{}_TEST_CONTAINER", f.sig.ident.to_string().to_uppercase()),
        Span::call_site(),
    );
    let test_code_block = f.block;

    quote!(
        #[test_case]
        const #test_ident: test_types::UnitTest = test_types::UnitTest {
            name: #test_name,
            test_func: || #test_code_block,
        };
    )
    .into()
}
```

The `proc_macro` simplify the way for defining the tests making it possible to use `kernel_test` macro :
```rust
    #[kernel_test]
    fn test_kernel_1() {
        assert!(1 == 1);
    }
```

The test are run using the custom `test_runner` defined and called from the tests entrypoint.

```rust
pub fn test_runner(tests: &[&test_types::UnitTest]) {
    println!("Running {} tests", tests.len());

    for (i, test) in tests.iter().enumerate() {
        print!("{:>3}. {:.<58}", i + 1, test.name);
        (test.test_func)();
        println!("[ok]")
    }
}
```

## Cargo test runner

The last thing I had to do is to specify which runner will be executed when executing `cargo test`. This is done in the `.cargo/config.toml` file :
```toml
[target.'cfg(target_os = "none")']
runner = "bash ./test_runner.sh"
```

The script is fairly trivial. It's first transforming the `ELF` generated by the compiler into a raw data binary, then it starts qemu emulation.
```bash
#!/bin/bash

~/tools/builroot/buildroot-2022.02.1/output/host/aarch64-buildroot-linux-uclibc/bin/objcopy -O binary $1 $1.img

~/tools/qemu-7.2.0/build/qemu-system-aarch64 \
    -machine raspi3b \
    -m 1024M   \
    -cpu cortex-a53 \
    -semihosting \
    -kernel $1.img \
    -serial stdio
```
Just note that I use `$1` (the first argument passed to the script) to retrieve the compiled file name. `cargo test` will passe the filename to run as the first argument.

Now I can run my tests using : 
- `cargo test -p kernel --lib --release --features qemu`

```
Running 2 tests
  1. test_get_current_el.......................................[ok]
  2. test_kernel_1.............................................[ok]
```
