# IDARustHelper

**Just a simple combination of some existing projects :)**

It can help you:

- **Demangle the Rust function name**
- **Add some Rust type**(like str, you can join more types by youself!)
- **Identify Rust strlit and rename str struct**

## Install

First, Install rust_demangler: `pip install rust_demangler`

And then, just copy the file `IDARustHelperPlugin.py` and the folder `IDARustHelper` to `${IDA_DIR}/plugins`.

## Usage

`Edit` -> `Plugins` -> `IDA Rust Helper`, and then wait a few seconds.

## Support

**Just tested on IDA Pro 7.7, python3.8 and 64bit ELF.** But it should work on Windows PE, Mach-O. 

Also should work with IDA Pro 8.x. 

Arm, RISC-V should be work well also, both 32bit and 64bit.

## Known Issue
- `callregs_t.set` need a `int const *` parm, but I really don't know how to pass it...

## How it work?

**Before I start, I would like to sincerely thank [teambi0s](https://github.com/teambi0s/rust_demangler), [timetravelthree](https://github.com/timetravelthree/IDARustDemangler), [hex-rays](https://hex-rays.com/blog/rust-analysis-plugin-tech-preview/) for their work!**

### Demangle

For the part of demangling, I combine the work of [teambi0s](https://github.com/teambi0s/rust_demangler) and [timetravelthree](https://github.com/timetravelthree/IDARustDemangler). Teambi0s's work can demangle most symbols, and timetravelthree's work was able to re-mangle the symbols to make them more friendly to display in IDA.

Re-mangle can't quite get the symbols to display perfectly in IDA, because IDA has a character limit for symbols, but I think it's enough. If you want full display, you can modify the character whitelist in `ida.cfg`(like `NameChars` variant) to bypass the restriction.

### Add Rust type

Just definde them in C declation and parse them! You can see `RustType.py` to get implementation details.

### Identify Rust strlit

For this part, I just simply ported the [hex-rays plugin](https://hex-rays.com/blog/rust-analysis-plugin-tech-preview/) to idapython. It follows the following basic idea:

1. Scan the entire read-only data segment to find long strings and initially split them based on xrefs.
2. Depending on the location of the xrefs, they are categorised into data references and code references, and different methods are used to detect their legitimacy.
3. For data references, some string literals are referenced in a form similar to golang's str structure, and we can find them in places like .data.rel.ro segments. Sometimes a literal is referenced by many str structures, and the length of the string literal is finally determined by traversing them and comparing them to the length of the initial division.
4. For code references, some string literals and their lengths are reflected directly in the assignment of instructions, the actual form of which will vary depending on the machine. The final length of the string is found by pattern matching.
5. Finally, all found str structures will be typed and renamed to make it easier to analyse in the code.



