English | [简体中文](README.md)

# IDA NO MCP

**Say goodbye to the complex, verbose, and laggy interaction mode of IDA MCP.**  

**AI Reverse Engineering, Zero Extra Configuration.**  

Simple · Fast · Intelligent · Low Cost

## Core Philosophy

Text, Source Code, and Shell are LLM's native languages.

AI is evolving rapidly with no fixed patterns—tools should stay simple. Export IDA decompilation results as source files, drop them into any AI IDE (Cursor / Claude Code / ...), and naturally benefit from indexing, parallelism, chunking (for huge decompiled functions), and other optimizations.

## Usage

### Plugin Mode

Copy `INP.py` to the IDA plugins directory:

- **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
- **Linux/macOS**: `~/.idapro/plugins/`

After restarting IDA:

- **Hotkey**: `Ctrl-Shift-E` for quick export
- **Menu**: `Edit` -> `Plugins` -> `Export for AI`

## Compatibility

- **IDA 7.x / 8.x**: Full support (type exports are gracefully skipped if `ida_typeinf` is unavailable)
- **IDA 9.0+**: Full support

## Exported Content

| File/Directory          | Content                    | Description                                                                                 |
| ----------------------- | -------------------------- | ------------------------------------------------------------------------------------------- |
| `decompile/`            | Decompiled C code          | Each function as a `.c` file, includes function name, address, callers, callees            |
| `decompile_failed.txt`  | Failed decompilation list  | Records functions that failed to decompile with reasons                                     |
| `decompile_skipped.txt` | Skipped functions list     | Records skipped library functions and invalid functions                                     |
| `function_index.txt`    | Function index             | Summary of all exported functions with addresses, names, and call relationships             |
| `segments.txt`          | Segment table              | All segments: name, address range, size, RWX permissions, type                             |
| `type_definitions.txt`  | Type definitions           | All structs, unions, and enums with member details                                          |
| `data_definitions.txt`  | Data item definitions      | All typed data items in data segments: address, size, type, name, value                    |
| `pointer_graph.txt`     | Pointer graph              | All pointers in data segments: source, target, target type (function/code/data)            |
| `strings.txt`           | String table               | Includes address, length, type (ASCII/UTF-16/UTF-32), content                               |
| `imports.txt`           | Import table               | Format: `address:function_name`                                                             |
| `exports.txt`           | Export table               | Format: `address:function_name`                                                             |
| `memory/`               | Memory hexdump             | 1MB chunks, hexdump format with address, hex bytes, ASCII                                   |

## Features

### Decompiled Function Export

Each function is exported as a separate `.c` file with metadata header:

```c
/*
 * func-name: sub_401000
 * func-address: 0x401000
 * callers: 0x402000, 0x403000
 * callees: 0x404000, 0x405000
 */

// Decompiled code...
```

**Smart Handling**:

- Automatically skips library functions and invalid functions
- Handles special characters and duplicate function names (adds address suffix)
- Generates detailed failure and skip logs
- Shows export progress (every 100 functions)
- Supports crash recovery (restart IDA and export resumes where it left off)

### Segment Export

Exports all segment details to `segments.txt`:

- Segment name, start/end address, size
- Read/Write/Execute permissions (RWX)
- Segment type

### Type Definition Export

Exports all recognized types to `type_definitions.txt`:

- **Structs** (S) and **Unions** (U): each member's name, type, offset, and size
- **Enums** (E): all enum members and their values

### Data Definition Export

Exports all typed data items from data segments to `data_definitions.txt`:

- Supports byte/word/dword/qword/float/double/string/struct and more
- Records address, size, type identifier, name, and value

### Pointer Graph

Extracts pointer relationships from data segments to `pointer_graph.txt`, helping AI understand cross-references between data structures:

- Source address → target address
- Target type: `F`=function, `C`=code, `D`=data
- Pointer width: p16/p32/p64

### Call Relationship Analysis

- **Callers**: Which functions call the current function
- **Callees**: Which functions are called by the current function
- Helps AI understand function dependencies and call chains

### Memory Export

- Exports all memory data organized by segment
- Maximum 1MB per file, automatically chunked
- Hexdump format with address, hex bytes, and ASCII display
- Filename format: `start_address--end_address.txt`

### Statistics

Displays detailed statistics after export:

- Total functions, exported, skipped, failed counts
- Segment count, type definition count, data item count, pointer count
- Memory export size and file count

## Tips

You can add more context in the IDB directory to give AI a complete picture:

| Directory | Content                                              |
| --------- | ---------------------------------------------------- |
| `apk/`    | APK decompilation directory (APKLab one-click export) |
| `docs/`   | Reverse engineering reports, notes                  |
| `codes/`  | exp, Frida scripts, decryptor, etc.                 |

State-of-the-art AI models can leverage all this information and scripts to provide you with the most powerful reverse engineering assistance.
