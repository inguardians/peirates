# Filesystem commands

## Menu entry

- **Menu item:** Unnumbered grouped row
- **Canonical commands:** `cd`, `pwd`, `ls`, `cat`, `json-cat`, `create-file`
- **Maturity:** Supported with intentionally limited syntax

## Purpose

Inspect, navigate, and create text files in the filesystem visible to the Peirates process without requiring external coreutils programs.

## Prerequisites and authorization

The process needs operating-system permission to access each path. In a container, the visible filesystem and any mounted host paths determine what can be read or written. `create-file` needs an existing, writable parent directory and a destination that does not already exist.

## Usage

```text
pwd
ls
ls /var/run/secrets
cd /tmp
cat /path/to/file
json-cat /path/to/file.json
json-cat first.json second.json
create-file /tmp/notes.txt
create-file "/tmp/notes with spaces.txt"
create-file
```

Each form also works as one-shot input, for example `peirates -m 'ls /tmp'`.

`create-file` prompts for a path if omitted, then prompts for pasted contents. At the path prompt, enter the path directly without surrounding quotes. Finish the contents with `EOF` on a line by itself, followed by Enter. For example, inside Peirates:

```text
create-file /tmp/notes.txt
Paste file contents. Finish with EOF on a line by itself (or end of input):
First line
  Indented second line
EOF
[+] Created file: /tmp/notes.txt
```

It also accepts standard input in one-shot mode:

```sh
printf 'First line\nSecond line\n' | peirates -c -m 'create-file /tmp/notes.txt'
```

## What it does

`pwd` prints the process working directory. `cd` changes that directory for the current process. `ls` prints entry names for the current directory or each supplied directory. `cat` prints each supplied file in order.

`json-cat` works like `cat`, but validates each file as JSON and pretty-prints it with two-space indentation. It preserves key order and numeric values. Each file must contain one JSON value; invalid JSON produces an error and processing continues with the next file.

`create-file` first creates a zero-byte file with owner-only read/write permissions (`0600`, subject to the process umask). Only after creation succeeds does it prompt for contents. It keeps that same file open while writing. Existing files, directories, and symlinks are rejected without modification. Missing parent directories are not created.

Blank lines, indentation, and trailing whitespace are preserved. `EOF` is a reserved terminator and is not written to the file; an actual end of input also finishes the file and preserves any final line without a newline. Entering `EOF` immediately creates an empty file. Pasted contents are not added to Peirates' command history.

## Expected output

Paths, directory entry names, or file contents are printed directly to the terminal.

For a file containing `{"name":"example","enabled":true}`, `json-cat` prints:

```json
{
  "name": "example",
  "enabled": true
}
```

## Side effects and cleanup

`cd` changes Peirates' working directory for the rest of the session. `create-file` creates and writes the selected local file; remove it when no longer needed. If input or writing fails, the empty or partially written file remains for inspection. The other commands are read-only. File contents may include credentials or other sensitive data and are not automatically redacted.

## Failure modes

For `create-file`, quote paths containing spaces when supplying them alongside the command. It accepts exactly one path and performs no shell expansion. The other filesystem commands split arguments on whitespace, so paths containing spaces are not handled reliably. `ls` rejects flags, does not provide metadata, and does not sort or format like system `ls`. Permission and missing-path errors are printed.

If the zero-byte creation fails, `create-file` reports the error before asking for contents. A successful empty-file creation does not guarantee later writes will succeed (for example, if the disk fills up); write and close errors are reported. One-shot `create-file` still reads contents from standard input, so supply input for unattended use.

## Implementation and tests

See the dispatcher in [`peirates.go`](../../internal/app/peirates.go), paste prompts in [`create_file.go`](../../internal/app/create_file.go), and helpers in [`filesystem.go`](../../internal/modules/filesystem/filesystem.go). Coverage is in [`filesystem_test.go`](../../internal/modules/filesystem/filesystem_test.go), [`create_file_test.go`](../../internal/modules/filesystem/create_file_test.go), [paste command tests](../../internal/app/create_file_test.go), [`filesystem_manipulation_test.go`](../../internal/app/filesystem_manipulation_test.go), and [`module_commands_test.go`](../../internal/app/module_commands_test.go).
