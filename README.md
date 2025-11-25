# demo_dyndxt

Demonstration of the [nxdk_dyndxt](https://github.com/abaire/nxdk_dyndxt) dynamic
loader.

The DLL produced by this project installs a 'demo' XBDM command processor that
responds to various commands.

Intended for use with [xbdm_gdb_bridge](https://github.com/abaire/xbdm_gdb_bridge)'s
`@load` command.

```
xbdm_gdb_bridge 127.0.0.1:1731

# Attach the debugger
> /attach

# Load the library
> @load libdemo_dyndxt.dll

# List commands
> @m demo!hello

```

# git hooks

This project uses [git hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
to automate some aspects of keeping the code base healthy.

Please copy the files from the `githooks` subdirectory into `.git/hooks` to
enable them.

# Building

## `CLion`

The CMake target can be configured to use the toolchain from the nxdk:

* CMake options

    `-DCMAKE_TOOLCHAIN_FILE=<absolute_path_to_nxdk>/share/toolchain-nxdk.cmake`

* Environment

    `NXDK_DIR=<absolute_path_to_nxdk>`
