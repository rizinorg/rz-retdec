# RetDec Rizin plugin

RetDec plugin for [Rizin](https://github.com/rizinorg/rizin).

The plugin integrates RetDec decompiler into Rizin console. rz-retdec is shipped with a bundled RetDec version, but you can use your own version (specified below).

With the bundled version of RetDec you can decompile the following architectures:
* 32-bit: Intel x86, ARM, MIPS, PIC32, and PowerPC.
* 64-bit: x86-64, ARM64 (AArch64).

### Use in Rizin Console

In rizin console you can type `pdz?` to print help:

```bash
Usage: pdz   # Native RetDec decompiler plugin.
| pdz      # Show decompilation result of current function.
| pdz*     # Show current decompiled function side by side with offsets.
| pdza[?]  # Run RetDec analysis.
| pdze     # Show environment variables.
| pdzj     # Dump current decompiled function as JSON.
| pdzo     # Show current decompiled function side by side with offsets.
```

The following environment variables may be used to dynamically customize the plugin's behavior:

```bash
$ export DEC_SAVE_DIR=<path> # custom path for output of decompilation to be saved to.
```

## Build and Installation

This section describes a local build and installation of rz-retdec.

### Requirements

* A compiler supporting c++17
* CMake (version >= 3.6)
* Existing Rizin installation

To build the bundled version of RetDec see [RetDec requirements section](https://github.com/avast/retdec#requirements).

### Process

* Clone the repository:
  * `git clone https://github.com/rizinorg/rz-retdec`
  * `cd rz-retdec`
  * `mkdir build && cd build`
  * `cmake .. -DCMAKE_INSTALL_PREFIX=~/.local`
  * `make`
  * `make install`

You have to pass the following parameters to `cmake`:
* `-DCMAKE_INSTALL_PREFIX=<path>` to set the installation path to `<path>`. It is important to set the `<path>` to a location where Rizin can load plugins from (for example `~/.local`).

You can pass the following additional parameters to `cmake`:
* `-DBUILD_BUNDLED_RETDEC=ON` to build bundled RetDec version with the plugin. The build of the bundled RetDec is by default turned on. RetDec will be installed to `CMAKE_INSTALL_PREFIX`. When turned OFF system is searched for RetDec installation.
* `-DRZ_RETDEC_DOC=OFF` optional parameter to build Doxygen documentation.
* `-DBUILD_CUTTER_PLUGIN=OFF` setting to ON will build the Cutter plugin. Cutter must be built with support for plugin loading, see [Cutter documentation](https://cutter.re/docs/plugins.html).

*Note*: rz-retdec requires [filesystem](https://en.cppreference.com/w/cpp/filesystem) library to be linked with the plugin. CMake will try to find the library in the system but on GCC 7 it might not be able to do so automatically. In that case you must specify a path where this library is located in the system to the cmake by adding:
* `-DCMAKE_LIBRARY_PATH=${PATH_TO_FILESTSTEM_DIR}`

On GCC 7 is `stdc++fs` located in:
* `-DCMAKE_LIBRARY_PATH=/usr/lib/gcc/x86_64-linux-gnu/7/`

## License

rz-retdec Copyright (c) 2022 RizinOrg

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

rz-retdec uses third-party libraries or other resources that may be
distributed under licenses different than this software.

In the event that we accidentally failed to list a required notice,
please bring it to our attention by contacting the repository owner.

RetDec r2plugin uses the following third-party libraries or other resources:
1) RetDec: https://github.com/avast/retdec Copyright (c) 2017 Avast Software, [MIT license](LICENSES/MIT.txt)
2) retdec-r2plugin: https://github.com/avast/retdec-r2plugin Copyright (c) 2020 Avast Software, [MIT license](LICENSES/MIT.txt)
