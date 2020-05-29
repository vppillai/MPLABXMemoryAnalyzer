# Introduction

A tool to generate modular memory usage summry of MPLABX based PIC32 projects.

Details are in my [blog](https://embeddedinn.xyz/articles/tutorial/analyzing-size-of-ELF-sections-and-symbols/).

# Usage

  - Make sure that compiler tools are added to system PATH (e.g. _C:\Program Files\Microchip\xc32\v2.40\bin_)
  - Make sure that you have python 3 installed in your system.
    - No special pyhton modules are required.
  - unzip/clone tool to anywhere in the system.
  - report will be geenrated in the build output folder (_project.x\dist\project\curiosity_)

```bash
usage: mapfileParse.py [-h] [-c <project config>] <project path to .X>

Tool to parse map file and provide component-wise memory usage of an embedded project

positional arguments:
  <project path to .X>

optional arguments:
  -h, --help            show this help message and exit
  -c <project config>, --config <project config>
                        specify a configuration name
```

# Results

Results will be generated in the build output folder (_project.x\dist\project\curiosity_). This includes :

|     |                           |                                                   |
| --- | ------------------------- | ------------------------------------------------- |
| 1   | <_project_>\_summary.csv  | Modular summary of memroy                         |
| 2   | <_project_>\_fileSize.csv | File wise memory usage                            |
| 3   | <_project_>\_syms.csv     | memory usage of symbols with associated files     |
| 4   | <_project_>\_clean.map    | map file with non-linked sections removed from it |

Summary will look like this:

![](docs/images/report.png)

[![Latest release](https://img.shields.io/github/release/vppillai/MPLABXMemoryAnalyzer.svg)](https://github.com/vppillai/MPLABXMemoryAnalyzer/releases/latest)
[![Latest release date](https://img.shields.io/github/release-date/vppillai/MPLABXMemoryAnalyzer.svg)](https://github.com/vppillai/MPLABXMemoryAnalyzer/releases/latest)
![GitHub commit activity](https://img.shields.io/github/commit-activity/y/vppillai/MPLABXMemoryAnalyzer)
[![Contributors](https://img.shields.io/github/contributors-anon/vppillai/MPLABXMemoryAnalyzer.svg)]()
