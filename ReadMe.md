# LDR - NativeCodeLoader

It is designed for map and run code under **debugger** or in another **controlled environment**. It can run raw shellcode or PE32 files (TODO PE32+).

CLI:
```
LDR (C) immortalp0ny 2017-2018
OPTIONS:
      -h, --help                        Display this help menu
      Arguments
        Path                              Path to target file
      Commands
        raw                               Load as raw code
        dll                               Load as dll
      Flags
        -r[Rva], --rva=[Rva]              Start rva
        -o[RawOffset],
        --offset=[RawOffset]              Start raw offset
        -e[ExportOrdinal],
        --ordinal=[ExportOrdinal]         Start export ordinal
        -f[FdwReason],
        --fdwReason=[FdwReason]           Value of fdwReason for DllMain
        -n[ExportName],
        --exname=[ExportName]             Start export name
        -l[Libs...], --lib=[Libs...]      List of libs for loading in process
        -m, --main                        Execute main before jump to start
        --ig-imp-err                      If this flags set loader will ignore
                                          error in imports resolving
        -w, --infwait                     Set this flag for infinity waiting
                                          after last call
      Tricks
        --location=[Change location]      Change image location
      Plugins
        --plugin=[Plugin]                 Set plugin path for use
        --plugin-cl=[PluginCommandLine]   Set plugin command line
      "--" can be used to terminate flag options and force all following
      arguments to be treated as positional options

    Load code to monitoring/debuging/analyzing
```
