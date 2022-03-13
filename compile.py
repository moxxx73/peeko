#!/usr/bin/env python3

# Just a simple install script inplace of a makefile #
import os
import subprocess
import sys

PEEKO_VER = '1.45'

gcc_flags:list = [
    "-Wall", "-Wextra", "-Wpedantic", "-Wformat=2", "-Wno-unused-parameter", "-Wshadow",
    "-Wwrite-strings", "-Wstrict-prototypes", "-Wold-style-definition", "-Wredundant-decls",
    "-Wnested-externs", "-Wmissing-include-dirs"
]

src_path = './src/'
include_path = './include/'

fatal_error = False

def compile_src(compile_bpf:bool) -> None:
    src_files:list = os.listdir(src_path)
    compiled:list = []
    obj:str = ''
    cmd:list = []
    for fn in src_files:
        if(fn in ['osx_net.c', 'bpf.c'] and not compile_bpf):
            continue
        cmd = ['gcc', '-c', f"{src_path:s}{fn:s}"] + gcc_flags
        r = subprocess.run(cmd)
        if(r.returncode == 0):
            obj = fn.split('.')[0]
            compiled.append(obj+'.o')
        else:
            fatal_error = True
            return compiled
    return compiled

def link_and_install(obj_files:list) -> None:
    cmd = ['gcc', '-o', 'peeko'] + obj_files + gcc_flags
    r = subprocess.run(cmd)
    if(r != 0):
        fatal_error = True

def cleanup(obj_files:list) -> None:
    for fn in obj_files:
        try:
            os.remove(f'./{fn:s}')
        except FileNotFoundError:
            continue
    return

def usage(bin:str) -> None:
    print(f'Usage: [Options/Flags] {bin:s}\n')
    print('[### Options/Flags ####]')
    print('  -h: Outputs usage')
    print('  -d: Specify installation directory')
    print(f'      (Default: {install_path:s})')
    return None

def main(argc:int, argv:list) -> int:
    global install_path
    x:int = 1
    ch:str = ''
    opt:str = ''
    build_target:str = ''
    compile_bpf:bool = False
    obj_files:list = []

    if(sys.platform == 'darwin'):
        build_target = 'Mac OSX'
        compile_bpf = True
    elif(sys.platform == 'linux'):
        build_target = 'Linux'
    else:
        print('The OS you\'re currently running is not supported')
        exit(1)

    if(argc > 1):
        while(x < argc):
            ch = argv[x][0]
            if(ch == '-' and len(argv[x]) > 1):
                opt = argv[x][1]
                if(opt == 'h'):
                    usage(argv[0])
                    return 0
                elif(opt == 'd'):
                    if((x+1) < argc):
                        install_path = argv[x+1]
                        x += 1
            x += 1
    print(f'Compilling for {build_target:s}...')
    obj_files = compile_src(compile_bpf)
    if(fatal_error):
        print('Fatal error occurred while trying to compile source code\nExititng...')
        exit(1)

    print('Linking object files...')
    link_and_install(obj_files)
    if(fatal_error):
        print('Fatal error occurred while trying to link object files\nExiting...')
        exit(1)


    print('Cleaning up...')
    cleanup(obj_files)
    print("Done")
    return 0


if(__name__=='__main__'):
    try:
        exit(main(len(sys.argv), sys.argv))
    except KeyboardInterrupt:
        exit(130)
