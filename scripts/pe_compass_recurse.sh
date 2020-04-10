#! /bin/bash

mkdir -p pe-compass-datasets/targets
pe-compass recurse -d /mnt/c -x .acm > pe-compass-datasets/targets/acm.txt
pe-compass recurse -d /mnt/c -x .ax  > pe-compass-datasets/targets/ax.txt
pe-compass recurse -d /mnt/c -x .com > pe-compass-datasets/targets/com.txt
pe-compass recurse -d /mnt/c -x .cpl > pe-compass-datasets/targets/cpl.txt
pe-compass recurse -d /mnt/c -x .dll > pe-compass-datasets/targets/dll.txt
pe-compass recurse -d /mnt/c -x .drv > pe-compass-datasets/targets/drv.txt
pe-compass recurse -d /mnt/c -x .efi > pe-compass-datasets/targets/efi.txt
pe-compass recurse -d /mnt/c -x .exe > pe-compass-datasets/targets/exe.txt
pe-compass recurse -d /mnt/c -x .mui > pe-compass-datasets/targets/mui.txt
pe-compass recurse -d /mnt/c -x .ocx > pe-compass-datasets/targets/ocx.txt
pe-compass recurse -d /mnt/c -x .scr > pe-compass-datasets/targets/scr.txt
pe-compass recurse -d /mnt/c -x .sys > pe-compass-datasets/targets/sys.txt
pe-compass recurse -d /mnt/c -x .tsp > pe-compass-datasets/targets/tsp.txt