#! /bin/bash
# get a refresh from git and execute make.

git pull origin master

make  nxphlite-v3_default

cp -f build/nuttx_nxphlite-v3_default/nxphlite-v3.bin ../NxphliteBinFiles

echo "BIN file available in /Firmware/build/nxphlite-v3_default/platforms/nuttx and copied to  ../NxphliteBinFiles"
