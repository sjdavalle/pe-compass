#! /bin/bash

echo "Setting IFS Variable to \\n"
IFS=$'\n';

echo "[=]  Starts Inspection of DLLs"
for x in $(cat targets/dll.txt | tr -d "'"); do base=$(basename $x); pe-compass inspect -f "$x" -o ./csv_dumps/dll/$base.csv -c; done;
echo "[+]  Ends Inspection of DLLs"

echo "[=]  Starts Inspection of EXEs"
for x in $(cat targets/exe.txt | tr -d "'"); do base=$(basename $x); pe-compass inspect -f "$x" -o ./csv_dumps/exe/$base.csv -c; done;
echo "[+]  Ends Inspection of EXEs"

echo "[=]  Starts Inspection of SYS"
for x in $(cat targets/sys.txt | tr -d "'"); do base=$(basename $x); pe-compass inspect -f "$x" -o ./csv_dumps/sys/$base.csv -c; done;
echo "[+]  Ends Inspection of SYS"

echo "[=]  Starts Inspection of DRV"
for x in $(cat targets/drv.txt | tr -d "'"); do base=$(basename $x); pe-compass inspect -f "$x" -o ./csv_dumps/drv/$base.csv -c; done;
echo "[+]  Ends Inspection of DRV"