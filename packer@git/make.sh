gcc packer.c packer_functions.c -o main
gcc test_re.c -o test

chmod +x regen.sh

echo "[*] test and main has been generated"
