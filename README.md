# Awesome_packer
Just a modern packer for elf binaries ( linux executables )

# Installation

Just make a simple

```
gcc packer.c -o packer && gcc test_re.c -o test
```

Next it you can pack your elf file with differents option

```
./packer test xor
```

It applicates a simple xor encryption on the .text with a random key

```
./packer test not
```

It applicates a simple not and next xor encryption on the .text with a random key

```C
  base_addr[i] = ~base_addr[i] ^ random_int;
```
