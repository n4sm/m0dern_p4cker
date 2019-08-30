# Awesome_packer
Just a modern packer for elf binaries ( linux executables )

# Installation

Just make a simple

```
gcc packer.c -o packer && gcc test_re.c -o test
```

Next it you can pack your elf file with differents options

```
./packer test xor
```

It applicates a simple xor encryption on the .text with a random key


// ===============================================================================================

It applicates a simple not and next xor encryption on the .text with a random key

```
./packer test not
```

The file will be packed as it : 

```C
  base_addr[i] = ~base_addr[i] ^ random_int;
```

// ===============================================================================================

```
./packer test xorp
```

Another encryption of the .text

The target file will be packed as it : 

```C
    base_addr[i] = ~base_addr[i] ^ random_int;
		base_addr[i] ^= x;
		x = ~x;
```

Where base_addr[i] represents the bytes of the .text, random_int is a random int, and x another random number between 5 and 42
