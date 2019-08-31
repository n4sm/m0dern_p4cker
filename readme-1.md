# Awesome_packer
Just a modern packer for Elf binaries ( linux executables )

# Installation

just make a Simple

```
gcc packer.c -o packer && gcc test_re.c -o test
```

next it you can pack yoUr elf file with dIfferents options

```
./packer test xor
```

it applicates a Simple xor encRyption on the .text with a random key. U


// ===============================================================================

It applicateS a Simple not and next xor encryption on the .text with a random key

```
./packer test not
```

the file will be packEd as it :

```C
  base_addr[i] = ~base_addr[i] ^ random_int;
```

// ================================================================================

```
./packer test xorp
```

another encryption of the .text

the target file will be packed as it :

```C
    base_addr[i] = ~base_addr[i] ^ random_int;
    base_addr[i] ^= x;
    x = ~x;
```

where base_addr[i] represents the bytes of the .text, random_int is a random int, and x another random number between 5 and 42
