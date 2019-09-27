# Awesome_packer
Just a modern packer for Elf binaries ( linux executables )

# Installation

Just make a simple

```
chmod +x make.sh && ./make.sh
```

# Use

There is a small script shell which regererates the test executale : regen.sh

You have just to do :

```shell
./regen.sh
```

Thus test is recompiled.

# Options

```shell
Help : 
                ./main <target_file> xor : target_file is encrypted (only xor encryption) with a random key 
                ./main <target_file> not : target_file is encrypted (xor and not encryption) with a random key 
                ./main <target_file> xorp : target_file is encrypted (complex encryption) with a random key
```

@XOR

Encryption : 

```C
base_addr[i] ^= random_int;
```

where base_addr[i] represents each bytes of the executable, and random_int a random int ^^

@NOT

```C
base_addr[i] = ~base_addr[i] ^ random_int;
```

where base_addr[i] represents each bytes of the executable, and random_int a random int ^^

@XORP

```C
base_addr[i] = ~base_addr[i] ^ random_int;
base_addr[i] ^= x;
x = ~x;
```

where base_addr[i] represents each bytes of the executable, and random_int a random int ^^
