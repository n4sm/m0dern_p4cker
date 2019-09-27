// ========================== Functions from my packer and my disassembler ============================
// ==============================https://github.com/n4sm/m0dern_p4cker=================================
// ====================================================================================================

size_t len_section(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], const char *section);

off_t search_section_name(char *sh_name_buffer[], Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], const char *section, size_t *len_sec);

int patch_target(void *p_entry, long pattern, int size, long patch);

int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]);

int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]);

uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *ptr);

char  *parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char *sh_name_buffer[]);

int x_pack_text(unsigned char *base_addr, size_t len_text, int random_int);

int r_pack_text(unsigned char *base_addr, size_t len_text, int random_int);

int c_pack_text(unsigned char *base_addr, size_t len_text, int random_int, int x);

off_t search_section(const char *section, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *ptr, int *i_sec);

int xor_encrypt(char *target_file);

int has_pie_or_not(Elf64_Phdr *buffer_mdata_ph[], Elf64_Ehdr *ptr);

int xor_encrypt_pie(char *file_ptr);

int not_encrypt(char *target_file);

int not_encrypt_pie(char *target_file);

int complexe_encrypt(char *target_file);

int rol(int in, int x);

int ror(int in, int x);

int complexe_encrypt_pie(char *target_file);

// ====================================================================================================
// ====================================================================================================
// ====================================================================================================