#include "TEA.hpp"

void TEA::encrypt(uint8_t inp_block[8], uint8_t key_block[16])
{
	uint32_t l_inp = 0, r_inp = 0;
	// split text block into two parts
	for (int i = 0; i < 4; i++) { l_inp |= inp_block[i]; l_inp <<= (i==3? 0:8);	}
	for (int i = 4; i < 8; i++)	{ r_inp |= inp_block[i]; r_inp <<= (i==7? 0:8);	}

	uint8_t k0 = 0, k1 = 0, k2 = 0, k3 = 0;
	for (int i = 0; i < 4; i++) { k0 |= key_block[i]; k0 <<= (i==3? 0:8); }
	for (int i = 4; i < 8; i++) { k1 |= key_block[i]; k1 <<= (i==7? 0:8); }
	for (int i = 8; i < 12; i++) { k2 |= key_block[i]; k2 <<= (i==11? 0:8); }
	for (int i = 12; i < 16; i++) { k3 |= key_block[i]; k3 <<= (i==15? 0:8); }

	for (int i = 1; i <= 32; i++)
	{		
		uint32_t old_r = r_inp;
		r_inp = l_inp+ ((r_inp<<4+k0)^(r_inp+2654435769*i)^(r_inp>>5+k1));
		l_inp = old_r;

		old_r = r_inp;
		r_inp = l_inp+ ((r_inp<<4+k2)^(r_inp+2654435769*i)^(r_inp>>5+k3));
		l_inp = old_r;
		
	}
	// save left and right parts in input block
	for (int i = 0; i < 4; i++) inp_block[i] = (uint8_t)(l_inp>>((3-i)*8));
	for (int i = 4; i < 8; i++) inp_block[i] = (uint8_t)(r_inp>>((3-i)*8));
}

void TEA::decrypt(uint8_t inp_block[8], uint8_t key_block[16])
{
	uint32_t l_inp = 0, r_inp = 0;
	for (int i = 0; i < 4; i++)	{ l_inp |= inp_block[i]; l_inp <<= (i==3?0:8); }
	for (int i = 4; i < 8; i++)	{ r_inp |= inp_block[i]; r_inp <<= (i==7?0:8); }

	uint8_t k0 = 0, k1 = 0, k2 = 0, k3 = 0;
	for (int i = 0; i < 4; i++) { k0 |= key_block[i]; k0 <<= (i==3? 0:8); }
	for (int i = 4; i < 8; i++) { k1 |= key_block[i]; k1 <<= (i==7? 0:8); }
	for (int i = 8; i < 12; i++) { k2 |= key_block[i]; k2 <<= (i==11? 0:8); }
	for (int i = 12; i < 16; i++) { k3 |= key_block[i]; k3 <<= (i==15? 0:8); }

	for (int i = 32; i >= 1; i--)
	{
		uint32_t old_l = l_inp;
		l_inp = r_inp- ((l_inp<<4+k2)^(l_inp+2654435769*i)^(l_inp>>5+k3));
		r_inp = old_l;

		old_l = l_inp;
		l_inp = r_inp- ((l_inp<<4+k0)^(l_inp+2654435769*i)^(l_inp>>5+k1));
		r_inp = old_l;
	}
	for (int i = 0; i < 4; i++) inp_block[i] = (uint8_t)(l_inp>>((3-i)*8));
	for (int i = 4; i < 8; i++) inp_block[i] = (uint8_t)(r_inp>>((3-i)*8));
}

void TEA::encrypt_file(std::string file, uint8_t key_block[16])
{
	// file - file name; key - data block
	namespace fs = std::experimental::filesystem;
	
	int file_size = fs::file_size(fs::path(file));
	int curr_size = file_size - (file_size%8) + ((file_size%8==0)?0:8); // this for size%8==0

	// file size + initialization vector size
	uint8_t buf[curr_size+8];
	for (int i = 0; i < file_size; i++) buf[i] = 1;
	
	uint8_t init_vector[8];
	for (int i = 0; i < 8; i++) init_vector[i] = (uint8_t)rand();

	// save initialization vector in buffer
	for (int i = 0; i < 8; i++)
	{
		buf[i] = init_vector[i];
	}
	
	std::ifstream in_file;
	in_file.open(fs::path(file), std::ios::in | std::ios::binary);
	in_file.read((char*)(buf+8), file_size); // "+8" to skip an init vector
	// remove trash from the end after reading the file
	for (int i = curr_size; i >= file_size; i--) (buf+8)[i] = 1;

	for (int n = 0; n < curr_size; n += 8)
	{
		for (int i = 0; i < 8; i++)
		{
			(buf+8+n)[i] ^= init_vector[i];
		}
		encrypt(buf+8+n, key_block);
		for (int i = 0; i < 8; i++)
		{
			init_vector[i] = (buf+8+n)[i];
		}
	}
	in_file.close();

	std::ofstream out_file;
	out_file.open(fs::path(file), std::ios::out | std::ios::binary);
	out_file.write((char*)buf,curr_size+8);

	out_file.close();
}

void TEA::decrypt_file(std::string file, uint8_t key_block[16])
{
	// file - file name; key - data block
	namespace fs = std::experimental::filesystem;
	
	int file_size = fs::file_size(fs::path(file));
	uint8_t buf[file_size-8];  // size - initialization vector size
	for (int i = 0; i < (file_size-8); i++) buf[i] = 1;
	
	uint8_t init_vector[8];
	uint8_t this_ciphertext[8];

	std::ifstream in_file;
	in_file.open(fs::path(file), std::ios::in | std::ios::binary);

	in_file.read((char*)init_vector, 8); // read init vector
	in_file.read((char*)buf, file_size-8); // read encrypted text

	for (int n = 0; n < file_size-8; n += 8)
	{
		for (int i = 0; i < 8; i++)
		{
			// the text will be encrypted, so you need to save it
			this_ciphertext[i] = (buf+n)[i];
		}
		decrypt(buf+n, key_block);
		for (int i = 0; i < 8; i++)
		{
			(buf+n)[i] ^= init_vector[i];
		}
		for (int i = 0; i < 8; i++)
		{
			init_vector[i] = this_ciphertext[i];
		}
	}
	in_file.close();
	while (buf[file_size-8-1]==1) file_size--;

	std::ofstream out_file;
	out_file.open(fs::path(file), std::ios::out | std::ios::binary);
	out_file.write((char*)buf,file_size-8);
	out_file.close();
}
void TEA::encrypt_file(std::string file, std::string key_file_name)
{
	// file - file name; key - file name
	std::ifstream key_file(key_file_name);
	uint8_t key[16];
	key_file.read((char*)key, 16);
	encrypt_file(file, key);
}

void TEA::decrypt_file(std::string file, std::string key_file_name)
{
	// file - file name; key - file name
	std::ifstream key_file(key_file_name);
	uint8_t key[16];
	key_file.read((char*)key, 16);
	decrypt_file(file, key);
}

void TEA::recursive_file_encrypt(std::string path, uint8_t key_block[16])
{
	namespace fs = std::experimental::filesystem;
	for (auto current_path : fs::recursive_directory_iterator(fs::path(path)))
	{
		if (!(fs::is_directory(current_path.path())))
		{
			encrypt_file(std::string(current_path.path()), key_block);
		}
	}
}

void TEA::recursive_file_decrypt(std::string path, uint8_t key_block[16])
{
	namespace fs = std::experimental::filesystem;
	for (auto current_path : fs::recursive_directory_iterator(fs::path(path)))
	{
		if (!(fs::is_directory(current_path.path())))
		{
			decrypt_file(std::string(current_path.path()), key_block);
		}
	}
}

void TEA::recursive_file_encrypt(std::string path, std::string key_file_name)
{
	std::ifstream key_file(key_file_name);
	uint8_t key[16];
	key_file.read((char*)key, 16);
	recursive_file_encrypt(path, key);
}

void TEA::recursive_file_decrypt(std::string path, std::string key_file_name)
{
	std::ifstream key_file(key_file_name);
	uint8_t key[16];
	key_file.read((char*)key, 16);
	recursive_file_decrypt(path, key);
}