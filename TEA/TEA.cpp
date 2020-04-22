#include "TEA.hpp"
#include <fstream>

void TEA::encrypt(uint8_t inp_block[8], uint8_t key_block[16])
{
	uint32_t l_inp = 0, r_inp = 0;
	// split text block into two parts
	for (int i = 0; i < 4; i++)
	{ 
		l_inp |= inp_block[i];
		l_inp <<= (i==3? 0:8);
	}
	for (int i = 4; i < 8; i++)
	{
		r_inp |= inp_block[i];
		r_inp <<= (i==7? 0:8);
	}

	uint32_t k0 = ((uint32_t*)key_block)[0];
	uint32_t k1 = ((uint32_t*)key_block)[1];
	uint32_t k2 = ((uint32_t*)key_block)[2];
	uint32_t k3 = ((uint32_t*)key_block)[3];

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
	for (int i = 0; i < 4; i++)
	{ 
		l_inp |= inp_block[i];
		l_inp <<= (i==3?0:8);
	}
	for (int i = 4; i < 8; i++)
	{
		r_inp |= inp_block[i];
		r_inp <<= (i==7?0:8);
	}

	uint32_t k0 = ((uint32_t*)key_block)[0];
	uint32_t k1 = ((uint32_t*)key_block)[1];
	uint32_t k2 = ((uint32_t*)key_block)[2];
	uint32_t k3 = ((uint32_t*)key_block)[3];

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
	
	uint8_t buf[curr_size];
	for (int i = 0; i < file_size; i++) buf[i] = 0;
	
	std::ifstream in_file;
	in_file.open(fs::path(file), std::ios::in | std::ios::binary);
	
	bool eof = false;
	int current_position = 0;
	while (!eof)
	{
		uint8_t byte_block[8] = {1,1,1,1,1,1,1,1};
		for (int i = 0; i < 8; i++)
		{
			byte_block[i] = (uint8_t)in_file.get();
			if (in_file.eof())
			{
				byte_block[i] = 1; // delete EOF char
				eof = true;
				break;
			}
		}
		encrypt(byte_block, key_block);
		for (int i = 0; i < 8; i++)
		{
			buf[current_position++] = byte_block[i];
		}
	}
	in_file.close();

	std::ofstream out_file;
	out_file.open(fs::path(file), std::ios::out | std::ios::binary);
	out_file.write((char*)buf,curr_size);

	out_file.close();
}

void TEA::decrypt_file(std::string file, uint8_t key_block[16])
{
	// file - file name; key - data block
	namespace fs = std::experimental::filesystem;
	
	int file_size = fs::file_size(fs::path(file));
	uint8_t buf[file_size];
	for (int i = 0; i < file_size; i++) buf[i] = 0;
	
	std::ifstream in_file;
	in_file.open(fs::path(file), std::ios::in | std::ios::binary);
	
	bool eof = false;
	int current_position = 0;
	while (!eof)
	{
		uint8_t byte_block[8] = {1,1,1,1,1,1,1,1};
		for (int i = 0; i < 8; i++)
		{
			byte_block[i] = (uint8_t)in_file.get();
			if (in_file.eof())
			{
				eof = true;
				break;
			}
		}
		decrypt(byte_block, key_block);
		for (int i = 0; i < 8; i++)
		{
			if (eof)
			{	
				while (buf[current_position-1] == 1) current_position--; // delete ones
				break;
			}
			buf[current_position++] = byte_block[i];
		}
	}
	in_file.close();

	std::ofstream out_file;
	out_file.open(fs::path(file), std::ios::out | std::ios::binary);
	out_file.write((char*)buf,current_position);
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
		encrypt_file(std::string(current_path.path()), key_block);
	}
}

void TEA::recursive_file_decrypt(std::string path, uint8_t key_block[16])
{
	namespace fs = std::experimental::filesystem;
	for (auto current_path : fs::recursive_directory_iterator(fs::path(path)))
	{
		decrypt_file(std::string(current_path.path()), key_block);
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