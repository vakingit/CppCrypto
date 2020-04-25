#include "GOST.hpp"

void GOST::encrypt(uint8_t data_block[8], uint8_t key_256[32])
{
	uint32_t l = 0, r = 0, old_r = 0;
	uint32_t keys[8] = {0,0,0,0,0,0,0,0};
	int keys_using[32] = 
	{
		1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,
		1,2,3,4,5,6,7,8,8,7,6,5,4,3,2,1
	};

	for (int i = 0; i < 4; i++) { l |= data_block[i]; l <<= (i==3? 0:8); }
	for (int i = 4; i < 8; i++)	{ r |= data_block[i]; r <<= (i==7? 0:8); }

	gost_generate_keys(keys,key_256);

	for (int step = 0; step < 32; step++)
	{
		old_r = r;
		r = l ^ (gost_shift(gost_s_block(r+keys_using[step]))); // r+key->s_blocks->shift->xor with l
		l = old_r;
	}

	for (int i = 0; i < 4; i++) { data_block[i] = ((uint8_t)(l>>((3-i)*8)));}
	for (int i = 4; i < 8; i++) { data_block[i] = ((uint8_t)(r>>((3-i)*8)));}
}

void GOST::decrypt(uint8_t data_block[8], uint8_t key_256[32])
{
	uint32_t l = 0, r = 0, old_l = 0;
	uint32_t keys[8] = {0,0,0,0,0,0,0,0};
	int keys_using[32] = 
	{
		1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,
		1,2,3,4,5,6,7,8,8,7,6,5,4,3,2,1
	};

	for (int i = 0; i < 4; i++) { l |= data_block[i]; l <<= (i==3? 0:8); }
	for (int i = 4; i < 8; i++)	{ r |= data_block[i]; r <<= (i==7? 0:8); }

	gost_generate_keys(keys,key_256);

	for (int step = 31; step >= 0; step--)
	{
		old_l = l;
		l = r ^ (gost_shift(gost_s_block(l+keys_using[step])));
		r = old_l;
	}

	for (int i = 0; i < 4; i++) { data_block[i] = ((uint8_t)(l>>((3-i)*8)));}
	for (int i = 4; i < 8; i++) { data_block[i] = ((uint8_t)(r>>((3-i)*8)));}
}

void GOST::gost_generate_keys(uint32_t keys[8], uint8_t key_256[32])
{
	for (int n = 0; n < 8; n++)
	{
		for (int i = (n*4); i < ((n*4)+4); i++)
		{
			keys[n] |= key_256[i];
			keys[n] <<= ((i==((n*4)+3))?0:8);
		}
	}
}

uint32_t GOST::gost_s_block(uint32_t data)
{
	uint32_t ret_data = 0, mask = 15, index = 0;
	// s-blocks id-tc26-gost-28147-param-Z
	uint8_t s_blocks[8][16] =
	{
		{12, 4,  6,  2,  10, 5,  11, 9,  14, 8,  13, 7,  0,  3,  15, 1},
		{6,  8,  2,  3,  9,  10, 5,  12, 1,  14, 4,  7,  11, 13, 0,  15},
		{11, 3,  5,  8,  2,  15, 10, 13, 14, 1,  7,  4,  12, 9,  6,  0},
		{12, 8,  2,  1,  13, 4,  15, 6,  7,  0,  10, 5,  3,  14, 9,  11},
		{7,  15, 5,  10, 8,  1,  6,  13, 0,  9,  3,  14, 11, 4,  2,  12},
		{5,  13, 15, 6,  9,  2,  12, 10, 11, 7,  8,  1,  4,  3,  14, 0},
		{8,  14, 2,  5,  6,  9,  1,  12, 15, 4,  11, 0,  13, 10, 3,  7},
		{1,  7,  14, 13, 0,  5,  8,  3,  4,  15, 10, 6,  9,  12, 11, 2},
	};
	for (int i = 0; i < 8; i++)
	{
		mask = 15; // 00001111b
		mask <<= ((7-i)*4);
		index = ((data & mask)>>((7-i)*4)); // cut 4 bits from data and get index
		ret_data |= (s_blocks[i][index]<<((7-i)*4));
	}
	return ret_data;
}

uint32_t GOST::gost_shift(uint32_t data)
{
	for (int i = 0; i < 11; i++)
	{
		uint32_t bit = (data>>31); // get the highest bit and set it to low
		data <<= 1;
		data |= bit;
	}
	return data;
}

/*
** working with file system
*/
void GOST::encrypt_file(std::string file, uint8_t key_256[32])
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
		encrypt(buf+8+n, key_256);
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

void GOST::decrypt_file(std::string file, uint8_t key_256[32])
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
		decrypt(buf+n, key_256);
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

void GOST::encrypt_file(std::string file, std::string key_file_name)
{
	// file - file name; key - file name
	std::ifstream key_file(key_file_name);
	uint8_t key[32];
	key_file.read((char*)key, 32);
	encrypt_file(file, key);
}

void GOST::decrypt_file(std::string file, std::string key_file_name)
{
	// file - file name; key - file name
	std::ifstream key_file(key_file_name);
	uint8_t key[32];
	key_file.read((char*)key, 32);
	decrypt_file(file, key);
}

void GOST::recursive_file_encrypt(std::string path, uint8_t key_256[32])
{
	namespace fs = std::experimental::filesystem;
	for (auto current_path : fs::recursive_directory_iterator(fs::path(path)))
	{
		if (!(fs::is_directory(current_path.path())))
		{
			encrypt_file(std::string(current_path.path()), key_256);
		}
	}
}

void GOST::recursive_file_decrypt(std::string path, uint8_t key_256[32])
{
	namespace fs = std::experimental::filesystem;
	for (auto current_path : fs::recursive_directory_iterator(fs::path(path)))
	{
		if (!(fs::is_directory(current_path.path())))
		{
			decrypt_file(std::string(current_path.path()), key_256);
		}
	}
}

void GOST::recursive_file_encrypt(std::string path, std::string key_file_name)
{
	std::ifstream key_file(key_file_name);
	uint8_t key[32];
	key_file.read((char*)key, 32);
	recursive_file_encrypt(path, key);
}

void GOST::recursive_file_decrypt(std::string path, std::string key_file_name)
{
	std::ifstream key_file(key_file_name);
	uint8_t key[32];
	key_file.read((char*)key, 32);
	recursive_file_decrypt(path, key);
}
