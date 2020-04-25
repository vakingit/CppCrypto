#include <experimental/filesystem>
#include <inttypes.h>
#include <fstream>
#include <cstdlib>
#include <string>

class TEA
{
public:
	// ----------block-----------
	void encrypt(uint8_t inp_block[8], uint8_t key_block[16]);
	void decrypt(uint8_t inp_block[8], uint8_t key_block[16]);
	// ----------file-----------
	void encrypt_file(std::string file, uint8_t key_block[16]);
	void decrypt_file(std::string file, uint8_t key_block[16]);
	void encrypt_file(std::string file, std::string key_file_name);
	void decrypt_file(std::string file, std::string key_file_name);
	// ----------directories-----------
	void recursive_file_encrypt(std::string path, uint8_t key_block[16]);
	void recursive_file_decrypt(std::string path, uint8_t key_block[16]);
	void recursive_file_encrypt(std::string path, std::string key_file_name);
	void recursive_file_decrypt(std::string path, std::string key_file_name);
};