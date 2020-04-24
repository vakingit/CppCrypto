#include <inttypes.h>
#include <experimental/filesystem>
#include <string>
#include <fstream>

class GOST
{
public:
	void encrypt(uint8_t* data_block, uint8_t* key_256);
	void decrypt(uint8_t* data_block, uint8_t* key_256);
	// ----------file-----------
	void encrypt_file(std::string file, uint8_t key_256[32]);
	void decrypt_file(std::string file, uint8_t key_256[32]);
	void encrypt_file(std::string file, std::string key_file_name);
	void decrypt_file(std::string file, std::string key_file_name);
	// ----------directories-----------
	void recursive_file_encrypt(std::string path, uint8_t key_256[32]);
	void recursive_file_decrypt(std::string path, uint8_t key_256[32]);
	void recursive_file_encrypt(std::string path, std::string key_file_name);
	void recursive_file_decrypt(std::string path, std::string key_file_name);
protected:
	void gost_generate_keys(uint32_t keys[8], uint8_t* key_256);
	uint32_t gost_s_block(uint32_t data);
	uint32_t gost_shift(uint32_t data);
};