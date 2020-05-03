#include <inttypes.h>
#include <fstream>
#include <experimental/filesystem>

class MD5
{
public:
	char* hash(const char* msg, uint64_t len, char* hash);
	char* file_hash(const char* name,char* hash);
protected:
	void align(char* aligned_msg, int len, uint64_t aligned_len);
};
