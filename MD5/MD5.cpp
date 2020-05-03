#include "MD5.hpp"

#define F(x,y,z) ((x&y)|((~x)&z))
#define G(x,y,z) ((x&z)|(y&(~z)))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y^(x|(~z)))

// char bytes[4] -> uint32_t
#define to_int32(bytes) (((uint32_t)((bytes)[0]&255)) \
                       |((uint32_t)((bytes)[1]&255) << 8) \
    	               |((uint32_t)((bytes)[2]&255) << 16) \
    	               |((uint32_t)((bytes)[3]&255) << 24))

#define md5_shift(number,n) ((number<<n)|(number>>(32-n)))

#define FF(a,b,c,d,M,s,T) {a = b+md5_shift((a+F(b,c,d)+M+T),s);}
#define GG(a,b,c,d,M,s,T) {a = b+md5_shift((a+G(b,c,d)+M+T),s);}
#define HH(a,b,c,d,M,s,T) {a = b+md5_shift((a+H(b,c,d)+M+T),s);}
#define II(a,b,c,d,M,s,T) {a = b+md5_shift((a+I(b,c,d)+M+T),s);}

char* MD5::hash(const char* msg,uint64_t len, char* hash)
{
	uint64_t aligned_len = (((((len*8)+64)/512)*512)+512);
	char* aligned_msg = new char[aligned_len/8];
	unsigned int T[64] = 
	{
		0xd76aa478,	0xe8c7b756,	0x242070db,	0xc1bdceee,
		0xf57c0faf,	0x4787c62a,	0xa8304613,	0xfd469501,
		0x698098d8,	0x8b44f7af,	0xffff5bb1,	0x895cd7be,
		0x6b901122,	0xfd987193,	0xa679438e,	0x49b40821,
		0xf61e2562,	0xc040b340,	0x265e5a51,	0xe9b6c7aa,
		0xd62f105d,	0x2441453,	0xd8a1e681,	0xe7d3fbc8,
		0x21e1cde6,	0xc33707d6,	0xf4d50d87,	0x455a14ed,
		0xa9e3e905,	0xfcefa3f8,	0x676f02d9,	0x8d2a4c8a,
		0xfffa3942,	0x8771f681,	0x6d9d6122,	0xfde5380c,
		0xa4beea44,	0x4bdecfa9,	0xf6bb4b60,	0xbebfbc70,
		0x289b7ec6,	0xeaa127fa,	0xd4ef3085,	0x4881d05,
		0xd9d4d039,	0xe6db99e5,	0x1fa27cf8,	0xc4ac5665,
		0xf4292244,	0x432aff97,	0xab9423a7,	0xfc93a039,
		0x655b59c3,	0x8f0ccc92,	0xffeff47d,	0x85845dd1,
		0x6fa87e4f,	0xfe2ce6e0,	0xa3014314,	0x4e0811a1,
		0xf7537e82,	0xbd3af235,	0x2ad7d2bb, 0xeb86d391
	};

	for (int i = 0; i < len; i++)
	{
		aligned_msg[i] = msg[i];
	}
	align((char*)aligned_msg,len,aligned_len);

	uint32_t A = 0x67452301;
	uint32_t B = 0xefcdab89;
	uint32_t C = 0x98badcfe;
	uint32_t D = 0x10325476;

	unsigned int a = A, b = B, c = C, d = D;
	
	for (int i = 0; i < aligned_len/512; i++)
	{
		// F(x,y,z) = (x&y)|((~x)&z)
		// FF(a,b,c,d,Mi,s,Ti) = a = b+((a+F(b,c,d)+Mi+ti)<<<s)
		FF(a,b,c,d,to_int32(aligned_msg+0*4),7,T[0]);
		FF(d,a,b,c,to_int32(aligned_msg+1*4),12,T[1]);
		FF(c,d,a,b,to_int32(aligned_msg+2*4),17,T[2]);
		FF(b,c,d,a,to_int32(aligned_msg+3*4),22,T[3]);
		FF(a,b,c,d,to_int32(aligned_msg+4*4),7,T[4]);
		FF(d,a,b,c,to_int32(aligned_msg+5*4),12,T[5]);
		FF(c,d,a,b,to_int32(aligned_msg+6*4),17,T[6]);
		FF(b,c,d,a,to_int32(aligned_msg+7*4),22,T[7]);
		FF(a,b,c,d,to_int32(aligned_msg+8*4),7,T[8]);
		FF(d,a,b,c,to_int32(aligned_msg+9*4),12,T[9]);
		FF(c,d,a,b,to_int32(aligned_msg+10*4),17,T[10]);
		FF(b,c,d,a,to_int32(aligned_msg+11*4),22,T[11]);
		FF(a,b,c,d,to_int32(aligned_msg+12*4),7,T[12]);
		FF(d,a,b,c,to_int32(aligned_msg+13*4),12,T[13]);
		FF(c,d,a,b,to_int32(aligned_msg+14*4),17,T[14]);
		FF(b,c,d,a,to_int32(aligned_msg+15*4),22,T[15]);

		// G(x,y,z) = (x&y)|(x&(~z))
		// GG(a,b,c,d,Mi,s,Ti) = a = b+(a+G(b,c,d)+Mi+ti)
		GG(a,b,c,d,to_int32(aligned_msg+1*4),5,T[16]);
		GG(d,a,b,c,to_int32(aligned_msg+6*4),9,T[17]);
		GG(c,d,a,b,to_int32(aligned_msg+11*4),14,T[18]);
		GG(b,c,d,a,to_int32(aligned_msg+0*4),20,T[19]);
		GG(a,b,c,d,to_int32(aligned_msg+5*4),5,T[20]);
		GG(d,a,b,c,to_int32(aligned_msg+10*4),9,T[21]);
		GG(c,d,a,b,to_int32(aligned_msg+15*4),14,T[22]);
		GG(b,c,d,a,to_int32(aligned_msg+4*4),20,T[23]);
		GG(a,b,c,d,to_int32(aligned_msg+9*4),5,T[24]);
		GG(d,a,b,c,to_int32(aligned_msg+14*4),9,T[25]);
		GG(c,d,a,b,to_int32(aligned_msg+3*4),14,T[26]);
		GG(b,c,d,a,to_int32(aligned_msg+8*4),20,T[27]);
		GG(a,b,c,d,to_int32(aligned_msg+13*4),5,T[28]);
		GG(d,a,b,c,to_int32(aligned_msg+2*4),9,T[29]);
		GG(c,d,a,b,to_int32(aligned_msg+7*4),14,T[30]);
		GG(b,c,d,a,to_int32(aligned_msg+12*4),20,T[31]);

		// H(x,y,z) = x^y^z
		// HH(a,b,c,d,Mi,s,Ti) = a = b+(a+H(b,c,d)+Mi+ti)
		HH(a,b,c,d,to_int32(aligned_msg+5*4),4,T[32]);
		HH(d,a,b,c,to_int32(aligned_msg+8*4),11,T[33]);
		HH(c,d,a,b,to_int32(aligned_msg+11*4),16,T[34]);
		HH(b,c,d,a,to_int32(aligned_msg+14*4),23,T[35]);
		HH(a,b,c,d,to_int32(aligned_msg+1*4),4,T[36]);
		HH(d,a,b,c,to_int32(aligned_msg+4*4),11,T[37]);
		HH(c,d,a,b,to_int32(aligned_msg+7*4),16,T[38]);
		HH(b,c,d,a,to_int32(aligned_msg+10*4),23,T[39]);
		HH(a,b,c,d,to_int32(aligned_msg+13*4),4,T[40]);
		HH(d,a,b,c,to_int32(aligned_msg+0*4),11,T[41]);
		HH(c,d,a,b,to_int32(aligned_msg+3*4),16,T[42]);
		HH(b,c,d,a,to_int32(aligned_msg+6*4),23,T[43]);
		HH(a,b,c,d,to_int32(aligned_msg+9*4),4,T[44]);
		HH(d,a,b,c,to_int32(aligned_msg+12*4),11,T[45]);
		HH(c,d,a,b,to_int32(aligned_msg+15*4),16,T[46]);
		HH(b,c,d,a,to_int32(aligned_msg+2*4),23,T[47]);

		// I(b,c,d) = c^(b|(~d))
		// II(a,b,c,d,Mi,s,Ti) = a = b+(a+I(b,c,d)+Mi+ti)
		II(a,b,c,d,to_int32(aligned_msg+0*4),6,T[48]);
		II(d,a,b,c,to_int32(aligned_msg+7*4),10,T[49]);
		II(c,d,a,b,to_int32(aligned_msg+14*4),15,T[50]);
		II(b,c,d,a,to_int32(aligned_msg+5*4),21,T[51]);
		II(a,b,c,d,to_int32(aligned_msg+12*4),6,T[52]);
		II(d,a,b,c,to_int32(aligned_msg+3*4),10,T[53]);
		II(c,d,a,b,to_int32(aligned_msg+10*4),15,T[54]);
		II(b,c,d,a,to_int32(aligned_msg+1*4),21,T[55]);
		II(a,b,c,d,to_int32(aligned_msg+8*4),6,T[56]);
		II(d,a,b,c,to_int32(aligned_msg+15*4),10,T[57]);
		II(c,d,a,b,to_int32(aligned_msg+6*4),15,T[58]);
		II(b,c,d,a,to_int32(aligned_msg+13*4),21,T[59]);
		II(a,b,c,d,to_int32(aligned_msg+4*4),6,T[60]);
		II(d,a,b,c,to_int32(aligned_msg+11*4),10,T[61]);
		II(c,d,a,b,to_int32(aligned_msg+2*4),15,T[62]);
		II(b,c,d,a,to_int32(aligned_msg+9*4),21,T[63]);

		a = (A += a);
		b = (B += b);
		c = (C += c);
		d = (D += d);

		aligned_msg+=64;
	}

	//presentation of the result
	char hextable[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

	for (int i = 0; i < 4; i++)
	{
		hash[i*2] = hextable[((uint8_t)(A>>(i*8)))>>4];//bits 7-4
		hash[i*2+1] = hextable[((uint8_t)(A>>(i*8)))&15];//bits 3-0
	}
	for (int i = 0; i < 4; i++)
	{
		hash[8+i*2] = hextable[((uint8_t)(B>>(i*8)))>>4];
		hash[8+i*2+1] = hextable[((uint8_t)(B>>(i*8)))&15];
	}
	for (int i = 0; i < 4; i++)
	{
		hash[16+i*2] = hextable[((uint8_t)(C>>(i*8)))>>4];
		hash[16+i*2+1] = hextable[((uint8_t)(C>>(i*8)))&15];
	}
	for (int i = 0; i < 4; i++)
	{
		hash[24+i*2] = hextable[((uint8_t)(D>>(i*8)))>>4];
		hash[24+i*2+1] = hextable[((uint8_t)(D>>(i*8)))&15];
	}
	hash[32] = '\0';

	delete (aligned_msg-aligned_len/8); // free memory

	return hash;
}

char* MD5::file_hash(const char* name,char* hash)
{
	namespace fs = std::experimental::filesystem;
	std::ifstream f(name,std::ios::binary);
	uint64_t size = fs::file_size(fs::path(name));
	char* mes = new char[size];
	f.read(mes,size);
	this->hash(mes,size,hash);
	delete mes;
	return hash;
}

void MD5::align(char* aligned_msg, int len, uint64_t aligned_len)
{
	// addition
	aligned_msg[len] = 128; // 10000000b
	for (int i = len+1; i < (aligned_len-64)/8; i++)
	{
		aligned_msg[i] = 0;
	}

	// add length
	for (int i = 0; i < 8; ++i)
		aligned_msg[(aligned_len/8)-8+i] = (uint8_t)(((uint64_t)(len)*8) >> (i*8));
}
