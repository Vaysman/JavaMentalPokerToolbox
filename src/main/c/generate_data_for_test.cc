#include "mpz_shash.hh"
#include "libTMCG.hh"
#include "mpz_helper.hh"
#include <iostream>
#include <stdio.h>

/* hash function h() (collision-resistant?) */
//void h
//	(char *output, const char *input, size_t size)
//{
//	gcry_md_hash_buffer(GCRY_MD_RMD160, output, input, size);
//}

/* hash function g() (The design is based on the ideas of [BR95].) */
//void g
//	(char *output, size_t osize, const char *input, size_t isize)
//{
//	size_t mdsize = gcry_md_get_algo_dlen(TMCG_GCRY_MD_ALGO);
//	size_t usesize = mdsize / 4;
//	size_t times = (osize / usesize) + 1;
//	char *out = new char[times * mdsize];
//	for (size_t i = 0; i < times; i++)
//	{
//		/* construct the expanded input y = x || TMCG<i> || x */
//		char *data = new char[9 + (2 * isize)];
//		memcpy(data, input, isize);
//		snprintf(data + isize, 9, "libTMCG%02x", (unsigned int)i);
//		memcpy(data + isize + 9, input, isize);
//
//		/* using h(y) "in some nonstandard way" with "output truncated" [BR95] */
//		h(out + (i * usesize), data, 9 + (2 * isize));
//		delete [] data;
//	}
//	memcpy(output, out, osize);
//	delete [] out;
//}

int main() {
	std::string type;
	unsigned long keysize = 512;
	mpz_t m, y, foo;

	mpz_init(foo);
	mpz_init(m);
	mpz_init(y);
	mpz_set_ui(m, 65536L);
	mpz_set_ui(y, 7654321L);

	std::ostringstream  text;

	text << "cyhr9jnjp5f8iq30b34rwmvnpu2st75hk89ek9j80lqhh1xmxo68cz3r9e3f4yhp^5";
	int mnsize = 41;
	char *mn = new char[mnsize];
	int size = (text.str()).length();

	g(mn, mnsize, (text.str()).c_str(), size);
	std::cout << "g function\n";
	for(int i = 0;i<mnsize;i++) {
    		std::cout << ", " << (int)mn[i];
	}
//	char *data = new char[9 + (2 * size)];
//	memcpy(data, input, size);
//	snprintf(data + size, 10, "libTMCG%02x", (unsigned int)16);
//	memcpy(data + size + 9, input, size);
//
//
//	h(mn, )
/*
	std::cout << "\nmpz_impor\n";

	mpz_import(foo, 1, -1, mnsize, 1, 0, mn);

	std::cout << foo;

	std::cout << "\n";

	std::cout << "mpz_get_ui\n***********\n";
	mpz_set_ui(foo, 567L);
	std::cout << foo << "\n";
	std::cout << mpz_get_ui(foo) << "\n";

	std::cout << "mpz_sqrtmn_r\n***********\n";
	mpz_set_ui(foo, 567L);
	std::cout << foo << "\n";
	std::cout << mpz_get_ui(foo) << "\n";
*/
	std::cout << "secret_key\n***********\n";
	TMCG_SecretKey sec("A", "a@a.com", 328L);
	std::cout <<  sec << "\n";
	std::cout << "p:" << sec.p << "\n";
	std::cout << "q:" << sec.q << "\n";
//	std::cout << "m1pq:" << sec.m1pq << "\n";
//	std::cout << "y1:" << sec.y1 << "\n";
//	std::cout << "gcdext_up:" << sec.gcdext_up << "\n";
//	std::cout << "gcdext_vq:" << sec.gcdext_vq << "\n";
//	std::cout << "pa1d4:" << sec.pa1d4 << "\n";
//	std::cout << "qa1d4:" << sec.qa1d4 << "\n";
}