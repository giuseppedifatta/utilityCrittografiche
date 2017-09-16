// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"


#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"


#include "cryptopp/hex.h"


#include "cryptopp/filters.h"


#include "cryptopp/aes.h"


#include "cryptopp/ccm.h"



#include "assert.h"

using namespace CryptoPP;

int main(int argc, char* argv[])
{
	//generazione chiave simmetrica e iv
	AutoSeededRandomPool rng;

	// chiave simmetrica
	SecByteBlock key( AES::MAX_KEYLENGTH ); //AES::MAX_KEYLENGTH=32
	rng.GenerateBlock( key, key.size() );
	//cout << key.size() << " !=  "<< sizeof(key) << endl;
	// Pretty print key
	string encoded;
	encoded.clear();
	StringSource(key, key.size(), true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	//initial value
	SecByteBlock iv(AES::BLOCKSIZE);
	rng.GenerateBlock( iv, iv.size() );
	// Pretty print iv
	encoded.clear();
	StringSource(iv,iv.size(),true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	//	string encodedIV;
	//	byte iv[AES::BLOCKSIZE];
	//	memset(iv, 0x01,AES::BLOCKSIZE);
	//	std::string s_iv( reinterpret_cast< char const* >(iv) ) ;
	//	StringSource(s_iv, true,
	//			new HexEncoder(
	//					new StringSink(encodedIV)
	//			) // HexEncoder
	//	); // StringSource
	//	cout << "iv: " << encodedIV << endl;

	string plain = "CBC Mode Test";
	string cipher, recovered;



	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource (plain, true,
				new StreamTransformationFilter(e,
						new StringSink(cipher)
				) // StreamTransformationFilter
		); // StringSource


	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}




	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{

		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
				new StreamTransformationFilter(d,
						new StringSink(recovered)
				) // StreamTransformationFilter
		); // StringSource



		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}
