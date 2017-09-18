// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"

#include <iostream>
#include <chrono>
#include <string>
#include <cstdlib>
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/rsa.h"


using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[])
{
	//generazione chiave simmetrica e iv
	//	AutoSeededRandomPool rng;
	//
	//	// chiave simmetrica
	//	SecByteBlock key( AES::MAX_KEYLENGTH ); //AES::MAX_KEYLENGTH=32
	//	rng.GenerateBlock( key, key.size() );
	//	//cout << key.size() << " !=  "<< sizeof(key) << endl;
	//	// Pretty print key
	//	string encoded;
	//	encoded.clear();
	//	StringSource(key, key.size(), true,
	//			new HexEncoder(
	//					new StringSink(encoded)
	//			) // HexEncoder
	//	); // StringSource
	//	cout << "key: " << encoded << endl;
	//
	//	//initial value
	//	SecByteBlock iv(AES::BLOCKSIZE);
	//	rng.GenerateBlock( iv, iv.size() );
	//	// Pretty print iv
	//	encoded.clear();
	//	StringSource(iv,iv.size(),true,
	//			new HexEncoder(
	//					new StringSink(encoded)
	//			) // HexEncoder
	//	); // StringSource
	//	cout << "iv: " << encoded << endl;
	string encodedKey = "BB2385F128C3B2B1E42C763D2BBA8553E0776666B2DEDE7BCFBDFA9AAB97EF68";
	string k;
	StringSource(encodedKey,true, new HexDecoder(new StringSink(k)));
	SecByteBlock key(reinterpret_cast< const byte*>(k.data()),k.size());
	string encodedIV;
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x01,AES::BLOCKSIZE);
	std::string s_iv( reinterpret_cast< char const* >(iv) ) ;
	StringSource(s_iv, true,
			new HexEncoder(
					new StringSink(encodedIV)
			) // HexEncoder
	); // StringSource
	cout << "iv: " << encodedIV << endl;

	///////////////////// //genero il mio plain

	//string plain = "CBC Mode Test";
	AutoSeededRandomPool rng;

	RSA::PrivateKey rsaPrivate;
	rsaPrivate.GenerateRandomWithKeySize(rng, 3072);

	//RSA::PublicKey rsaPublic(rsaPrivate);

	ByteQueue queue2;
	rsaPrivate.Save(queue2);

	//copiamo la privateKey dal ByteQueue in una stringa
	string privateKey;
	StringSink ss2(privateKey);
	queue2.CopyTo(ss2);
	ss2.MessageEnd();
	cout << "privateKey: " << privateKey << endl; //formato byte

	string encodedPR;
	StringSource(privateKey, true,
			new HexEncoder(new StringSink(encodedPR)));
	cout << "encodedPrivateKey: " << encodedPR << endl;
	string plain = privateKey;
	string cipher, recovered;
	//////////////////////////


	auto t0 = std::chrono::high_resolution_clock::now();

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
	auto t1 = std::chrono::high_resolution_clock::now();
	auto dt = 1.e-6*std::chrono::duration_cast<std::chrono::nanoseconds>(t1-t0).count();

	cout << "Time to encrypt privateKey: " << dt << " millisecond(s)"  << endl;



	/*********************************\
	\*********************************/

	// Pretty print
	string encoded;
	encoded.clear();
	StringSource(cipher, true,
			new HexEncoder(
					new StringSink(encoded)
			) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	auto t2 = std::chrono::high_resolution_clock::now();
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
	auto t3 = std::chrono::high_resolution_clock::now();
	auto dt1 = 1.e-6*std::chrono::duration_cast<std::chrono::nanoseconds>(t3-t2).count();

		cout << "Time to decrypt privateKey: " << dt1 << " millisecond(s)"  << endl;

	/*********************************\
	\*********************************/

	if (plain == recovered){
		cout << "recovered plain" << endl;
	}
	string decodedPrivateKey;
	StringSource(recovered, true,
			new HexDecoder(new StringSink(decodedPrivateKey)));
	//cout << "decodedPRivateKey" << decodedPrivateKey << endl;
	return 0;
}

