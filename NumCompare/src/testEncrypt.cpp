#include<iostream>
#include <exception>
#include <boost/program_options.hpp>
#include<henc/paillier.h>
#include<ctime>
using namespace std;

namespace op = boost::program_options;

void test_paillier_for_encrypt_time(long bitlens);

int main(int argc, char* argv[])
{
    cout<<"hello world"<<endl;

    long bitlens;
	op::options_description desc("All options for testing Paillier algorithm");
	desc.add_options()
		("help", "Produce help message")
		("bitlens", op::value<long>(&bitlens)->default_value(100), "Key length");
	
	op::variables_map vm;
	op::store(op::parse_command_line(argc, argv, desc), vm);
	op::notify(vm);

    if(argc == 1 || vm.count("help")){
		std::cout << desc << std::endl;
		return 0;
	}
		
	if(vm.count("bitlens")){
		test_paillier_for_encrypt_time(bitlens);
		return 0;
	}

    return 0;
}

void test_paillier_for_encrypt_time(long bitlens){
	std::cout << "The key length is: " << 2*bitlens << " (bits)" << std::endl;
	
	Paillier::SecretKey sk;
	Paillier::PublicKey pk;
	Paillier::key_gen(sk, pk, bitlens);
	
	Paillier::Encryptor enc(pk);

	// Paillier::Decryptor dec(sk);
	
	clock_t start, end;
	start = clock();
	for(int k = 0; k < 1; k++){
		NTL::ZZ m;
		m = NTL::RandomLen_ZZ(32);
		
		HEnc::PTxt pt;
		HEnc::CTxt ct;
		
		pt.set_pt(m);
		// std::cout << "pt = " << pt.get_pt() << std::endl;
		
		// Encrypt a message pt
		enc.encrypt(pt, ct);
		// std::cout << "ct = " << ct.get_ct() << std::endl;
	}
	end =clock();
	std::cout<<(double)(end-start)/CLOCKS_PER_SEC<<"s"<<std::endl;
}
