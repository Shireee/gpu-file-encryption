
#include "Header.h"



int main()
{
	AEScipher path("key.txt", "data");


	//path.PrintDataFiles(path.keyss);

	//path.PrintDataFiles(path.files);



	std::cout<<std::endl;



	if (path.keyss.size() == path.files.size()) {

		std::cout << "Equal number of keys and files" << std::endl;

		path.StartEncryption();

		std::cout << std::endl << std::endl << std::endl << std::endl << std::endl << std::endl << std::endl;

		// new keyss in keyss_shuffer
		path.Shuffer(path.keyss.size());

		std::cout << "0 - The keys go sequentially to the files\n"
			"1 - The order of the keys is unknown: ";

		bool index;

		std::cin >> index;

		std::cout << std::endl;

		if (index == 0) {
			path.StartDecryption();
		}
		else if (index == 1) {
			path.StartDecryptionShuffer();
		}
		else {
			std::cout << "Incorrect data entered" << std::endl;
		}

	}
	else {
		std::cout << "Error: not equal number of keys and files" << std::endl;
		
	}


	for (auto& vec : path.keyss) {
		vec.clear(); 
	}
	path.keyss.clear();

	for (auto& vec : path.keyss) {
		vec.clear(); 
	}
	path.keyss.clear();




	return 0;
}