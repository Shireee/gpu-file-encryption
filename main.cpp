
#include "AES.h"




int main()
{


	AEScipher path("data/keys.txt", "data/source");
	bool readKey = false;
	std::cout << "Output the keys?\n1 - Yes 0 - No : ";
	std::cin >> readKey;
	if (readKey == 1) {
		std::cout << "Key:" << std::endl;

		path.PrintDataFiles(path.keyss);
	}




	if (path.keyss.size() == path.files.size()) {
		std::cout << "Equal number of keys and files" << std::endl;

		path.StartEncryption();


		std::cout << std::endl << std::endl;


		std::cout << "0 - The keys go sequentially to the files\n"
			"1 - The order of the keys is unknown: ";

		bool index;

		std::cin >> index;

		std::cout << std::endl;

		if (index == 0) {
			path.StartDecryption(index);
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


	path.MemoryCleaning();



	return 0;
}