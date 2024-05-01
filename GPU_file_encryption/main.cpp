#include "Header.h"

int main()
{
	AEScipher path("key.txt", "data");
	

	std::cout << "key: ";
	path.PrintDataFiles(path.keyss);



	
	path.PrintDataFiles(path.files);




	std::cout << "Combined data written to output_combined.bin" << std::endl;


	path.files.erase(std::remove_if(path.files.begin(), path.files.end(), [](const auto& vec) {
		return vec.empty();
		}), path.files.end());

	std::cout << "Writing data to a files: "<<std::endl;

	for (std::size_t i = 0; i < path.files.size(); ++i) {
		std::string filename = "dataEncode/fileEncript" + std::to_string(i) + ".bin";
		path.WriteFile(path.files[i], filename);
		std::cout << "Data written to " << filename << std::endl;
	}



	// then must be function
	for (int i = 0; i < path.keyss.size(); i++) {

		// 
		

		unsigned char* Encrytkeyss = new unsigned char[path.keyss[i].size()];//path.EncryptionAES(path.files[3].data(), path.keyss[3].data());
		unsigned char* EncrytFiles = new unsigned char[path.files[i].size()];

		std::copy(path.keyss[i].begin(), path.keyss[i].end(), Encrytkeyss);
		std::copy(path.files[i].begin(), path.files[i].end(), EncrytFiles);


	

		size_t length1 = path.files[i].size();
		std::cout << std::endl << length1 << std::endl;


		//checkSum
		//int sum1 = path.CheckSums(EncrytFiles, length1);
		//std::cout << "Sum " << sum1 << std::endl;

		unsigned char* EncrytData = path.EncryptionAES(EncrytFiles, Encrytkeyss);

		std::cout<<"strlen "<<strlen(reinterpret_cast<const char*>(EncrytData))<<std::endl;





	




		std::vector<unsigned char  > filesEncriptdata;
		

		std::cout << "EncryptionAES: " << std::endl;
		for (size_t  j= 0; j < length1; ++j) {
			filesEncriptdata.push_back(EncrytData[j]);
			std::cout << static_cast<int>(EncrytData[j]) << " ";
		}
		std::cout << std::endl;



		std::vector<unsigned char> emtyLine;
		for (unsigned char ch : filesEncriptdata) {
			if (ch == '\n') {
				path.filesEncript.push_back(emtyLine);
				emtyLine.clear();
			}
			else {
				emtyLine.push_back(ch);
			}
		}
		if (!emtyLine.empty()) {
			path.filesEncript.push_back(emtyLine);
		}


		delete[] EncrytData;



	}
	std::cout << "Contents of dataVector:" << std::endl;

	path.PrintDataFiles(path.filesEncript);










	int length1E = path.filesEncript.size();
	std::cout << "key CHECKK" << std::endl;

	path.PrintDataFiles(path.keyss);




	//del
	 
	 
	for (int i = 0; i < path.keyss.size(); i++) {
		unsigned char* Decryptkeyss = new unsigned char[path.keyss[i].size()];//path.EncryptionAES(path.files[3].data(), path.keyss[3].data());
		unsigned char* DecryptFiles = new unsigned char[path.filesEncript[i].size()];

		std::copy(path.keyss[i].begin(), path.keyss[i].end(), Decryptkeyss);
		std::copy(path.filesEncript[i].begin(), path.filesEncript[i].end(), DecryptFiles);

		size_t length1 = path.filesEncript[i].size();

		std::cout << "path.keyss[i]" << std::endl;
		for (const auto& element : path.keyss[i]) {

			std::cout << static_cast<int>(element) << " ";
		}
		//std::cout <<"Encrytkeyss: "<< i<<" " << Decryptkeyss << std::endl;
	

		unsigned char* DecryptionData = path.DecryptionAES(DecryptFiles, Decryptkeyss);
		std::cout << "DecryptionAEScheck: " << std::endl;



		std::cout << "DecryptionData[" << i <<"] " << std::endl;
		for (size_t j = 0; j < length1; ++j) {
			std::cout << static_cast<int>(DecryptionData[j]) << " ";
		}
		std::cout << std::endl;
		
	}

	for (auto& vec : path.keyss) {
		vec.clear(); // ������� ���������� ��������� ��������
	}
	path.keyss.clear();

	for (auto& vec : path.keyss) {
		vec.clear(); // ������� ���������� ��������� ��������
	}
	path.keyss.clear();



	return 0;
}

