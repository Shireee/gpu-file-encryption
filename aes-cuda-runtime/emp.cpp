#include "functions.h"

int main() {

	std::cout << "HelloWorld" << std::endl;
	printBytes(reinterpret_cast<unsigned char *>("HelloWorld"), 16);

}