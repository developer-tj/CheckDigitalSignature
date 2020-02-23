
#include <iostream>
#include "DigitalSignatureInfo.h"
#include <tchar.h>

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc == 2)
    {
        DigitalSignatureInfo digitalSignatureInfo(argv[1]);
        digitalSignatureInfo.initialize();
        digitalSignatureInfo.PrintCertificateInfoList();

        return 0;
    }
    else
    {
        std::cout << "ERROR!! Need Check FilePath" << std::endl;;
        std::cout << "CheckDigitalSignature.exe [filePath]" << std::endl;
    }

    return 1;
}