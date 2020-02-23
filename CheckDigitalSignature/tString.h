#ifndef TSTRING_H
#define TSTRING_H
#include <string>

#ifdef UNICODE
using tstring = std::wstring;
#else
using tstring = std::string;
#endif

#endif


