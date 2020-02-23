#ifndef TIOSTREAM_H
#define TIOSTREAM_H

#include <iostream>
#include <sstream>

#ifdef UNICODE
using char_t = wchar_t;
using tostringstream = std::wostringstream;
#else
using char_t = char;
using tostringstream = std::ostringstream;
#endif

template<typename T> struct select_cout;
template<> struct select_cout<char> { static std::ostream& cout; };
std::ostream& select_cout<char>::cout = std::cout;

template<> struct select_cout<wchar_t> { static std::wostream& cout; };
std::wostream& select_cout<wchar_t>::cout = std::wcout;

std::basic_ostream<char_t>& cout = select_cout<char_t>::cout;


#endif
