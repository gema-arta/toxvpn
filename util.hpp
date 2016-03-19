#ifndef UTIL_HPP
#define UTIL_HPP
#include <string>
#include <memory>
#include <cstdio>
#include <cstdarg>

namespace Util {
inline void trace(const char* formator, ...) {
    FILE *file = stderr;
    va_list al;
    va_start(al, formator);
    vfprintf(file, formator, al);
    fprintf(file, "\n");
}

size_t file_get_size(FILE *file)
{
    const size_t pos = ftell(file);
    fseek(file, 0, SEEK_END);
    const size_t size = ftell(file);
    fseek(file, pos, SEEK_SET);
    return size;
}

std::string string_format(const std::string fmt_str, ...) {
    int final_n, n = ((int)fmt_str.size()) * 2; /* Reserve two times as much as the length of the fmt_str */
    std::string str;
    std::unique_ptr<char[]> formatted;
    va_list ap;
    while(1) {
        formatted.reset(new char[n]); /* Wrap the plain char array into the unique_ptr */
        strcpy(&formatted[0], fmt_str.c_str());
        va_start(ap, fmt_str);
        final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
        va_end(ap);
        if (final_n < 0 || final_n >= n)
            n += abs(final_n - n + 1);
        else
            break;
    }
    return std::string(formatted.get());
}

}

#endif // UTIL_HPP
