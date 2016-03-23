#ifndef GLIBCCOMPAT_H
#define GLIBCCOMPAT_H

__asm__(".symver memcpy,memcpy@GLIBC_2.2.5");
__asm__(".symver clock_gettime,clock_gettime@GLIBC_2.2.5");


#endif // GLIBCCOMPAT_H
