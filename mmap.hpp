#ifndef MMAP_HPP
#define MMAP_HPP

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

class MemoryMappedFile {
protected:
    string file_name;
    void *address = nullptr;
    size_t length = 0;
    int fd = -1;

public:
    MemoryMappedFile(const string &file_name) {
        assert(!file_name.empty());

        this->file_name = file_name;
    }

    ~MemoryMappedFile() {
        unmap();
        unlink(file_name.c_str());
    }

    void unmap() {
        if (address) {
            if (munmap(address, length)) {
                Util::trace("Failed to unmap file \"%s\": %s", file_name.c_str(), strerror(errno));
            }

            address = nullptr;
        }

        if (fd != -1) {
            if (close(fd)) {
                Util::trace("Failed to close mmaped file \"%s\": %s", file_name.c_str(), strerror(errno));
            }
            fd = -1;
        }
    }

    bool is_mapped() const {
        return address != nullptr && fd != -1;
    }

    bool map(const string &content) {
        assert(!content.empty());

        if (address) {
            munmap(address, length);
        }

        fd = open(file_name.c_str(), O_RDWR | O_CREAT);
        if (fd == -1) {
            Util::trace("Failed create a file \"%s\": %s", file_name.c_str(), strerror(errno));
            return false;
        }

        ftruncate(fd, content.size());

        length = content.size();
        address = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (address == MAP_FAILED) {
            address = nullptr;
            Util::trace("Failed map a file \"%s\" to memory: %s", file_name.c_str(), strerror(errno));
            return false;
        }

        sprintf((char*) address, content.c_str());

        return true;
    }
};


#endif // MMAP_HPP
