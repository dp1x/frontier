#include "simdutf.h"
#include <cstdio>
#include <vector>
#include <cstdint>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

int main() {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif
    std::vector<unsigned char> buf;
    unsigned char tmp[65536];
    size_t n;
    while ((n = std::fread(tmp, 1, sizeof(tmp), stdin)) > 0) {
        buf.insert(buf.end(), tmp, tmp + n);
    }
    bool ok = simdutf::validate_utf8(reinterpret_cast<const char*>(buf.data()), buf.size());
    std::printf(ok ? "VALID\n" : "INVALID\n");
    return 0;
}
