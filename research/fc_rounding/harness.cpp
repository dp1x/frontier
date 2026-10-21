#include <charconv>
#include <cfenv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(__clang__)
#pragma STDC FENV_ACCESS ON
#endif

int main(int argc, char** argv) {
    if (argc < 5) {
        std::fprintf(stderr, "usage: %s <f|d> <g|h> <mode 0..3> <input>\n", argv[0]);
        return 2;
    }
    char typec = argv[1][0];
    char fmtc = argv[2][0];
    int mode = std::atoi(argv[3]);
    const char* s = argv[4];
    std::size_t n = std::strlen(s);

    std::chars_format fmt = (fmtc == 'h') ? std::chars_format::hex : std::chars_format::general;

    static const int modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    int req = modes[mode];

    int rc_set = std::fesetround(req);
    int actual_before = std::fegetround();

    bool ok = false;
    int ec = 0;
    std::size_t consumed = 0;
    unsigned long long bits = 0;

    if (typec == 'f') {
        float val = 0.0f;
        auto res = std::from_chars(s, s + n, val, fmt);
        ec = static_cast<int>(res.ec);
        consumed = static_cast<std::size_t>(res.ptr - s);
        ok = (res.ec == std::errc{});
        if (ok) {
            unsigned int u = 0;
            static_assert(sizeof(u) == sizeof(val), "size");
            std::memcpy(&u, &val, sizeof(u));
            bits = u;
        }
    } else {
        double val = 0.0;
        auto res = std::from_chars(s, s + n, val, fmt);
        ec = static_cast<int>(res.ec);
        consumed = static_cast<std::size_t>(res.ptr - s);
        ok = (res.ec == std::errc{});
        if (ok) {
            unsigned long long u = 0;
            static_assert(sizeof(u) == sizeof(val), "size");
            std::memcpy(&u, &val, sizeof(u));
            bits = u;
        }
    }

    int actual_after = std::fegetround();

    // print JSON
    std::printf("{\"type\":\"%c\",\"fmt\":\"%c\",\"mode\":%d,\"rc_set\":%d,\"actual_before\":%d,\"ec\":%d,\"consumed\":%zu,\"ok\":%s,\"bits\":%llu,\"actual_after\":%d}\n",
        typec, fmtc, mode, rc_set, actual_before, ec, consumed, ok ? "true" : "false", bits, actual_after);
    return 0;
}
