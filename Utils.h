#pragma once

bool string_vsprintf(std::string *str, const char *fmt, ...);

bool read_file(const std::string path, ByteVector *file);

template<typename T, size_t size>
T *pattern_find(T *haystack, size_t haystack_size, const T *pattern,
    const std::bitset<size> &mask) {
    for (size_t i = 0; i < haystack_size; i++) {
        for (size_t j = 0; j < size; j++) {
            if (!mask[j]) { continue; }
            else if (haystack[i + j] != pattern[j]) { break; }
            else if (j + 1 == size) { return &haystack[i]; }
        }
    }
    return nullptr;
}

template<typename T, size_t size>
void pattern_search(T *haystack, size_t haystack_size, const T *pattern,
    const std::bitset<size> &mask, std::function<void(u8 *)> handler) {
    auto pos = haystack;
    auto remaining = haystack_size;
    for (;;) {
        auto match = pattern_find(pos, remaining, pattern, mask);
        if (!match) { return; }
        handler(match);
        auto next = match + 1;
        remaining -= next - pos;
        pos = next;
        if (remaining == 0 || pos > haystack + haystack_size) { return; }
    }
}
