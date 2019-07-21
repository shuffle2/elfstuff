#include "Utils.h"

bool string_vsprintf(std::string *str, const char *fmt, ...) {
    int required, length;
    va_list args;

    va_start(args, fmt);
    required = std::vsnprintf(nullptr, 0, fmt, args);
    va_end(args);
    if (required < 0) {
        str->clear();
        return false;
    }
    required += 1;

    auto buf = std::make_unique<char[]>(required);
    va_start(args, fmt);
    length = std::vsnprintf(buf.get(), required, fmt, args);
    va_end(args);
    if (length < 0) {
        str->clear();
        return false;
    }

    *str = buf.get();
    return true;
}

bool read_file(const std::string path, ByteVector *file) {
    file->clear();
    auto f = fopen(path.c_str(), "rb");
    if (!f) {
        return false;
    }
    bool status = false;
    struct _stat64 sb = { 0 };
    if (_stat64(path.c_str(), &sb)) {
        goto done;
    }
    *file = ByteVector(sb.st_size);
    if (!fread(file->data(), file->size(), 1, f)) {
        file->clear();
        goto done;
    }
    status = true;
done:
    fclose(f);
    return status;
}
