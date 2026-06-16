#include <jni.h>
#include <cstdint>
#include <string>
#include <vector>

namespace {
constexpr uint32_t kDelta = 0x9e3779b9u;
constexpr uint32_t kKey[4] = {
    0x72636573u, // secr
    0x616c7465u, // etla
    0x616e2d62u, // b-na
    0x65766974u, // tive
};

int decodeChar(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::string base64Decode(const std::string& input) {
    std::string out;
    int val = 0;
    int valb = -8;
    for (unsigned char c : input) {
        if (c == '=') break;
        int d = decodeChar(static_cast<char>(c));
        if (d < 0) continue;
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::vector<uint32_t> bytesToWords(const std::string& bytes) {
    const size_t words = (bytes.size() + 3) / 4;
    std::vector<uint32_t> out(words + 1, 0u);
    for (size_t i = 0; i < bytes.size(); ++i) {
        out[i / 4] |= static_cast<uint32_t>(static_cast<unsigned char>(bytes[i])) << ((i % 4) * 8);
    }
    out[words] = static_cast<uint32_t>(bytes.size());
    return out;
}

std::string wordsToBytes(const std::vector<uint32_t>& words, size_t byteCount) {
    std::string out(byteCount, '\0');
    for (size_t i = 0; i < byteCount; ++i) {
        out[i] = static_cast<char>((words[i / 4] >> ((i % 4) * 8)) & 0xffu);
    }
    return out;
}

std::string xxteaDecrypt(const std::string& input) {
    if (input.size() < 8 || (input.size() % 4) != 0) {
        return {};
    }
    std::vector<uint32_t> v = bytesToWords(input);
    const int n = static_cast<int>(v.size()) - 1;
    if (n < 2) {
        return {};
    }
    uint32_t rounds = 6u + 52u / static_cast<uint32_t>(n);
    uint32_t sum = rounds * kDelta;
    while (sum != 0u) {
        uint32_t e = (sum >> 2) & 3u;
        for (int p = n - 1; p > 0; --p) {
            uint32_t z = v[p - 1];
            uint32_t y = v[p];
            uint32_t mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
                ^ ((sum ^ y) + (kKey[(p & 3) ^ e] ^ z));
            v[p] -= mx;
        }
        uint32_t z = v[n];
        uint32_t y = v[0];
        uint32_t mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((sum ^ y) + (kKey[e] ^ z));
        v[0] -= mx;
        sum -= kDelta;
    }
    const uint32_t len = v[n];
    if (len > static_cast<uint32_t>(n * 4)) {
        return {};
    }
    v.pop_back();
    return wordsToBytes(v, len);
}
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_secretlab_secure_AppSecrets_decryptBlob(JNIEnv* env, jobject, jstring encodedBlob) {
    const char* raw = env->GetStringUTFChars(encodedBlob, nullptr);
    std::string input = base64Decode(raw ? raw : "");
    if (raw != nullptr) {
        env->ReleaseStringUTFChars(encodedBlob, raw);
    }
    std::string decoded = xxteaDecrypt(input);
    return env->NewStringUTF(decoded.c_str());
}
