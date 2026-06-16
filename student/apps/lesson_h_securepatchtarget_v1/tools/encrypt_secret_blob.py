#!/usr/bin/env python3

import argparse
import base64

DELTA = 0x9E3779B9
KEY = [
    0x72636573,  # secr
    0x616C7465,  # alte
    0x616E2D62,  # an-b
    0x65766974,  # evit
]


def bytes_to_words_with_len(data: bytes) -> list[int]:
    words = [0] * (((len(data) + 3) // 4) + 1)
    for i, byte in enumerate(data):
        words[i // 4] |= byte << ((i % 4) * 8)
    words[-1] = len(data)
    return words


def words_to_bytes(words: list[int]) -> bytes:
    out = bytearray(len(words) * 4)
    for i, word in enumerate(words):
        out[i * 4 + 0] = word & 0xFF
        out[i * 4 + 1] = (word >> 8) & 0xFF
        out[i * 4 + 2] = (word >> 16) & 0xFF
        out[i * 4 + 3] = (word >> 24) & 0xFF
    return bytes(out)


def xxtea_encrypt(plaintext: bytes) -> bytes:
    v = bytes_to_words_with_len(plaintext)
    n = len(v) - 1
    if n < 1:
        return b""

    rounds = 6 + 52 // (n + 1)
    total = 0
    z = v[n]
    for _ in range(rounds):
        total = (total + DELTA) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            mx = (
                (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
                ^ ((total ^ y) + (KEY[(p & 3) ^ e] ^ z))
            ) & 0xFFFFFFFF
            z = v[p] = (v[p] + mx) & 0xFFFFFFFF
        y = v[0]
        mx = (
            (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
            ^ ((total ^ y) + (KEY[(n & 3) ^ e] ^ z))
        ) & 0xFFFFFFFF
        z = v[n] = (v[n] + mx) & 0xFFFFFFFF

    return words_to_bytes(v[:-1])


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encrypt plaintext into the Base64 blob format accepted by AppSecrets.decryptBlob()."
    )
    parser.add_argument("plaintext", help="Plaintext secret, for example a Geoapify API key")
    args = parser.parse_args()

    encrypted = xxtea_encrypt(args.plaintext.encode("utf-8"))
    print(base64.b64encode(encrypted).decode("ascii"))


if __name__ == "__main__":
    main()
