"""scrypt parameters — N, r, p, memory, maxmem, and the RFC 7914 test vectors

https://www.rfc-editor.org/rfc/rfc7914    (CWE-916: https://cwe.mitre.org/data/definitions/916.html)

scrypt is memory-hard: each derivation fills a table of 128 * r * N bytes and
reads it back in a data-dependent order, which is what makes GPU and ASIC
cracking expensive. N (a power of two) and r set that memory; p runs
independent lanes that can be computed one after another in the *same*
memory, so raising p buys CPU cost but no extra memory hardness.

Tutorial parameters like N=1024, r=1 use 128 KiB and are cheap to attack.
OWASP's baseline is N=2**17, r=8, p=1 (128 MiB). hashlib.scrypt refuses to
use more than maxmem bytes (32 MiB by default), and the exact requirement in
OpenSSL is 128 * r * (N + p + 2), so compute maxmem from the parameters
instead of guessing it.
"""

import hashlib

VECTORS = [  # RFC 7914 section 12 (the N=1048576 vector needs 1 GiB and is skipped)
    (b"", b"", 16, 1, 1,
     "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
     "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
    (b"password", b"NaCl", 1024, 8, 16,
     "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
     "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"),
    (b"pleaseletmein", b"SodiumChloride", 16384, 8, 1,
     "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
     "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"),
]


def required_maxmem(n: int, r: int, p: int) -> int:
    return 128 * r * (n + p + 2)


def mib(nbytes: int) -> str:
    return f"{nbytes / 2**20:.3f} MiB" if nbytes < 2**20 else f"{nbytes / 2**20:.0f} MiB"


def main() -> None:
    for password, salt, n, r, p, want in VECTORS:
        got = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p,
                             maxmem=required_maxmem(n, r, p), dklen=64)
        print(f"RFC 7914 N={n:<5} r={r} p={p:<2}: {got.hex() == want}")

    print()
    print("params               table memory   relative work")
    for label, n, r, p in (("noncompliant", 2**10, 1, 1), ("p instead of N", 2**10, 1, 128),
                           ("compliant", 2**17, 8, 1)):
        print(f"{label:14} ln={n.bit_length() - 1:<2} r={r} p={p:<3} {mib(128 * r * n):>12}   "
              f"{n * r * p // 2**10:>6}x")

    print()
    n, r, p = 2**17, 8, 1
    need = required_maxmem(n, r, p)
    for maxmem in (0, need - 1, need):  # 0 means the 32 MiB default
        try:
            hashlib.scrypt(b"pw", salt=b"0123456789abcdef", n=n, r=r, p=p, maxmem=maxmem, dklen=32)
            result = "ok"
        except ValueError as exc:
            result = f"{type(exc).__name__}, memory limit: {'memory limit' in str(exc)}"
        print(f"maxmem={maxmem:<10} for N=2**17 r=8 p=1 -> {result}")
    try:
        hashlib.scrypt(b"pw", salt=b"salt", n=1000, r=8, p=1)
    except ValueError as exc:
        print(f"N=1000 -> {type(exc).__name__}, power of 2 required: {'power of 2' in str(exc)}")


if __name__ == "__main__":
    main()

# Output:
# RFC 7914 N=16    r=1 p=1 : True
# RFC 7914 N=1024  r=8 p=16: True
# RFC 7914 N=16384 r=8 p=1 : True
#
# params               table memory   relative work
# noncompliant   ln=10 r=1 p=1      0.125 MiB        1x
# p instead of N ln=10 r=1 p=128    0.125 MiB      128x
# compliant      ln=17 r=8 p=1        128 MiB     1024x
#
# maxmem=0          for N=2**17 r=8 p=1 -> ValueError, memory limit: True
# maxmem=134220799  for N=2**17 r=8 p=1 -> ValueError, memory limit: True
# maxmem=134220800  for N=2**17 r=8 p=1 -> ok
# N=1000 -> ValueError, power of 2 required: True
