/*
	FIXME: This code assumes little endian machine word ordering, and thus
	will not work properly on big endian machines
 */
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "crypt/dove.h"

static const uint32_t sbox[256] = {
	0xb7e15162, 0x8aed2a6a, 0xbf715880, 0x9cf4f3c7, 0x62e7160f, 0x38b4da56, 0xa784d904, 0x5190cfef,
	0x324e7738, 0x926cfbe5, 0xf4bf8d8d, 0x8c31d763, 0xda06c80a, 0xbb1185eb, 0x4f7c7b57, 0x57f59584,
	0x90cfd47d, 0x7c19bb42, 0x158d9554, 0xf7b46bce, 0xd55c4d79, 0xfd5f24d6, 0x613c31c3, 0x839a2ddf,
	0x8a9a276b, 0xcfbfa1c8, 0x77c56284, 0xdab79cd4, 0xc2b3293d, 0x20e9e5ea, 0xf02ac60a, 0xcc93ed87,
	0x4422a52e, 0xcb238fee, 0xe5ab6add, 0x835fd1a0, 0x753d0a8f, 0x78e537d2, 0xb95bb79d, 0x8dcaec64,
	0x2c1e9f23, 0xb829b5c2, 0x780bf387, 0x37df8bb3, 0x00d01334, 0xa0d0bd86, 0x45cbfa73, 0xa6160ffe,
	0x393c48cb, 0xbbca060f, 0x0ff8ec6d, 0x31beb5cc, 0xeed7f2f0, 0xbb088017, 0x163bc60d, 0xf45a0ecb,
	0x1bcd289b, 0x06cbbfea, 0x21ad08e1, 0x847f3f73, 0x78d56ced, 0x94640d6e, 0xf0d3d37b, 0xe67008e1,
	0x86d1bf27, 0x5b9b241d, 0xeb64749a, 0x47dfdfb9, 0x6632c3eb, 0x061b6472, 0xbbf84c26, 0x144e49c2,
	0xd04c324e, 0xf10de513, 0xd3f5114b, 0x8b5d374d, 0x93cb8879, 0xc7d52ffd, 0x72ba0aae, 0x7277da7b,
	0xa1b4af14, 0x88d8e836, 0xaf14865e, 0x6c37ab68, 0x76fe690b, 0x57112138, 0x2af341af, 0xe94f77bc,
	0xf06c83b8, 0xff5675f0, 0x979074ad, 0x9a787bc5, 0xb9bd4b0c, 0x5937d3ed, 0xe4c3a793, 0x96215eda,
	0xb1f57d0b, 0x5a7db461, 0xdd8f3c75, 0x540d0012, 0x1fd56e95, 0xf8c731e9, 0xc4d7221b, 0xbed0c62b,
	0xb5a87804, 0xb679a0ca, 0xa41d802a, 0x4604c311, 0xb71de3e5, 0xc6b400e0, 0x24a6668c, 0xcf2e2de8,
	0x6876e4f5, 0xc50000f0, 0xa93b3aa7, 0xe6342b30, 0x2a0a4737, 0x3b25f73e, 0x3b26d569, 0xfe2291ad,
	0x36d6a147, 0xd1060b87, 0x1a2801f9, 0x78376408, 0x2ff592d9, 0x140db1e9, 0x399df4b0, 0xe14ca8e8,
	0x8ee9110b, 0x2bd4fa98, 0xeed150ca, 0x6dd89322, 0x45ef7592, 0xc703f532, 0xce3a30cd, 0x31c070eb,
	0x36b4195f, 0xf33fb1c6, 0x6c7d70f9, 0x3918107c, 0xe2051fed, 0x33f6d1de, 0x9491c7de, 0xa6a5a442,
	0xe154c8bb, 0x6d8d0362, 0x803bc248, 0xd414478c, 0x2afb07ff, 0xe78e89b9, 0xfeca7e30, 0x60c08f0d,
	0x61f8e368, 0x01df66d1, 0xd8f9392e, 0x52caef06, 0x53199479, 0xdf2be64b, 0xbaab008c, 0xa8a06fda,
	0xce9ce704, 0x89845a08, 0x2ba36d61, 0x1e99f2fb, 0xe724246d, 0x18b54e33, 0x5cac0dd1, 0xab9dfd79,
	0x88a4b0c4, 0x558aa119, 0x417720b6, 0xe150ce2b, 0x927d48d7, 0x256e445e, 0x333cb757, 0x2b3bd00f,
	0xb2746043, 0x189cac11, 0x6cedc7e7, 0x71ae0358, 0xff752a3a, 0x6b6c79a5, 0x8a9a549b, 0x50c58706,
	0x90755c35, 0xe4e36b52, 0x9038ca73, 0x3fd1aaa8, 0xdab40133, 0xd80320e0, 0x790968c7, 0x6546b993,
	0xf6c8ff3b, 0x2542750d, 0xa1ffada7, 0xb7473178, 0x2e330ef7, 0xd92c43be, 0x1ad8c50a, 0x8eae20a5,
	0x556cbdd1, 0xf24c9997, 0x2cb03c73, 0x006f5c08, 0xa4e220e7, 0x4abc1791, 0x51412b1e, 0x2dd60a08,
	0xa11b02e8, 0xd70d7d71, 0x64583301, 0x1bf60945, 0x507f1a32, 0x721ac08a, 0xedc2661d, 0xa91839d1,
	0x46a2a4c4, 0x25c0ffb8, 0x7085f9b0, 0xe09b94b1, 0x46a9a478, 0x3908f3f2, 0x67a78c59, 0x430485ed,
	0x89205b36, 0xb66a57e7, 0x56e00652, 0x23670282, 0x87f8c1d6, 0x95df88c6, 0x0fe07528, 0xfcbe915c,
	0x7bf23382, 0xea293fa2, 0xda1577f9, 0xcac299bb, 0x7b4beeaf, 0xef9628c3, 0xebeaf871, 0x75c6a1f8,
	0xbdd07be3, 0x07fa1bfa, 0x9aeff794, 0xc19dfc36, 0x5f447527, 0xdea110f4, 0x208b941a, 0xa7d18538,
	0x0478aa52, 0x0e3fe233, 0x5a322edf, 0x147bbdb5, 0x27aa2ad3, 0xcb0f7d6e, 0xd381cd6a, 0xc35a1d24,
};

static const uint64_t ln2 = 0xb17217f7d1cf79ab;

static uint64_t sumsbox(uint64_t x) {
	uint8_t bytes[8];
	memcpy(bytes, &x, 8);

	uint32_t s0 = 0, s1 = 0;
	for (int i = 0; i < 4; ++i) {
		s0 += sbox[bytes[i + 0]];
		s1 += sbox[bytes[i + 4]];
	}

	return (uint64_t) s0 | (uint64_t) s1 << 32;
}

static uint64_t interlace(uint64_t x) {
	uint64_t t = x;

	uint8_t* xp = (uint8_t*) &x;
	uint8_t* tp = (uint8_t*) &t;

	for (int i = 0; i < 4; ++i) {
		xp[i * 2 + 0] = tp[i + 0];
		xp[i * 2 + 1] = tp[i + 4];
	}

	return x;
}

static uint64_t rotate(uint64_t x) {
	uint32_t a = x & 0xffffffff, b = x >> 32;

	a = a << 5 | a >> 27;
	b = b >> 5 | b << 27;

	return (uint64_t) a | (uint64_t) b << 32;
}

static uint64_t hash(uint64_t x, const void* key) {
	const uint8_t* keybytes = key;

	uint64_t k;

	memcpy(&k, keybytes, 8);
	x = sumsbox(x) ^ k;

	memcpy(&k, keybytes + 8, 8);
	x = sumsbox(interlace(x)) ^ k;

	memcpy(&k, keybytes + 16, 8);
	x = sumsbox(rotate(x)) ^ k;

	memcpy(&k, keybytes + 24, 8);
	x = sumsbox(interlace(x)) ^ k;

	return ~(x + ln2);
}

static void sumsboxkey(uint8_t* key) {
	uint32_t s[8] = { 0 };
	for (int i = 0; i < 4; ++i)
		for (int j = 0; j < 8; ++j)
			s[j] += sbox[key[j * 4 + i]];
		
	memcpy(key, s, 32);
}

static void interlacekey8(uint8_t* key) {
	uint8_t t[32];
	memcpy(t, key, 32);

	for (int i = 0; i < 4; ++i) {
		key[i * 4 +  0] = t[i +  0];
		key[i * 4 +  1] = t[i +  4];
		key[i * 4 +  2] = t[i +  8];
		key[i * 4 +  3] = t[i + 12];
		key[i * 4 + 16] = t[i + 16];
		key[i * 4 + 17] = t[i + 20];
		key[i * 4 + 18] = t[i + 24];
		key[i * 4 + 19] = t[i + 28];
	}
}

static void interlacekey16(uint8_t* key) {
	uint16_t t[16];
	memcpy(t, key, 32);

	uint16_t* pk = (uint16_t*) key; // Hopefully the key is aligned to a 2-byte boundary
	for (int i = 0; i < 4; ++i) {
		pk[i * 4 + 0] = t[i +  0];
		pk[i * 4 + 1] = t[i +  4];
		pk[i * 4 + 2] = t[i +  8];
		pk[i * 4 + 3] = t[i + 12];
	}
}

static void nextkey(const uint8_t* prev, uint8_t* next) {
	memcpy(next, prev, 32);

	sumsboxkey(next);
	interlacekey8(next);
	sumsboxkey(next);
	interlacekey16(next);
	sumsboxkey(next);
}

static void lastround(uint64_t* l, uint64_t* r, const void* key) {
	*l ^= hash(*r, key);
}

static void roundfun(uint64_t* l, uint64_t* r, const void* key) {
	lastround(l, r, key);

	*l ^= *r;
	*r ^= *l;
	*l ^= *r;
}

void dove_init_keychain(const void* key_, void* keychain_, size_t rounds) {
	assert(key_);
	assert(keychain_);
	assert(rounds);

	const uint8_t* key = key_;
	uint8_t* keychain = keychain_;

	memcpy(keychain, key, 32);

	for (size_t i = 1; i < rounds; ++i)
		nextkey(keychain + (i - 1) * 32, keychain + i * 32);
}

void dove_encrypt(const void* keychain_, void* block_, size_t rounds) {
	assert(keychain_);
	assert(block_);
	assert(rounds);

	const uint8_t* keychain = keychain_;
	uint64_t* block = block_; // Hopefully aligned

	for (size_t i = 0; i < rounds - 1; ++i)
		roundfun(block + 0, block + 1, keychain + i * 32);
	lastround(block + 0, block + 1, keychain + (rounds - 1) * 32);
}

void dove_decrypt(const void* keychain_, void* block_, size_t rounds) {
	assert(keychain_);
	assert(block_);
	assert(rounds);

	const uint8_t* keychain = keychain_;
	uint64_t* block = block_; // Hopefully aligned

	for (size_t i = rounds - 1; i >= 1; --i)
		roundfun(block + 0, block + 1, keychain + i * 32);
	lastround(block + 0, block + 1, keychain);
}

#ifndef NDEBUG
void dove_test(void) {
	// In theory, if all the normal functions work fine, the rest of the code
	// should as well

	//   01 23 45 67 = 0x8aed2a6a + 0x835fd1a0 + 0x061b6472 + 0xbed0c62b
	// = 0xd33926a7
	// 89 ab cd ef = 0xf33fb1c6 + 0xe150ce2b + 0x4abc1791 + 0x75c6a1f8
	// = 0x9513397a
	assert(sumsbox(0x0123456789abcdef) == 0xd33926a79513397a);

	// 01 23 45 67 -,
	// 89 ab cd ef -'
	// 01 89 23 ab 45 cd 67 ef
	assert(interlace(0x0123456789abcdef) == 0x018923ab45cd67ef);

	//   01234567 >> 5
	// = 70123456 >> 1
	// = 38091a2b
	//   89abcdef << 5
	// = 9abcdef8 << 1
	// = 3579bdf1
	assert(rotate(0x0123456789abcdef) == 0x38091a2b3579bdf1);

	const uint32_t result[8] = { 0x4a3a8cc0, 0x4a3a8cc0, 0x4a3a8cc0, 0x4a3a8cc0, 0x6418fa81, 0x6418fa81, 0x6418fa81, 0x6418fa81 };
	uint32_t key[8] = { 0x01020304, 0x01020304, 0x01020304, 0x01020304, 0x05060708, 0x05060708, 0x05060708, 0x05060708 };

	sumsboxkey((uint8_t*) key);
	assert(!memcmp(key, result, 32));

	uint8_t normal8[32] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
	};
	const uint8_t inter8[32] = {
		// 0x00, 0x01, 0x02, 0x03 || 0x04, 0x05, 0x06, 0x07 || 0x08, 0x09, 0x0a, 0x0b || 0x0c, 0x0d, 0x0e, 0x0f
		0x00, 0x04, 0x08, 0x0c, 0x01, 0x05, 0x09, 0x0d, 0x02, 0x06, 0x0a, 0x0e, 0x03, 0x07, 0x0b, 0x0f,
		// 0x00, 0x10, 0x20, 0x30 || 0x40, 0x50, 0x60, 0x70 || 0x80, 0x90, 0xa0, 0xb0 || 0xc0, 0xd0, 0xe0, 0xf0,
		0x00, 0x40, 0x80, 0xc0, 0x10, 0x50, 0x90, 0xd0, 0x20, 0x60, 0xa0, 0xe0, 0x30, 0x70, 0xb0, 0xf0,
	};

	interlacekey8(normal8);
	assert(!memcmp(normal8, inter8, 32));

	uint16_t normal16[16] = {
		0x0000, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777,
		0x8888, 0x9999, 0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff,
	};
	uint16_t inter16[16] = {
		0x0000, 0x4444, 0x8888, 0xcccc, 0x1111, 0x5555, 0x9999, 0xdddd,
		0x2222, 0x6666, 0xaaaa, 0xeeee, 0x3333, 0x7777, 0xbbbb, 0xffff,
	};

	interlacekey16((uint8_t*) normal16);
	assert(!memcmp(normal16, inter16, 32));
}
#endif
