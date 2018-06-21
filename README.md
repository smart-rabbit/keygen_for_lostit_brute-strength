KeygenMe "Psychic powers or brute strength your choice" ([task source](https://forum.tuts4you.com/topic/37904-keygenme-01-psychic-powers-or-brute-strength-your-choice)) **solution** based on **multithreaded brute-force**

**CAUTION**: _This solution is far from elegance. You processor will burn :)_

### Program flow explanation

program accept:
	```5 <= len(NAME) < 256```
	```16 <= len(KEY) < 256```
it lowercase all `NAME` chars, and  delete from name all non `a`-`z` chars. Then it delete all non base64-alphabet chars from KEY, and check if `len(KEY) == 16`
Lets consider `NAME` as string with length 5 or greater, and which consist from 'a'-'z' chars.
Lets consider `KEY` as string with length 16, and which consist from base64-alphabet chars (`+,/',0-9,A-Z,a-z`).

Then program compare if NAME:KEY pair is not 
+ "lostit":"_RY5obY7IduF4Se2T_"
+ "tutsyou":"_RkIomczPYHNrJoCA_"

which are valid NAME:KEY pairs, but for some reason blacklisted in such way.

Now your program begin to calculate different hashes and make different checks.

**FIRST HASH**: hash retrieved from `KEY`, lets give him a name `K_hash_1`. `K_hash_1` is 12-byte hash, each 4 bytes of `KEY` converted to 3 bytes of `K_hash_1` . Below code snippet explain this transformation, consider `get_K_hash_1()` function:
```C
char base64alphabet_map[] = {
	/* 01*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 10*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 20*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 30*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 40*/ 0, 0, 0,62, 0, 0, 0,63,51,53,/*43:+,47:/,48:0*/
	/* 50*/54,55,56,57,58,59,60,61, 0, 0,
	/* 60*/ 0, 0, 0, 0, 0, 0, 1, 2, 3, 4,/*65:A*/
	/* 70*/ 5, 6, 7, 8, 9,10,11,12,13,14,
	/* 80*/15,16,17,18,19,20,21,22,23,24,
	/* 90*/25, 0, 0, 0, 0, 0, 0,26,27,28,/*90:Z,97:a*/
	/*100*/29,30,31,32,33,34,35,36,37,38,
	/*110*/39,40,41,42,43,44,45,46,47,48,
	/*120*/49,50,51, 0, 0, 0, 0, 0, 0, 0/*122:z*/
};


void get_K_hash_1_quarter(const char in[4], char out[3]) {
	unsigned int c0 = base64alphabet_map[in[0]];
	unsigned int c1 = base64alphabet_map[in[1]];
	unsigned int c2 = base64alphabet_map[in[2]];
	unsigned int c3 = base64alphabet_map[in[3]];

	unsigned int hash_chunk = (((((c0 << 6) + c1) << 6) + c2) << 6) + c3;

	unsigned int temp_hash;
	temp_hash = hash_chunk >> 16;
	out[0] = (char)temp_hash;
	temp_hash = hash_chunk >> 8;
	out[1] = (char)temp_hash;
	out[2] = (char)hash_chunk;
}

void get_K_hash_1(const char *key, char custom_hash[16]) {
	for (int i = 0, n = 0; i < KEY_LEN, n < HASH_LEN; i = i + 4, n = n + 3) {
		get_K_hash_1_quarter(key + i, custom_hash + n);
	}
}
```

**SECOND HASH**: 2nd 16-byte hash, which is retrieved from `K_hash_1`, lets name it `K_hash_2`.
`K_hash_2` initilized using function in listing below.
```C
void init_K_hash_2(const char src_hash[16], char dest_hash[0x10]) {
	dest_hash[0x0] = src_hash[0];
	dest_hash[0x1] = src_hash[1];
	dest_hash[0x2] = src_hash[2];
	dest_hash[0x3] = src_hash[3];
	dest_hash[0x4] = src_hash[4];
	dest_hash[0x5] = src_hash[5];

	dest_hash[0x6] = src_hash[0];
	dest_hash[0x7] = src_hash[1];
	dest_hash[0x8] = src_hash[2];
	dest_hash[0x9] = src_hash[3];
	dest_hash[0xA] = src_hash[4];
	dest_hash[0xB] = src_hash[5];

	dest_hash[0xC] = src_hash[0];
	dest_hash[0xD] = src_hash[1];
	dest_hash[0xE] = src_hash[2];
	dest_hash[0xF] = src_hash[3];
}
```
Then `K_hash_2`  is used as input string to calculate MD5 hash. `K_hash_2` is XOR-ed with resulting hash. See code below:
```C
#include <openssl/md5.h>

void _cdecl MD5_and_XOR(char hash_buffer[16]) {
	char md5[MD5_DIGEST_LENGTH] = { 0 };
	MD5((const unsigned char *)hash_buffer, 16, (unsigned char *)md5);
	for (int i = 0; i < 16; i++)
		hash_buffer[i] ^= md5[i];
	return;
}
```
This operation repeated 1000 times.

**THIRD HASH**: getting 16-byte hash from `NAME`, lets name it `N_hash`.
`N_hash` initilized using function in listing below.
```C
void init_N_hash(const char * name, unsigned char name_len, char dest_hash[0x10]) {
	if (name_len <= 0x10) {
		for (int i = 0; i < 0x10; i++) {
			dest_hash[i] = name[i % name_len];
		}
	}
	if (name_len > 0x10) {
		memcpy(dest_hash, name, 0x10);
		for (int i = 0; i < name_len - 0x10; i++)
			dest_hash[i % 0x10] ^= name[i + 0x10];
	}
}
```
,then  `N_hash`  is hashed with MD5 and XOR-ed 1000 times in the same way as K_hash_2  (discribed above).

**1ST CHECK**:  
Note: python lists used for below pseudocode
```python
N_hash[0:6] == K_hash_1[6:12]
```

**2ND CHECK**:
```python
K_hash_2[0:6] == [0xE9, 0x85, 0x5D, 0x5B, 0x2F, 0x41]
```

### Checks bypass
**1ST CHECK**:  
we have `NAME`, we can produce `N_hash`, `N_hash[0:6]`  according to 1st check conditions should be equal to `K_hash_1[6:12]`, from `K_hash_1[6:12]` we can easely get 2nd part of `KEY[8:16]`.
Below code of function that help us retrieve `KEY[8:12]` from `N_hash[0:3]` and `KEY[12:16]` from `N_hash[3:6]`.
```C
void brute_key_quarter(const char * in_3chars, char * out_4chars) {
	/*Brute-force init*/
	char input[4] = { '.','/' ,'/' ,'/' }; 	// '/'-'9', 'A'-'Z', 'a'-'z'
	unsigned int* p2input_as_dw = (unsigned int*)input;
	char output[3] = { 0 };
	/*Brute-force loop*/
	do {
	START:
		(*p2input_as_dw)++;
		for (int i = 0; i < 4; i++) {
			if (
				!(input[i] >= '/' && input[i] <= '9') &&
				!(input[i] >= 'A' && input[i] <= 'Z') &&
				!(input[i] >= 'a' && input[i] <= 'z')
				) {
				goto START;
			}
		}
		get_K_hash_1st_quarter(input, output);
	} while (
		!(output[0] == in_3chars[0] && output[1] == in_3chars[1] && output[2] == in_3chars[2])
		);
	/*Brute-force end*/
	out_4chars[0] = input[0];
	out_4chars[1] = input[1];
	out_4chars[2] = input[2];
	out_4chars[3] = input[3];
};
```

**2ND CHECK**:  
we have 2nd 8-bytes of `KEY`, we could try to brute 1st 8-bytes of `KEY` and pass this check.

Repository contains multithreaded bruter, brute threads quantity is equal to quantity of cores on your PC .
