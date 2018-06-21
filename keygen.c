#include <stdio.h>
#include <openssl/md5.h>
#include <windows.h>


void init_N_hash(const char * name, unsigned char name_len, char dest_hash[0x10]);
void init_K_hash_2nd(const char src_hash[16], char dest_hash[0x10]);
void MD5_and_XOR(char hash_buffer[16]);
void get_K_hash_1st_quarter(const char in[4], char out[3]);
void get_K_hash_1st(const char *key, char custom_hash[16]);
void brute_key_1st_half(char key[16], char K_hash_1st[16], char K_hash_2nd[16], char N_hash[6]);
void brute_key_quarter(const char * in_3chars, char * out_4chars);
void brute_key_1st_half_mt(char * key_1st_half);

static char base64_for_brute[63] = { '/',
									'0', '1', '2', '3','4', '5', '6', '7', '8', '9',
									'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H','I', 'J',
									'K', 'L', 'M', 'N', 'O', 'P','Q', 'R', 'S', 'T',
									'U', 'V', 'W', 'X','Y', 'Z',
									'a', 'b', 'c', 'd', 'e', 'f','g', 'h', 'i', 'j',
									'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
									'u', 'v', 'w', 'x', 'y', 'z' };

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
char hrdcd_bytes[6] = { 0xE9, 0x85, 0x5D, 0x5B, 0x2F, 0x41 };


char * name;
char N_hash[16] = { 0 };

char key[17] = { 0 };  // 16 base64alphabet chars
char K_hash_1st[16] = { 0 }; // 12 bytes + 0,0,0,0
char K_hash_2nd[16] = { 0 };

unsigned int solution_founded = 0;


int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("[!] Usage: keygen.exe name\n");
		ExitProcess(1);
	}
	name = argv[1];
	if (strlen(name) <= 4) {
		printf("[!] Name is too short. It`s length should be minimum 5 chars.\n");
		ExitProcess(2);
	}
	if (strlen(name) > 255) {
		printf("[!] Name is too long. It`s length should be maximum 255 chars.\n");
		ExitProcess(2);
	}
	for (int i = 0; name[i]; i++) {
		if (name[i] < 'a' || name[i] > 'z') {
			printf("[!] Name should contains only lowercase letters in range 'a'-'z'.\n");
			ExitProcess(3);
		}
	}

	printf("Provided name : %s\n", name);

	// N hash
	init_N_hash(name, strlen(name), N_hash);
	for (int i = 0; i < 1000; i++)
		MD5_and_XOR(N_hash);

	/*1st  C H E C K  :: N_hash[0:6] == K_hash_1st[6:12]
	source info:
		N_hash[0:6] == K_hash_1st[6:12]
		BuffK[8:16] -> K_hash_1st[6:12]
	consequently:
		BuffK[8:16] -> N_hash[0:6]
	consequently:
		BuffK[ 8:12] -> N_hash[0:3]
		BuffK[12:16] -> N_hash[3:6]
	*/
	brute_key_quarter(N_hash + 0, key + 8);
	brute_key_quarter(N_hash + 3, key + 12);

	/*2nd  C H E C K  :: K_hash_2nd[0:6] == HardcodedHashBytes[0:6]*/
	/*multithreading Brute*/
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo); // DWORD dwNumberOfProcessors = siSysInfo.dwNumberOfProcessors

	char *initial_key_1st_halfs = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8 * siSysInfo.dwNumberOfProcessors);
	HANDLE *h2thread_arr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HANDLE)*siSysInfo.dwNumberOfProcessors);
	DWORD *thread_ID_arr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DWORD)*siSysInfo.dwNumberOfProcessors);
	if (!initial_key_1st_halfs || !h2thread_arr || !thread_ID_arr) {
		fprintf(stderr, "[!] Error on dynamic memory allocation.\n");
		ExitProcess(4);
	}

	for (int i = 0; i < siSysInfo.dwNumberOfProcessors; i++) {
		memset(initial_key_1st_halfs + i * 8, '/', 8);
		(initial_key_1st_halfs + i * 8)[0] = '.';
		(initial_key_1st_halfs + i * 8)[7] = base64_for_brute[sizeof(base64_for_brute) / siSysInfo.dwNumberOfProcessors * i];
		h2thread_arr[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)brute_key_1st_half_mt, initial_key_1st_halfs + i * 8, 0, &thread_ID_arr[i]);
	}

	WaitForMultipleObjects(siSysInfo.dwNumberOfProcessors, h2thread_arr, TRUE, INFINITE);

	free(thread_ID_arr);
	free(h2thread_arr);
	free(initial_key_1st_halfs);

	/*onethread Brute*/
	//brute_key_1st_half(key, K_hash_1st, K_hash_2nd, N_hash);

	printf("Key : %s\n", key);
	return 0;
}

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

void init_K_hash_2nd(const char src_hash[16], char dest_hash[0x10]) {
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

void MD5_and_XOR(_Inout_ char hash_buffer[16]) {
	char md5[MD5_DIGEST_LENGTH] = { 0 };
	MD5((const unsigned char *)hash_buffer, 16, (unsigned char *)md5);
	for (int i = 0; i < 16; i++)
		hash_buffer[i] ^= md5[i];
	return;
}

void get_K_hash_1st_quarter(const char in[4], char out[3]) {
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

void get_K_hash_1st(const char *key, char custom_hash[16]) {
#define KEY_LEN 16
#define HASH_LEN 12
	for (int i = 0, n = 0; i < KEY_LEN, n < HASH_LEN; i = i + 4, n = n + 3) {
		get_K_hash_1st_quarter(key + i, custom_hash + n);
	}
}

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

void brute_key_1st_half(char key[16], char K_hash_1st[16], char K_hash_2nd[16], const char N_hash[6]) {
	//init key local copy
	char key_lc[16] = { 0 };
	memcpy(key_lc, key, 16);
	char key_1st_half[8] = { '.','/','/','/','/','/','/','/' };
	UINT64 * pK_1kst_half = (UINT64 *)key_1st_half;
	// K_hash_1st[6:12] = N_hash[0:6]
	memcpy(K_hash_1st + 6, N_hash, 6);

	do {
		// increment searched value
	INCREMENT:	(*pK_1kst_half)++;
		for (int i = 0; i < sizeof(key_1st_half); i++) {   // Acceptable ranges :'/'-'9', 'A'-'Z', 'a'-'z'
			if (key_1st_half[i] < '/' || key_1st_half[i] > 'z' ||
				(key_1st_half[i] > '9' && key_1st_half[i] < 'A') ||
				(key_1st_half[i] > 'Z' && key_1st_half[i] < 'a')
				) {
				goto INCREMENT;
			}
		}
		memcpy(key_lc, key_1st_half, 8);

		// calculate K_hash_1st
		/*get_K_hash_1st(key_lc, K_hash_1st);*/
		get_K_hash_1st_quarter(key_lc + 0, K_hash_1st + 0);
		get_K_hash_1st_quarter(key_lc + 4, K_hash_1st + 3);

		// calculate 2nd K hash
		init_K_hash_2nd(K_hash_1st, K_hash_2nd);
		for (int i = 0; i < 1000; i++)
			MD5_and_XOR(K_hash_2nd);
	} while (!(
		// K_hash_2nd[0:6] == HardcodedHashBytes[0:6]:
		hrdcd_bytes[0] == K_hash_2nd[0] &&
		hrdcd_bytes[1] == K_hash_2nd[1] &&
		hrdcd_bytes[2] == K_hash_2nd[2] &&
		hrdcd_bytes[3] == K_hash_2nd[3] &&
		hrdcd_bytes[4] == K_hash_2nd[4] &&
		hrdcd_bytes[5] == K_hash_2nd[5]
		));

	memcpy(key, key_lc, 16);
}

void brute_key_1st_half_mt(char * key_1st_half) {
	//init local key copy
	char lc_key[16] = { 0 };
	memcpy(lc_key, key, 16);
	//init local K_hash_1st copy
	char lc_K_hash_1[16] = { 0 }; // 12 bytes + 0,0,0,0
	memcpy(lc_K_hash_1, K_hash_1st, 16);
	//init local K_hash_2nd copy
	char lc_K_hash_2[16] = { 0 };
	memcpy(lc_K_hash_2, K_hash_2nd, 16);

	UINT64 * pK_1st_half = (UINT64 *)key_1st_half;

	// K_hash_1st[6:12] = N_hash[0:6]
	memcpy(lc_K_hash_1 + 6, N_hash, 6);

	do {
		// increment searched value
	INCREMENT:	(*pK_1st_half)++;
		for (int i = 0; i < 8; i++) {   // Acceptable ranges :'/'-'9', 'A'-'Z', 'a'-'z'
			if (key_1st_half[i] < '/' || key_1st_half[i] > 'z' ||
				(key_1st_half[i] > '9' && key_1st_half[i] < 'A') ||
				(key_1st_half[i] > 'Z' && key_1st_half[i] < 'a')
				) {
				goto INCREMENT;
			}
		}
		memcpy(lc_key, key_1st_half, 8);

		// calculate K_hash_1st
		/*get_K_hash_1st(key_lc, K_hash_1st);*/
		get_K_hash_1st_quarter(lc_key + 0, lc_K_hash_1 + 0);
		get_K_hash_1st_quarter(lc_key + 4, lc_K_hash_1 + 3);

		// calculate 2nd K hash
		init_K_hash_2nd(lc_K_hash_1, lc_K_hash_2);
		for (int i = 0; i < 1000; i++)
			MD5_and_XOR(lc_K_hash_2);

		if (hrdcd_bytes[0] == lc_K_hash_2[0] && hrdcd_bytes[1] == lc_K_hash_2[1] && hrdcd_bytes[2] == lc_K_hash_2[2] && hrdcd_bytes[3] == lc_K_hash_2[3] && hrdcd_bytes[4] == lc_K_hash_2[4] && hrdcd_bytes[5] == lc_K_hash_2[5]) {
			solution_founded = 1;
			memcpy(key, lc_key, 16);
			return;
		}

	} while (!solution_founded);
	return;
}
