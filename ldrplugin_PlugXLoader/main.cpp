#include "plugin.h"

#include "helper.h"

// Static key
#define PLUGX_CONFKEY 0xBEEFCACE

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// IDA defs.h macros
#define HIBYTE(x) (*((unsigned char*)&(x)+3))
#define BYTEn(x, n) (*((unsigned char*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define BYTE2(x)   BYTEn(x,  2)
#define BYTE3(x)   BYTEn(x,  3)
#define BYTE4(x) BYTEn(x, 4)



static char* pluginName = "PlugX Runner @immortalp0ny";
static char* pluginVersion = "1.0";

PluginLogger* plgxRunLogger = getLogger("RPLGX");

static std::string configPath;
static int code;

static PluginDescriptor* plgd;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	return TRUE;
}

typedef NTSTATUS (__stdcall *t_RtlCompressBuffer)(
	USHORT CompressionFormatAndEngine,
	PUCHAR UncompressedBuffer,
	ULONG  UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG  CompressedBufferSize,
	ULONG  UncompressedChunkSize,
	PULONG FinalCompressedSize,
	PVOID  WorkSpace
);

typedef NTSTATUS (__stdcall *t_RtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
);

typedef struct _PlugxShellcodeArgument
{
	void* pMpImageBase;
	size_t cbMpImage;

	void* pMpOffset;
	size_t cbMp;

	void* pCfg;
	size_t cbCfg;

	unsigned int runCode;

} PlugxShellcodeArgument;

int cryptRawData(unsigned char *pData, int cbData, int key)
{
	
	unsigned int add_key = key ^ 0x13353E4; // v5
	unsigned int sub_key = key ^ 0x139;	   // v6
	
	for (int i = 0; i < cbData; i++)
	{
		add_key += 0x655;
		sub_key -= 0x6697;
		unsigned char c = ((BYTE2(sub_key) ^ (((sub_key & 0xFF) ^ ((BYTE2(add_key) ^ ((add_key & 0xFF) - BYTE1(add_key))) - HIBYTE(add_key))) - BYTE1(sub_key))) - HIBYTE(sub_key));
		pData[i] ^= c;
	}
	return 0;
}


bool encodeConfiguration(void* data, size_t cbData, void** encodedData, size_t* cbEncodedData)
{
	HMODULE hNtdll = GetModuleHandle("ntdll.dll");
	if (hNtdll == NULL)
		return false;

	t_RtlCompressBuffer pfnRtlCompressBuffer = (t_RtlCompressBuffer)GetProcAddress(hNtdll, "RtlCompressBuffer");
	if (pfnRtlCompressBuffer == NULL)
		return false;

	t_RtlGetCompressionWorkSpaceSize pfnRtlGetCompressionWorkSpaceSize = (t_RtlGetCompressionWorkSpaceSize)GetProcAddress(hNtdll, "RtlGetCompressionWorkSpaceSize");
	if (pfnRtlGetCompressionWorkSpaceSize == NULL)
		return false;

	unsigned int compressBufferWorkSpaceSize = NULL;
	unsigned int compressFragmentWorkSpaceSize = NULL;
	if (!NT_SUCCESS(pfnRtlGetCompressionWorkSpaceSize(2, (PULONG)&compressBufferWorkSpaceSize, (PULONG)&compressFragmentWorkSpaceSize)))
	{
		return false;
	}

	char* pWorkspaceBuffer = new char[compressBufferWorkSpaceSize];

	char compressedData[0x4000];
	unsigned int compressedSize = NULL;
	if (!NT_SUCCESS(pfnRtlCompressBuffer(2, (PUCHAR)data, cbData, (PUCHAR)compressedData, 0x4000, 4096, (PULONG)&compressedSize, (PVOID)pWorkspaceBuffer)))
	{
		return false;
	}
	delete[] pWorkspaceBuffer;

	int key = PLUGX_CONFKEY;
	int encodedDataSize = compressedSize + 0x08;

	char* preparedCompressedData = new char[compressedSize + 4];
	memcpy(preparedCompressedData, &cbData, 4);
	memcpy(preparedCompressedData + 4, compressedData, compressedSize);

	cryptRawData((unsigned char*)preparedCompressedData, compressedSize + 4, key);

	char* preparedData = new char[encodedDataSize + 4];

	memcpy(preparedData, &encodedDataSize, 4);
	memcpy(preparedData + 4, &key, 4);
	memcpy(preparedData + 8, preparedCompressedData, compressedSize + 4);

	std::stringstream ss;
	std::string strMessage;

	ss.str(std::string());
	ss << "Full encoded config size: " << std::hex << encodedDataSize;
	strMessage = ss.str();
	plgxRunLogger->logInfoMessage(strMessage);

	ss.str(std::string());
	ss << "Compressed config size: " << std::hex << compressedSize;
	strMessage = ss.str();
	plgxRunLogger->logInfoMessage(strMessage);

	ss.str(std::string());
	ss << "Key: " << std::hex << key;
	strMessage = ss.str();
	plgxRunLogger->logInfoMessage(strMessage);

	ss.str(std::string());
	ss << "Uncompressed config size: " << std::hex << cbData;
	strMessage = ss.str();
	plgxRunLogger->logInfoMessage(strMessage);

	

	*encodedData = preparedData;
	*cbEncodedData = cbData;
	delete[] preparedCompressedData;
	return true;
}



PLDR_EXPORT plugin_Init(PluginDescriptor* pPlugin, unsigned int argc, char** argv)
{
	plgd = pPlugin;
	pPlugin->pluginType = PLDRT_DllPlugin;
	pPlugin->pluginName = pluginName;
	pPlugin->pluginVersion = pluginVersion;
	pPlugin->pfnGetLpReserved = plugin_GetLpReserved;

	if (argc < 3)
	{
		std::string m("To few args. Usage: <path to PlugX config> <run code>");
		plgxRunLogger->logErrorMessage(m);
		return PLDRR_ERROR;
	}

	code = atoi(argv[2]);
	configPath.insert(0, argv[1]);

	return PLDRR_SUCCESS;
}

PLDR_EXPORT plugin_Release(PluginDescriptor* pPlugin)
{
	return PLDRR_SUCCESS;
}


PLDR_EXPORT plugin_GetLpReserved(PLDR_LpReserved__inType pReserved, LDRP_LOADED_PE* pLoadedPe)
{
	std::string errorMessage;
	char* targetData = NULL;
	unsigned int cbTargetData = NULL;



	std::stringstream ss;
	std::string strMessage;
	ss.str(std::string());
	ss << "Read PlugX configuration file from " << configPath;
	strMessage = ss.str();
	plgxRunLogger->logImportantMessage(strMessage);

	if (!readall(configPath, &targetData, &cbTargetData, errorMessage))
	{
		plgxRunLogger->logErrorMessage(errorMessage);
		return PLDRR_IGNORE;
	}



	PlugxShellcodeArgument* pPSA = new PlugxShellcodeArgument();

	pPSA->pMpImageBase = 0x0;
	pPSA->cbMpImage = 0x0;

	pPSA->pMpOffset = pLoadedPe->imageBase;
	pPSA->cbMp = pLoadedPe->imageSize;

	void* pEncodedConfig = NULL;
	size_t cbEncodedCnfig = NULL;
	if (!encodeConfiguration(targetData, cbTargetData, &pEncodedConfig, &cbEncodedCnfig))
	{
		ss.str(std::string());
		ss << "Failed perform encryption of config data" << configPath;
		strMessage = ss.str();
		plgxRunLogger->logWarningMessage(strMessage);
		delete pPSA;
		delete[] pEncodedConfig;
		return PLDRR_IGNORE;
	}

	pPSA->pCfg = pEncodedConfig;
	pPSA->cbCfg = cbEncodedCnfig;

	pPSA->runCode = code;

	*pReserved = pPSA;

	return PLDRR_SUCCESS;
}