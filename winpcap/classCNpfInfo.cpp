/*網卡信息類CNpfInfo定義*/

class CNpfInfo
{
public:
	CNpfInfo();		//構造函數
	~CNpfInfo();	//析構函數
	int GetAdpaterCount();	//獲得當前網卡數目

	//獲得網卡名稱
	//參數:	nAdapter: 網卡編號
	LPCSTR GetAdapterName(int nAdapter);

	//獲得網卡描述
	//參數:	nAdapter: 網卡編號
	LPCSTR GetAdapterDescription(int nAdapter);

	//獲得所有網卡信息
	BOOL GetAdapterInfo();

	//根據網卡MAC位址打開網卡並得到操作信息
	struct _ADAPTER* GetAdapter(ETHERNET_ADDRESS macAddress);

	//根據網卡編號打開網卡並得到操作信息
	struct _ADAPTER* GetAdapter(LPCSTR pszAdapter, ETHERNET_ADDRESS &macAddress);

protected:
	//網卡信息
	EcAdapterInfo	m_pAdapterInfo[MAX_NUM_ADAPTER];
	int				m_nADapter;		//網卡數目
};