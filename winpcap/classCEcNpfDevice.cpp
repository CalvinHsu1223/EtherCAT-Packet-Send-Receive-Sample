/*網卡操作類CEcNpfDevice類定義*/
class CEcNpfDevice
{
public:
	//參數 macAdapter: 通信的網卡MAC位址
	CEcNpfDevice(ETHERNET_ADDRESSmacAdapter = NullEthernetAddress);

	//參數 pszAdapter: 通信網卡的名稱
	CEcNpfDevice(LPCSTR pszAdapter);

	virtual ~CEcNpfDevice();
	//IUnknown
	virtual ULONG STDMETHODCALLTYPE Release(void);

	//打開所選擇的網卡，返回執行結果
	virtual HRESULT Open();

	//關閉所選擇的網卡，返回執行結果
	virtual HRESULT Close();

	//獲得鏈接波特率
	virtual ULONG GetLinkSpeed();

	//向所選用網卡發送一個數據包，並返回調用結果
	//參數 pData: 要發送數據的指標
	//參數 nData: 發送數據的字節數
	virtual long SendPacket(PVOID pData, ULONG nData);

	//從所接收到的訊框緩存區得到一個訊框，並返回調用結果
	//參數 pData: 接收的數據保存在pData指標指向的空間中
	virtual long CheckRecvFrame(PBYTE pData);


protected:
	//從所選網卡讀取訊框，保存在fifo列表m_listPacket中
	virtual long ReadPackets();

	LPSTR				m_pszAdapter;	//選用的網卡名稱
	ETHERNET_ADDRESS	m_macAdapter;	//選用的網卡MAC位址


private:
	//創建一個執行緒，從網卡接收乙太封包，並返回調用結果
	//參數: nPriority: 執行緒的優先級
	long StartReceiverThread(long nPriority = THREAD_PRIORITY_HIGHEST);

	//執行緒函數，返回調用結果
	//參數: lpParameter: 執行緒參數
	static DWORD WINAPI ReceiverThread(LPVOID lpParameter);

	HANDLE				m_hStartEvent;
	HANDLE				m_hCloseEvent;
	HANDLE				m_hReceiverThread;	//接收執行緒
	DWORD				m_dwThreadId;
	bool				m_bStopReceiver;	//運行標誌
	long				m_lRef;
	struct _ADAPTER*	m_pAdapter;			//選甕的網卡操作信息
	CFiFoList<PVOID, MAX_NPFPACKETS>m_listPacket;	//接收緩存列表，先入先出
};

