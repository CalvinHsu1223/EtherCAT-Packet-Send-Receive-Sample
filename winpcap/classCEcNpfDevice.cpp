/*���d�ާ@��CEcNpfDevice���w�q*/
class CEcNpfDevice
{
public:
	//�Ѽ� macAdapter: �q�H�����dMAC��}
	CEcNpfDevice(ETHERNET_ADDRESSmacAdapter = NullEthernetAddress);

	//�Ѽ� pszAdapter: �q�H���d���W��
	CEcNpfDevice(LPCSTR pszAdapter);

	virtual ~CEcNpfDevice();
	//IUnknown
	virtual ULONG STDMETHODCALLTYPE Release(void);

	//���}�ҿ�ܪ����d�A��^���浲�G
	virtual HRESULT Open();

	//�����ҿ�ܪ����d�A��^���浲�G
	virtual HRESULT Close();

	//��o�챵�i�S�v
	virtual ULONG GetLinkSpeed();

	//�V�ҿ�κ��d�o�e�@�Ӽƾڥ]�A�ê�^�եε��G
	//�Ѽ� pData: �n�o�e�ƾڪ�����
	//�Ѽ� nData: �o�e�ƾڪ��r�`��
	virtual long SendPacket(PVOID pData, ULONG nData);

	//�q�ұ����쪺�T�ؽw�s�ϱo��@�ӰT�ءA�ê�^�եε��G
	//�Ѽ� pData: �������ƾګO�s�bpData���Ы��V���Ŷ���
	virtual long CheckRecvFrame(PBYTE pData);


protected:
	//�q�ҿ���dŪ���T�ءA�O�s�bfifo�C��m_listPacket��
	virtual long ReadPackets();

	LPSTR				m_pszAdapter;	//��Ϊ����d�W��
	ETHERNET_ADDRESS	m_macAdapter;	//��Ϊ����dMAC��}


private:
	//�Ыؤ@�Ӱ�����A�q���d�����A�ӫʥ]�A�ê�^�եε��G
	//�Ѽ�: nPriority: ��������u����
	long StartReceiverThread(long nPriority = THREAD_PRIORITY_HIGHEST);

	//�������ơA��^�եε��G
	//�Ѽ�: lpParameter: ������Ѽ�
	static DWORD WINAPI ReceiverThread(LPVOID lpParameter);

	HANDLE				m_hStartEvent;
	HANDLE				m_hCloseEvent;
	HANDLE				m_hReceiverThread;	//���������
	DWORD				m_dwThreadId;
	bool				m_bStopReceiver;	//�B��лx
	long				m_lRef;
	struct _ADAPTER*	m_pAdapter;			//���|�����d�ާ@�H��
	CFiFoList<PVOID, MAX_NPFPACKETS>m_listPacket;	//�����w�s�C��A���J���X
};

