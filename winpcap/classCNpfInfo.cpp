/*���d�H����CNpfInfo�w�q*/

class CNpfInfo
{
public:
	CNpfInfo();		//�c�y���
	~CNpfInfo();	//�R�c���
	int GetAdpaterCount();	//��o��e���d�ƥ�

	//��o���d�W��
	//�Ѽ�:	nAdapter: ���d�s��
	LPCSTR GetAdapterName(int nAdapter);

	//��o���d�y�z
	//�Ѽ�:	nAdapter: ���d�s��
	LPCSTR GetAdapterDescription(int nAdapter);

	//��o�Ҧ����d�H��
	BOOL GetAdapterInfo();

	//�ھں��dMAC��}���}���d�ño��ާ@�H��
	struct _ADAPTER* GetAdapter(ETHERNET_ADDRESS macAddress);

	//�ھں��d�s�����}���d�ño��ާ@�H��
	struct _ADAPTER* GetAdapter(LPCSTR pszAdapter, ETHERNET_ADDRESS &macAddress);

protected:
	//���d�H��
	EcAdapterInfo	m_pAdapterInfo[MAX_NUM_ADAPTER];
	int				m_nADapter;		//���d�ƥ�
};