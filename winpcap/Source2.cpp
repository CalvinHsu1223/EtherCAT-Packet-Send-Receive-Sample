//CNpfInfo::GetAdapterInfo():��o�p����W�Ҧ����d���H��
//m_nAdapter:�s����d�ƥ�
//m_pAdapterInfo[MAX_NUM_ADAPTER]:�s����d�H��

BOOL CNpfInfo::GetAdapterInfo()
{
	int i = 0;
	char *szTmpName, *szTmpName1;
	ULONG nAdapterLength = DEFAULT_ADAPTER_NAMELIST;
	char *szAdapterName = new char[nAdapterLength];
	m_nAdapter= -1;
	//��o���d�W��
	if (PacketGetAdapterNames(PTSTR(szAdapterName), &nAdapterLength) == FALSE)
	{	//�p�G��ư��楢�ѡA�M��szAdapterName�a�}�Ŷ�
		delete[] szAdapterName;
		szAdapterName = new char[nAdapterLength];
		if (PacketGetAdapterNames(PTSTR(szAdapterName), &nAdapterLength) == FALSE)
		{	//��ƦA�����楢�ѡA��^���~���G
			delete[] szAdapterName;
			return FALSE;
		}
	}

	szTmpName=szAdapterName;
	szTmpName1=szAdapterName;

	//���Ǳo�쥻�����d�W��
	while ((*szTmpName!='\0') || (*(szTmpName-1) != '\0'))
	{
		if (*sz