//CNpfInfo::GetAdapterInfo():獲得計算機上所有網卡的信息
//m_nAdapter:存放網卡數目
//m_pAdapterInfo[MAX_NUM_ADAPTER]:存放網卡信息

BOOL CNpfInfo::GetAdapterInfo()
{
	int i = 0;
	char *szTmpName, *szTmpName1;
	ULONG nAdapterLength = DEFAULT_ADAPTER_NAMELIST;
	char *szAdapterName = new char[nAdapterLength];
	m_nAdapter= -1;
	//獲得網卡名稱
	if (PacketGetAdapterNames(PTSTR(szAdapterName), &nAdapterLength) == FALSE)
	{	//如果函數執行失敗，清空szAdapterName地址空間
		delete[] szAdapterName;
		szAdapterName = new char[nAdapterLength];
		if (PacketGetAdapterNames(PTSTR(szAdapterName), &nAdapterLength) == FALSE)
		{	//函數再次執行失敗，返回錯誤結果
			delete[] szAdapterName;
			return FALSE;
		}
	}

	szTmpName=szAdapterName;
	szTmpName1=szAdapterName;

	//順序得到本機網卡名稱
	while ((*szTmpName!='\0') || (*(szTmpName-1) != '\0'))
	{
		if (*sz