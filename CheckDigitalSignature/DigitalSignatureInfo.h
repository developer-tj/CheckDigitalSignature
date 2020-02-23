#ifndef DIGITAL_SIGNATURE_INFO_H
#define DIGITAL_SIGNATURE_INFO_H
#include "tString.h"
#include "Windows.h"
#include <vector>

class DigitalSignatureInfo
{	
public:
	DigitalSignatureInfo(const tstring& inFilePath) : m_strFilePath(inFilePath) {}
	virtual ~DigitalSignatureInfo() {}
	BOOL initialize();
	void PrintCertificateInfoList();

private:
	BOOL CheckCertificate();
	BOOL DecryptCertificateData(HANDLE hWVTStateData);

	void CertGetSerialNumber(PCCERT_CONTEXT inCertContext, tstring &outSerialNumber);
	BOOL CertGetIssuer(PCCERT_CONTEXT inCertContext, tstring& outIssuer);
	BOOL CertGetSubject(PCCERT_CONTEXT inCertContext, tstring& outSubject);
	BOOL CertGetData(PCCERT_CONTEXT inCertContext, DWORD inType, DWORD inFlags, tstring& outSubject);

	tstring m_strFilePath;

	struct CertificateInfo
	{
		tstring m_strSerialNumber;
		tstring	m_strIssuer;
		tstring m_strSubject;
	};

	std::vector< CertificateInfo> m_CertificateInfoList;
};

#endif

