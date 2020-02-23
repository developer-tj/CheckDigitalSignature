#include "DigitalSignatureInfo.h"
#include "Wintrust.h"
#include <Softpub.h>
#include <iostream>
#include "tIostream.h"
#include <iomanip>
#include <tchar.h>

BOOL DigitalSignatureInfo::initialize()
{
   return CheckCertificate();
}

BOOL DigitalSignatureInfo::CheckCertificate()
{
    DWORD Error = ERROR_SUCCESS;
    GUID GenericActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WintrustData = {};
    WINTRUST_FILE_INFO FileInfo = {};
    WINTRUST_SIGNATURE_SETTINGS SignatureSettings = {};
    CERT_STRONG_SIGN_PARA StrongSigPolicy = {};

    // Setup data structures for calling WinVerifyTrust
    WintrustData.cbStruct = sizeof(WINTRUST_DATA);
    WintrustData.dwUIChoice = WTD_UI_NONE;
    WintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WintrustData.dwUnionChoice = WTD_CHOICE_FILE;

    FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO_);
    FileInfo.pcwszFilePath = m_strFilePath.c_str();
    WintrustData.pFile = &FileInfo;

    //
    // First verify the primary signature (index 0) to determine how many secondary signatures
    // are present. We use WSS_VERIFY_SPECIFIC and dwIndex to do this, also setting
    // WSS_GET_SECONDARY_SIG_COUNT to have the number of secondary signatures returned.
    //
    SignatureSettings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
    SignatureSettings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
    
    WintrustData.pSignatureSettings = &SignatureSettings;

    BOOL bResult = TRUE;
    DWORD dwSignerIndex = 0;

    do
    {
        WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        SignatureSettings.dwIndex = dwSignerIndex;
        Error = WinVerifyTrust(nullptr, &GenericActionId, &WintrustData);
        if (Error == ERROR_SUCCESS)
        {
            if (!DecryptCertificateData(WintrustData.hWVTStateData))
            {
                bResult = FALSE;
            }

            // Need to clear the previous state data from the last call to WinVerifyTrust
            WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
            Error = WinVerifyTrust(nullptr, &GenericActionId, &WintrustData);
            if (Error != ERROR_SUCCESS)
            {
                //Error Print
                cout << TEXT("WinVerifyTrust() Error dwStateAction WTD_STATEACTION_CLOSE") << std::endl;
            }
        }

        if (Error != ERROR_SUCCESS)
        {
            //Error Print
            cout << TEXT("WinVerifyTrust() Error Code ") << Error << std::endl;
            break;
        }
        ++dwSignerIndex;
    } while (dwSignerIndex <= WintrustData.pSignatureSettings->cSecondarySigs);

    return bResult;
}

BOOL DigitalSignatureInfo::DecryptCertificateData(HANDLE hWVTStateData)
{
    BOOL result = TRUE;
    CRYPT_PROVIDER_DATA* pCryptProvData = WTHelperProvDataFromStateData(hWVTStateData);
    CRYPT_PROVIDER_SGNR* pSigner = WTHelperGetProvSignerFromChain(pCryptProvData, 0, FALSE, 0);
    CRYPT_PROVIDER_CERT* pCert = WTHelperGetProvCertFromChain(pSigner, 0);
    CertificateInfo certificateInfo;

    CertGetSerialNumber(pCert->pCert, certificateInfo.m_strSerialNumber);
    result |= CertGetIssuer(pCert->pCert, certificateInfo.m_strIssuer);
    result |= CertGetSubject(pCert->pCert, certificateInfo.m_strSubject);
    m_CertificateInfoList.emplace_back(certificateInfo);

    return result;
}

void DigitalSignatureInfo::CertGetSerialNumber(PCCERT_CONTEXT pCertContext, tstring& outSerialNumber)
{
    DWORD dwData = pCertContext->pCertInfo->SerialNumber.cbData;
    tostringstream s;
    for (DWORD n = 0; n < dwData; n++)
    {
        s << std::setw(2) << std::setfill(TEXT('0'))
            << std::hex << pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)];
    }
    outSerialNumber = s.str();
}

BOOL DigitalSignatureInfo::CertGetIssuer(PCCERT_CONTEXT pCertContext, tstring& outIssuer)
{
    return CertGetData(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, outIssuer);
}

BOOL DigitalSignatureInfo::CertGetSubject(PCCERT_CONTEXT pCertContext, tstring& outSubject)
{
    return CertGetData(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, outSubject);
}

BOOL DigitalSignatureInfo::CertGetData(PCCERT_CONTEXT inCertContext, DWORD inType, DWORD inFlags, tstring& outSubject)
{
    DWORD dwData;
    if (!(dwData = CertGetNameString(inCertContext,
        inType,
        inFlags,
        nullptr,
        nullptr,
        0)))
    {
        cout << TEXT("Get size CertGetNameString failed.") << std::endl;
        return FALSE;
    }

    // Allocate memory for data
    auto strData = std::make_unique<TCHAR[]>(dwData);

    // Get data
    if (!(CertGetNameString(inCertContext,
        inType,
        inFlags,
        nullptr,
        strData.get(),
        dwData)))
    {
        cout << TEXT("Get Data CertGetNameString failed.") << std::endl;
        return FALSE;
    }

    outSubject = strData.get();
    return TRUE;
}

void DigitalSignatureInfo::PrintCertificateInfoList()
{
    size_t index = 1;
    for (auto& certificateInfo : m_CertificateInfoList)
    {
        cout << TEXT("Signer Certificate : ") << index << std::endl;
        cout << TEXT("Serial Number : ") << certificateInfo.m_strSerialNumber << std::endl;
		cout << TEXT("Issuer Name : ") << certificateInfo.m_strIssuer << std::endl;
        cout << TEXT("Subject Name : ") << certificateInfo.m_strSubject << std::endl;
        cout << std::endl;
        ++index;
    }
}