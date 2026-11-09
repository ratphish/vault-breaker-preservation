import sys

path = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

target = """static BOOL WINAPI Hook_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
) {
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%p)", pszPolicyOID);
    BOOL res = TRUE;
    if (g_real_CertVerifyCertificateChainPolicy) {
        res = g_real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    }
    if (pszPolicyOID == (LPCSTR)1 || (intptr_t)pszPolicyOID == 1) {
        if (pPolicyStatus) {
            pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
        }
        LogMsg("[Crypto] CertVerifyCertificateChainPolicy (SSL) -> Forcing SUCCESS");
    }
    return TRUE;
}"""

replacement = """static BOOL WINAPI Hook_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus
) {
    void* caller = _ReturnAddress();
    char certSubject[256] = "none";
    char certIssuer[256] = "none";
    if (pChainContext && pChainContext->cChain > 0 && pChainContext->rgpChain[0]->cElement > 0) {
        PCCERT_CONTEXT cert = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;
        if (cert) {
            CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, certSubject, sizeof(certSubject));
            CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, certIssuer, sizeof(certIssuer));
        }
    }
    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%p, caller=%p, subject='%s', issuer='%s')",
           pszPolicyOID, caller, certSubject, certIssuer);
    BOOL res = TRUE;
    if (g_real_CertVerifyCertificateChainPolicy) {
        res = g_real_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);
    }
    if (pszPolicyOID == (LPCSTR)1 || (intptr_t)pszPolicyOID == 1) {
        if (pPolicyStatus) {
            pPolicyStatus->dwError = 0; // CERT_TRUST_NO_ERROR = 0
        }
        LogMsg("[Crypto] CertVerifyCertificateChainPolicy (SSL) -> Forcing SUCCESS");
    }
    return TRUE;
}"""

# Normalize CRLF
content_norm = content.replace('\r\n', '\n')
target_norm = target.replace('\r\n', '\n')
replacement_norm = replacement.replace('\r\n', '\n')

if target_norm in content_norm:
    content_norm = content_norm.replace(target_norm, replacement_norm, 1)
    with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
        f.write(content_norm.replace('\n', '\r\n'))
    print('[+] Successfully patched Hook_CertVerifyCertificateChainPolicy!')
else:
    print('[-] Target not found!')
