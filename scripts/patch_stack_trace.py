path = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(path, 'r', encoding='utf-8') as f:
    code = f.read()

target = """    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%p, caller=%p, subject='%s', issuer='%s')",
           pszPolicyOID, caller, certSubject, certIssuer);"""

replacement = """    LogMsg("[Crypto] CertVerifyCertificateChainPolicy called (policy=%p, caller=%p, subject='%s', issuer='%s')",
           pszPolicyOID, caller, certSubject, certIssuer);
    void* stack[16];
    USHORT frames = RtlCaptureStackBackTrace(0, 16, stack, NULL);
    for (USHORT f = 0; f < frames; f++) {
        LogMsg("[Crypto-Stack]   #%d: %p", f, stack[f]);
    }"""

assert target in code, "target not found"
code = code.replace(target, replacement, 1)

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(code)

print("[+] Successfully added stack trace to CertVerifyCertificateChainPolicy!")
