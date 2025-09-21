## OpenSSL Cert Project (VS C / OpenSSL 3.x)

**목적**: Visual Studio C에서 OpenSSL 3.x 기본 동작 검증(자체서명 인증서·CSR·RSA-PSS 서명·AES-GCM)  
**산출물**: `test_cert.pem`, `test_key.pem`, `test_req.csr`, `csr_key.pem`, `sig.bin`, `test.txt` (실행 폴더)

### 빌드 요약
1. vcpkg로 OpenSSL 설치(동적):
   ```
   vcpkg install openssl:x64-windows
   vcpkg integrate install

2. 프로젝트 설정:

   * 플랫폼: **x64**, 서브시스템: **콘솔(/SUBSYSTEM\:CONSOLE)**
   * 링크: `libcrypto.lib` (및 `Shlwapi.lib`)
   * DLL 실행 환경: `C:\vcpkg\installed\x64-windows\bin` 을 PATH 추가 *(또는 DLL 복사)*
3. 소스 상단(한 파일만):

   ```
   #include <openssl/applink.c>
   ```

### 실행

* **Ctrl+F5** 실행 → 로그에 `self-signature OK / MATCH / CSR OK / PSS VERIFY OK / GCM OK` 표시되면 성공
* 산출물 위치: `x64/Debug/` *(또는 설정한 OutDir)*

### 포함 기능

* RSA-2048 키 생성 → 자체서명 X.509 v3 인증서 발급/저장/검증
* 키–인증서 일치 검사: `X509_check_private_key`
* CSR 생성/저장: `X509_REQ` + `PEM_write_bio_X509_REQ`
* 파일 해시 전자서명: `EVP_DigestSign/Verify` (RSA-PSS, SHA-256)
* 대칭키 실습: `AES-256-GCM` 암·복호 라운드트립
