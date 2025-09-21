// main.c — OpenSSL 3.x 자체서명 인증서 생성/저장/검증 + 추가 테스트 통합 (exe 폴더에 .pem 저장)
// 빌드: x64 / 콘솔(/SUBSYSTEM:CONSOLE) / 링크: libcrypto.lib, Shlwapi.lib
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <shlwapi.h>
#include <conio.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <openssl/applink.c>  // 반드시 딱 한 파일에만 포함

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Shlwapi.lib")

// ----- 유틸 -----
static void print_err(const char* where) {
    unsigned long e;
    fprintf(stderr, "[ERR] %s\n", where);
    while ((e = ERR_get_error()) != 0) {
        char buf[256]; ERR_error_string_n(e, buf, sizeof(buf));
        fprintf(stderr, "  -> %s\n", buf);
    }
}

static void path_in_exe_dir(char* out, size_t cap, const char* fname) {
    wchar_t exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
    PathRemoveFileSpecW(exe);
    wchar_t wpath[MAX_PATH]; wsprintfW(wpath, L"%s\\%S", exe, fname);
    WideCharToMultiByte(CP_ACP, 0, wpath, -1, out, (int)cap, NULL, NULL);
}

static int save_text_if_absent(const char* path, const char* text) {
    FILE* f = fopen(path, "rb");
    if (f) { fclose(f); return 1; }
    f = fopen(path, "wb"); if (!f) return 0;
    fwrite(text, 1, (unsigned)strlen(text), f);
    fclose(f); return 1;
}

// ----- 인증서 생성 -----
static int add_ext(X509* cert, int nid, const char* val) {
    X509V3_CTX ctx; X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION* ex = X509V3_EXT_nconf_nid(NULL, &ctx, nid, (char*)val);
    if (!ex) return 0;
    int ok = X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return ok == 1;
}

static int make_self_signed(EVP_PKEY** out_pkey, X509** out_cert) {
    *out_pkey = NULL; *out_cert = NULL;

    // RSA 2048 키
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx) { print_err("PKEY_CTX_new_id"); return 0; }
    if (EVP_PKEY_keygen_init(kctx) != 1) { print_err("keygen_init"); EVP_PKEY_CTX_free(kctx); return 0; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) != 1) { print_err("rsa_bits"); EVP_PKEY_CTX_free(kctx); return 0; }
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(kctx, &pkey) != 1) { print_err("keygen"); EVP_PKEY_CTX_free(kctx); return 0; }
    EVP_PKEY_CTX_free(kctx);

    // X509 v3
    X509* cert = X509_new();
    if (!cert) { print_err("X509_new"); EVP_PKEY_free(pkey); return 0; }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60L * 60 * 24 * 365);

    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)"OpenSSL Test", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);

    if (X509_set_pubkey(cert, pkey) != 1) { print_err("X509_set_pubkey"); X509_free(cert); EVP_PKEY_free(pkey); return 0; }

    if (!add_ext(cert, NID_basic_constraints, "CA:FALSE") ||
        !add_ext(cert, NID_key_usage, "digitalSignature,keyEncipherment") ||
        !add_ext(cert, NID_ext_key_usage, "serverAuth,clientAuth") ||
        !add_ext(cert, NID_subject_key_identifier, "hash") ||
        !add_ext(cert, NID_authority_key_identifier, "keyid:always"))
    {
        print_err("add_ext"); X509_free(cert); EVP_PKEY_free(pkey); return 0;
    }

    if (X509_sign(cert, pkey, EVP_sha256()) <= 0) { print_err("X509_sign"); X509_free(cert); EVP_PKEY_free(pkey); return 0; }

    *out_pkey = pkey; *out_cert = cert;
    return 1;
}

// ----- 정보/검증 -----
static void print_cert_info(X509* cert) {
    char subj[512], iss[512];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
    X509_NAME_oneline(X509_get_issuer_name(cert), iss, sizeof(iss));
    printf("[Subject] %s\n[Issuer ] %s\n", subj, iss);

    BIO* b = BIO_new(BIO_s_mem());
    ASN1_TIME_print(b, X509_get0_notBefore(cert)); char nb[64] = { 0 }; BIO_read(b, nb, sizeof nb - 1); BIO_free(b);
    b = BIO_new(BIO_s_mem()); ASN1_TIME_print(b, X509_get0_notAfter(cert)); char na[64] = { 0 }; BIO_read(b, na, sizeof na - 1); BIO_free(b);
    printf("[Valid  ] %s ~ %s\n", nb, na);

    unsigned int n = 0; unsigned char md[EVP_MAX_MD_SIZE];
    if (X509_digest(cert, EVP_sha256(), md, &n) == 1) {
        printf("[Finger ] SHA-256 ");
        for (unsigned i = 0;i < n;i++) printf("%02X%s", md[i], (i + 1 < n) ? ":" : "");
        puts("");
    }
}

static int verify_self_signature(X509* cert) {
    EVP_PKEY* pub = X509_get_pubkey(cert);
    if (!pub) { print_err("X509_get_pubkey"); return 0; }
    int ok = X509_verify(cert, pub);
    EVP_PKEY_free(pub);
    return ok == 1;
}

/* ===== 추가 테스트 소스 (통합) ===== */

// 1) 키·인증서 일치 검사
static void test_key_match(const char* certPath, const char* keyPath) {
    BIO* bc = BIO_new_file(certPath, "r");
    BIO* bk = BIO_new_file(keyPath, "r");
    if (!bc || !bk) { puts("[KeyMatch] open fail"); if (bc)BIO_free(bc); if (bk)BIO_free(bk); return; }
    X509* x = PEM_read_bio_X509(bc, NULL, NULL, NULL); BIO_free(bc);
    EVP_PKEY* p = PEM_read_bio_PrivateKey(bk, NULL, NULL, NULL); BIO_free(bk);
    if (!x || !p) { print_err("[KeyMatch] read pem"); if (x)X509_free(x); if (p)EVP_PKEY_free(p); return; }
    int ok = X509_check_private_key(x, p);
    printf("[KeyMatch] %s\n", ok == 1 ? "MATCH" : "MISMATCH");
    X509_free(x); EVP_PKEY_free(p);
}

// 2) CSR 생성/저장 (새 키 포함)
static int make_csr_and_save(const char* csrPath, const char* keyOutPath) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx) { print_err("CSR keyctx"); return 0; }
    if (EVP_PKEY_keygen_init(kctx) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) != 1) {
        print_err("CSR keygen init"); EVP_PKEY_CTX_free(kctx); return 0;
    }
    EVP_PKEY* pkey = NULL; if (EVP_PKEY_keygen(kctx, &pkey) != 1) { print_err("CSR keygen"); EVP_PKEY_CTX_free(kctx); return 0; }
    EVP_PKEY_CTX_free(kctx);

    X509_REQ* req = X509_REQ_new();
    X509_NAME* nm = X509_NAME_new();
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, (const unsigned char*)"OpenSSL Demo", -1, -1, 0);
    X509_REQ_set_subject_name(req, nm); X509_NAME_free(nm);
    X509_REQ_set_pubkey(req, pkey);
    if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) { print_err("X509_REQ_sign"); X509_REQ_free(req); EVP_PKEY_free(pkey); return 0; }

    BIO* bk = BIO_new_file(keyOutPath, "w"); if (!bk) { print_err("CSR key save"); X509_REQ_free(req); EVP_PKEY_free(pkey); return 0; }
    PEM_write_bio_PrivateKey(bk, pkey, NULL, NULL, 0, NULL, NULL); BIO_free(bk);
    BIO* br = BIO_new_file(csrPath, "w"); if (!br) { print_err("CSR save"); X509_REQ_free(req); EVP_PKEY_free(pkey); return 0; }
    PEM_write_bio_X509_REQ(br, req); BIO_free(br);

    X509_REQ_free(req); EVP_PKEY_free(pkey);
    printf("[CSR] OK: %s / %s\n", csrPath, keyOutPath);
    return 1;
}

// 3) RSA-PSS 서명/검증 (파일 해시 SHA-256)
static int sign_verify_pss_file(const char* keyPath, const char* msgPath, const char* sigPath) {
    // 키 로드(없으면 실패 처리)
    BIO* bk = BIO_new_file(keyPath, "r"); if (!bk) { puts("[PSS] key open fail"); return 0; }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bk, NULL, NULL, NULL); BIO_free(bk);
    if (!pkey) { print_err("[PSS] read key"); return 0; }

    // 서명
    EVP_MD_CTX* mctx = EVP_MD_CTX_new(); EVP_PKEY_CTX* pctx = NULL;
    if (EVP_DigestSignInit(mctx, &pctx, EVP_sha256(), NULL, pkey) != 1) { print_err("[PSS] SignInit"); EVP_PKEY_free(pkey); return 0; }
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST);

    FILE* fm = fopen(msgPath, "rb"); if (!fm) { puts("[PSS] msg open fail"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); return 0; }
    unsigned char buf[4096]; size_t n; while ((n = fread(buf, 1, sizeof buf, fm)) > 0) { if (EVP_DigestSignUpdate(mctx, buf, n) != 1) { fclose(fm); print_err("[PSS] SignUpdate"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); return 0; } }
    fclose(fm);
    size_t siglen = 0; EVP_DigestSignFinal(mctx, NULL, &siglen);
    unsigned char* sig = (unsigned char*)OPENSSL_malloc(siglen);
    if (EVP_DigestSignFinal(mctx, sig, &siglen) != 1) { print_err("[PSS] SignFinal"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); OPENSSL_free(sig); return 0; }
    BIO* bs = BIO_new_file(sigPath, "wb"); if (!bs) { puts("[PSS] sig open fail"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); OPENSSL_free(sig); return 0; }
    BIO_write(bs, sig, (int)siglen); BIO_free(bs);
    EVP_MD_CTX_free(mctx);

    // 검증
    mctx = EVP_MD_CTX_new(); EVP_PKEY_CTX* vp = NULL;
    if (EVP_DigestVerifyInit(mctx, &vp, EVP_sha256(), NULL, pkey) != 1) { print_err("[PSS] VerifyInit"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); OPENSSL_free(sig); return 0; }
    EVP_PKEY_CTX_set_rsa_padding(vp, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(vp, RSA_PSS_SALTLEN_DIGEST);
    fm = fopen(msgPath, "rb"); if (!fm) { puts("[PSS] msg reopen fail"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); OPENSSL_free(sig); return 0; }
    while ((n = fread(buf, 1, sizeof buf, fm)) > 0) { if (EVP_DigestVerifyUpdate(mctx, buf, n) != 1) { fclose(fm); print_err("[PSS] VerifyUpdate"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); OPENSSL_free(sig); return 0; } }
    fclose(fm);
    int ok = EVP_DigestVerifyFinal(mctx, sig, siglen);
    printf("[PSS] %s (sig=%s)\n", ok == 1 ? "VERIFY OK" : "VERIFY FAIL", sigPath);
    EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); OPENSSL_free(sig);
    return ok == 1;
}

// 4) AES-256-GCM 메모리 암·복호
static int aes_gcm_demo(void) {
    unsigned char key[32], iv[12];
    if (RAND_bytes(key, 32) != 1 || RAND_bytes(iv, 12) != 1) { print_err("[GCM] RAND_bytes"); return 0; }
    const unsigned char* pt = (const unsigned char*)"AES-256-GCM demo";
    unsigned char ct[256], tag[16]; int len = 0, out = 0;

    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof iv, NULL);
    EVP_EncryptInit_ex(c, NULL, NULL, key, iv);
    EVP_EncryptUpdate(c, ct, &len, pt, (int)strlen((const char*)pt)); out = len;
    EVP_EncryptFinal_ex(c, ct + out, &len); out += len;
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, (int)sizeof tag, tag);
    EVP_CIPHER_CTX_free(c);

    unsigned char rec[256]; int dec = 0;
    c = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof iv, NULL);
    EVP_DecryptInit_ex(c, NULL, NULL, key, iv);
    EVP_DecryptUpdate(c, rec, &dec, ct, out);
    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, (int)sizeof tag, tag);
    if (EVP_DecryptFinal_ex(c, rec + dec, &len) != 1) { print_err("[GCM] tag check"); EVP_CIPHER_CTX_free(c); return 0; }
    dec += len; rec[dec] = '\0'; EVP_CIPHER_CTX_free(c);

    printf("[GCM] OK: %s\n", rec);
    return 1;
}

// ----- main -----
int main(void) {
    OPENSSL_init_crypto(0, NULL);
    printf("== OpenSSL %s ==\n", OpenSSL_version(OPENSSL_VERSION));

    char certPath[MAX_PATH], keyPath[MAX_PATH];
    path_in_exe_dir(certPath, sizeof certPath, "test_cert.pem");
    path_in_exe_dir(keyPath, sizeof keyPath, "test_key.pem");

    EVP_PKEY* pkey = NULL; X509* cert = NULL;

    // 없으면 생성/저장, 있으면 로드
    FILE* f = fopen(certPath, "rb");
    if (!f) {
        printf("[*] %s 없음 → 생성\n", certPath);
        if (!make_self_signed(&pkey, &cert)) return 1;

        FILE* fk = fopen(keyPath, "wb");
        if (!fk || !PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL)) { print_err("write key"); if (fk) fclose(fk); return 1; }
        fclose(fk);

        FILE* fc = fopen(certPath, "wb");
        if (!fc || !PEM_write_X509(fc, cert)) { print_err("write cert"); if (fc) fclose(fc); return 1; }
        fclose(fc);

        puts("[+] PEM 저장 완료");
    }
    else {
        fclose(f);
        printf("[*] %s 존재 → 로드\n", certPath);
        FILE* fc = fopen(certPath, "rb"); cert = PEM_read_X509(fc, NULL, NULL, NULL); fclose(fc);
        FILE* fk = fopen(keyPath, "rb");  if (fk) { pkey = PEM_read_PrivateKey(fk, NULL, NULL, NULL); fclose(fk); }
        if (!cert) { print_err("PEM_read_X509"); return 1; }
    }

    print_cert_info(cert);
    puts(verify_self_signature(cert) ? "[Verify] self-signature OK" : "[Verify] FAIL");

    // ===== 추가 테스트 실행 =====
    test_key_match(certPath, keyPath);

    char csrPath[MAX_PATH], csrKeyPath[MAX_PATH];
    path_in_exe_dir(csrPath, sizeof csrPath, "test_req.csr");
    path_in_exe_dir(csrKeyPath, sizeof csrKeyPath, "csr_key.pem");
    make_csr_and_save(csrPath, csrKeyPath);

    char msgPath[MAX_PATH], sigPath[MAX_PATH];
    path_in_exe_dir(msgPath, sizeof msgPath, "test.txt");
    path_in_exe_dir(sigPath, sizeof sigPath, "sig.bin");
    save_text_if_absent(msgPath, "hello openssl\n");
    sign_verify_pss_file(keyPath, msgPath, sigPath);

    aes_gcm_demo();

    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);

    printf("Press any key to exit...");
    _getch();
    return 0;
}
