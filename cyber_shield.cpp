#include <iostream>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <cstring>
#include <cstdarg>
#include <sstream>
#include <sys/ptrace.h>
#include <syslog.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <chrono>
#include <sodium.h>
#include <csignal>
#include <cstddef>

using namespace std;

class QuantumIdentity {
private:
    array<unsigned char, 32> system_fingerprint;
    array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES> session_key;
    
    void generate_fingerprint() {
        array<unsigned char, ETH_ALEN> mac{};
        ifreq ifr{};
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) throw runtime_error("فشل إنشاء السوكيت");
        
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
        
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            close(sock);
            throw runtime_error("فشل الحصول على العنوان الفيزيائي");
        }
        close(sock);
        copy_n(ifr.ifr_hwaddr.sa_data, ETH_ALEN, mac.begin());

        auto now = chrono::high_resolution_clock::now().time_since_epoch().count();
        stringstream ss;
        ss << now << hex << mac[0] << mac[1] << mac[2];
        
        randombytes_buf(system_fingerprint.data(), system_fingerprint.size());
    }

public:
    QuantumIdentity() {
        if (sodium_init() < 0) throw runtime_error("فشل تهيئة libsodium");
        generate_fingerprint();
        crypto_aead_chacha20poly1305_keygen(session_key.data());
    }

    const auto& get_session_key() const { return session_key; }

    ~QuantumIdentity() {
        sodium_memzero(session_key.data(), session_key.size());
        sodium_memzero(system_fingerprint.data(), system_fingerprint.size());
    }
};

class SelfDestruct {
private:
    const array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES>& key_ref;

    bool detect_debugger() {
        #ifdef __linux__
            return (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1);
        #else
            return false;
        #endif
    }

public:
    SelfDestruct(const array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES>& key) 
        : key_ref(key) {}

    ~SelfDestruct() {
        if (detect_debugger()) {
            syslog(LOG_ALERT, "تم الكشف عن مصحح! تدمير المفاتيح...");
            sodium_memzero(const_cast<unsigned char*>(key_ref.data()), key_ref.size());
            raise(SIGKILL);
        }
    }
};

class DynamicCipher {
    array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES> key;
    array<unsigned char, crypto_aead_chacha20poly1305_NPUBBYTES> nonce;

public:
    DynamicCipher(const array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES>& k) 
        : key(k) {
        randombytes_buf(nonce.data(), nonce.size());
    }

    pair<unique_ptr<unsigned char[]>, size_t> encrypt(const string& data) {
        unique_ptr<unsigned char[]> ciphertext(new unsigned char[data.size() + crypto_aead_chacha20poly1305_ABYTES]);
        unsigned long long ciphertext_len;
        
        crypto_aead_chacha20poly1305_encrypt(
            ciphertext.get(), &ciphertext_len,
            reinterpret_cast<const unsigned char*>(data.data()), data.size(),
            nullptr, 0,
            nullptr,
            nonce.data(),
            key.data()
        );

        return {move(ciphertext), ciphertext_len};
    }

    string decrypt(const unsigned char* ciphertext, size_t len) {
        unique_ptr<unsigned char[]> plaintext(new unsigned char[len]);
        unsigned long long plaintext_len;
        
        if (crypto_aead_chacha20poly1305_decrypt(
            plaintext.get(), &plaintext_len,
            nullptr,
            ciphertext, len,
            nullptr, 0,
            nonce.data(),
            key.data()) != 0) {
            throw runtime_error("فشل فك التشفير: بيانات مرفوضة");
        }

        return string(reinterpret_cast<char*>(plaintext.get()), plaintext_len);
    }
};

namespace SystemHook {
    typedef int (*orig_open_type)(const char*, int, ...);
    orig_open_type orig_open = nullptr;

    QuantumIdentity qid;
    DynamicCipher cipher(qid.get_session_key());
    SelfDestruct destructor(qid.get_session_key());

    vector<string> protected_paths = {
        "/etc/passwd",
        "/etc/shadow",
        "/secret/",
        "/root/",
        "/var/log/auth.log",
        "/etc/sudoers",
        "/boot/"
    };

    bool is_protected(const char* path) {
        string target(path);
        for (const auto& p : protected_paths) {
            if (p.back() == '/' && target.find(p) == 0) {
                syslog(LOG_WARNING, "محاولة وصول إلى مجلد محمي: %s", path);
                return true;
            }
            if (p == target) {
                syslog(LOG_WARNING, "محاولة وصول إلى ملف محمي: %s", path);
                return true;
            }
        }
        return false;
    }

    int open(const char* path, int flags, ...) {
        mode_t mode = 0;
        va_list args;
        va_start(args, flags);
        if (flags & O_CREAT) mode = va_arg(args, mode_t);
        va_end(args);

        if (is_protected(path)) {
            syslog(LOG_ALERT, "تم منع الوصول إلى: %s", path);
            errno = EACCES;
            return -1;
        }
        return orig_open(path, flags, mode);
    }
}

extern "C" {
    int open(const char* path, int flags, ...) {
        if (!SystemHook::orig_open) {
            SystemHook::orig_open = reinterpret_cast<SystemHook::orig_open_type>(
                dlsym(RTLD_NEXT, "open")
            );
        }
        
        va_list args;
        va_start(args, flags);
        mode_t mode = (flags & O_CREAT) ? va_arg(args, mode_t) : 0;
        va_end(args);
        
        return SystemHook::open(path, flags, mode);
    }
}

void self_test() {
    try {
        QuantumIdentity qid;
        DynamicCipher cipher(qid.get_session_key());
        
        string test_data = "بيانات اختبار سرية للغاية";
        auto [ct, ct_len] = cipher.encrypt(test_data);
        string decrypted = cipher.decrypt(ct.get(), ct_len);
        
        if (decrypted != test_data) {
            throw runtime_error("فشل الاختبار الذاتي: البيانات غير متطابقة");
        }
        
        #ifndef DEBUG_MODE
            if (!ptrace(PTRACE_TRACEME, 0, nullptr, nullptr)) {
                throw runtime_error("فشل الكشف عن المصحح");
            }
        #endif
        
        cout << "الاختبار الذاتي ناجح ✓" << endl;
    } catch (const exception& e) {
        cerr << "خطأ في الاختبار الذاتي: " << e.what() << endl;
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    openlog("CyberShield", LOG_PID|LOG_CONS, LOG_AUTH);
    
    self_test();
    
    if (argc > 1) {
        try {
            QuantumIdentity qid;
            DynamicCipher cipher(qid.get_session_key());
            
            ifstream file(argv[1], ios::binary);
            if (!file) throw runtime_error("فشل فتح الملف: " + string(argv[1]));
            
            string content((istreambuf_iterator<char>(file)), 
                         istreambuf_iterator<char>());
            
            auto [ct, ct_len] = cipher.encrypt(content);
            ofstream out(string(argv[1]) + ".enc", ios::binary);
            out.write(reinterpret_cast<char*>(ct.get()), ct_len);
            
            cout << "تم تشفير الملف بنجاح: " << argv[1] << ".enc" << endl;
        } catch (const exception& e) {
            syslog(LOG_ERR, "خطأ في التشفير: %s", e.what());
            cerr << "خطأ: " << e.what() << endl;
            return EXIT_FAILURE;
        }
    }
    
    closelog();
    return EXIT_SUCCESS;
}