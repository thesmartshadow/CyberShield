#include <iostream>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <cstring>
#include <cstdarg>
#include <sstream>
#include <vector>
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

// Global flag to control debugger detection behavior
bool g_skip_debugger_detection = false;

// --- QuantumIdentity Class ---
class QuantumIdentity {
private:
    array<unsigned char, 32> system_fingerprint;
    array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES> session_key;
    
    void generate_fingerprint() {
        array<unsigned char, ETH_ALEN> mac{};
        ifreq ifr{};
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) >= 0) {
                memcpy(mac.data(), ifr.ifr_hwaddr.sa_data, ETH_ALEN);
            }
            close(sock);
        }
        randombytes_buf(system_fingerprint.data(), system_fingerprint.size());
    }
public:
    QuantumIdentity() {
        if (sodium_init() < 0) throw runtime_error("libsodium init failed");
        generate_fingerprint();
        crypto_aead_chacha20poly1305_keygen(session_key.data());
    }
    const auto& get_session_key() const { return session_key; }
    ~QuantumIdentity() {
        sodium_memzero(session_key.data(), session_key.size());
        sodium_memzero(system_fingerprint.data(), system_fingerprint.size());
    }
};

// --- SelfDestruct Class ---
class SelfDestruct {
private:
    const array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES>& key_ref;
    bool detect_debugger() {
        if (g_skip_debugger_detection) return false;
        #ifdef __linux__
            return (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1);
        #else
            return false;
        #endif
    }
public:
    SelfDestruct(const array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES>& key) : key_ref(key) {}
    ~SelfDestruct() {
        if (detect_debugger()) {
            syslog(LOG_ALERT, "Debugger detected! Clearing keys and terminating.");
            sodium_memzero(const_cast<unsigned char*>(key_ref.data()), key_ref.size());
            raise(SIGKILL);
        }
    }
};

// --- DynamicCipher Class ---
class DynamicCipher {
    array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES> key;
    array<unsigned char, crypto_aead_chacha20poly1305_NPUBBYTES> nonce;

public:
    DynamicCipher(const array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES>& k) : key(k) {
        randombytes_buf(nonce.data(), nonce.size());
    }

    // تعديل أمير المعتمد: سياسة رفض المدخلات الفارغة لحماية استقرار البرنامج
    pair<unique_ptr<unsigned char[]>, size_t> encrypt(const string& data) {
        if (data.empty()) {
            throw runtime_error("Data is empty! Security policy rejects empty input.");
        }

        unique_ptr<unsigned char[]> ciphertext(new unsigned char[data.size() + crypto_aead_chacha20poly1305_ABYTES]);
        unsigned long long ciphertext_len;

        crypto_aead_chacha20poly1305_encrypt(
            ciphertext.get(), &ciphertext_len,
            reinterpret_cast<const unsigned char*>(data.data()), data.size(),
            nullptr, 0, nullptr, nonce.data(), key.data()
        );

        return {move(ciphertext), static_cast<size_t>(ciphertext_len)};
    }

    const auto& get_nonce() const { return nonce; }
};

// --- SystemHook Namespace (Original Logic) ---
namespace SystemHook {
    typedef int (*orig_open_type)(const char*, int, ...);
    orig_open_type orig_open = nullptr;

    int open(const char* path, int flags, ...) {
        if (!orig_open) orig_open = reinterpret_cast<orig_open_type>(dlsym(RTLD_NEXT, "open"));
        
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, mode_t);
            va_end(args);
        }
        return orig_open(path, flags, mode);
    }
}

// --- High Level Functions ---
void encrypt_file(const string& input_path) {
    QuantumIdentity qid;
    DynamicCipher cipher(qid.get_session_key());
    ifstream file(input_path, ios::binary);
    if (!file) throw runtime_error("Could not open file: " + input_path);

    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    auto [ct, ct_len] = cipher.encrypt(content);

    ofstream out(input_path + ".enc", ios::binary);
    out.write(reinterpret_cast<const char*>(cipher.get_nonce().data()), cipher.get_nonce().size());
    out.write(reinterpret_cast<const char*>(ct.get()), ct_len);
    
    sodium_memzero(content.data(), content.size());
}

void file_self_check() {
    // تم حل التعارض هنا باستخدام مصفوفة char التقليدية لضمان استقرار البناء
    char path_template[] = "/tmp/cybershield_selftestXXXXXX";
    int fd = mkstemp(path_template);
    if (fd == -1) throw runtime_error("Self-test file creation failed");
    
    const char* payload = "integrity-check";
    write(fd, payload, strlen(payload));
    close(fd);

    encrypt_file(path_template);
    
    unlink(path_template);
    string enc_path = string(path_template) + ".enc";
    unlink(enc_path.c_str());
}

// --- Entry Point ---
int main(int argc, char* argv[]) {
    try {
        if (argc > 1 && string(argv[1]) == "--self-test") {
            file_self_check();
            cout << "Self-check passed ✓" << endl;
            return 0;
        }
        
        if (argc > 1) {
            encrypt_file(argv[1]);
            cout << "File encrypted successfully." << endl;
        } else {
            cout << "Usage: " << argv[0] << " <filename> | --self-test" << endl;
        }
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
