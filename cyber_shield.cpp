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
#include <algorithm>

using namespace std;

// --- QuantumIdentity Class ---
class QuantumIdentity {
private:
    array<unsigned char, 32> system_fingerprint;
    array<unsigned char, crypto_aead_chacha20poly1305_KEYBYTES> session_key;
    
    void generate_fingerprint() {
        array<unsigned char, ETH_ALEN> mac{};
        ifreq ifr{};
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) throw runtime_error("Failed to create socket");

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            close(sock);
            randombytes_buf(system_fingerprint.data(), system_fingerprint.size());
            return;
        }
        close(sock);
        copy_n(reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data), ETH_ALEN, mac.begin());
        randombytes_buf(system_fingerprint.data(), system_fingerprint.size());
    }
public:
    QuantumIdentity() {
        if (sodium_init() < 0) throw runtime_error("Libsodium init failed");
        generate_fingerprint();
        crypto_aead_chacha20poly1305_keygen(session_key.data());
    }
    const auto& get_session_key() const { return session_key; }
    ~QuantumIdentity() {
        sodium_memzero(session_key.data(), session_key.size());
        sodium_memzero(system_fingerprint.data(), system_fingerprint.size());
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

    // التعديل الخاص بك: Data Validation
    pair<unique_ptr<unsigned char[]>, size_t> encrypt(const string& data) {
        if (data.empty()) {
            throw runtime_error("Data is empty! Security policy rejects empty encryption.");
        }
        
        size_t ciphertext_buffer_len = data.size() + crypto_aead_chacha20poly1305_ABYTES;
        auto ciphertext = make_unique<unsigned char[]>(ciphertext_buffer_len);
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

// --- Global Functions & Self Tests ---
void encrypt_file(const string& input_path, const array<unsigned char, 32>& key_data) {
    DynamicCipher cipher(key_data);
    ifstream file(input_path, ios::binary);
    if (!file) throw runtime_error("Cannot open input file");

    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    auto [ct, ct_len] = cipher.encrypt(content);

    ofstream out(input_path + ".enc", ios::binary);
    out.write(reinterpret_cast<const char*>(cipher.get_nonce().data()), cipher.get_nonce().size());
    out.write(reinterpret_cast<const char*>(ct.get()), ct_len);
}

// حل التعارض (Conflict Resolution) في الـ Self Check
void file_self_check() {
    char path_template[] = "/tmp/cybershield_XXXXXX"; // تعديلك لاستخدام مصفوفة char
    int fd = mkstemp(path_template);
    if (fd == -1) throw runtime_error("Self-test file creation failed");

    const char* payload = "integrity-test";
    if (write(fd, payload, strlen(payload)) == -1) {
        close(fd);
        throw runtime_error("Write failed");
    }
    close(fd);

    QuantumIdentity qid;
    encrypt_file(path_template, qid.get_session_key());

    string out_path = string(path_template) + ".enc";
    unlink(path_template);
    unlink(out_path.c_str());
}

int main(int argc, char* argv[]) {
    try {
        if (argc > 1 && string(argv[1]) == "--self-test") {
            file_self_check();
            cout << "Self-check passed ✓" << endl;
            return 0;
        }
        
        // مسار التشفير العادي
        if (argc > 1) {
            QuantumIdentity qid;
            encrypt_file(argv[1], qid.get_session_key());
            cout << "File encrypted successfully." << endl;
        }
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}
