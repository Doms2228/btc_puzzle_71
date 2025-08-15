#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <random>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <signal.h>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#ifndef RIPEMD160_DIGEST_LENGTH
#define RIPEMD160_DIGEST_LENGTH 20
#endif

#ifndef UINT128_MAX
#define UINT128_MAX ((uint128(0) - 1))
#endif

using uint128 = __uint128_t;

std::atomic<bool> running(true);
std::mutex print_mutex;
std::string last_address;
std::string last_privkey;
std::string last_wif;
std::mutex last_mutex;

void signal_handler(int) {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::cout << "\n[!] Ctrl+C detected. Exiting cleanly...\n";
    running = false;
}

std::string hex_str(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        oss << std::setw(2) << (int)data[i];
    return oss.str();
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    const EVP_MD* md = EVP_ripemd160();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash.data(), nullptr);
    EVP_MD_CTX_free(ctx);
    return hash;
}

std::string base58_encode(const std::vector<unsigned char>& input) {
    const char* alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<unsigned char> input_copy = input;
    size_t zeros = 0;
    while (zeros < input_copy.size() && input_copy[zeros] == 0)
        ++zeros;
    std::vector<unsigned char> b58((input_copy.size() - zeros) * 138 / 100 + 1);
    size_t length = 0;
    for (size_t i = zeros; i < input_copy.size(); ++i) {
        int carry = input_copy[i];
        size_t j = 0;
        for (auto it = b58.rbegin(); (carry != 0 || j < length) && it != b58.rend(); ++it, ++j) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        length = j;
    }
    std::string result;
    auto it = b58.begin() + (b58.size() - length);
    while (it != b58.end() && *it == 0) ++it;
    for (size_t i = 0; i < zeros; ++i)
        result += '1';
    for (; it != b58.end(); ++it)
        result += alphabet[*it];
    return result;
}

std::string private_key_to_wif(const unsigned char* priv_key) {
    std::vector<unsigned char> extended;
    extended.push_back(0x80);
    extended.insert(extended.end(), priv_key, priv_key + 32);
    extended.push_back(0x01);
    auto checksum = sha256(sha256(extended));
    extended.insert(extended.end(), checksum.begin(), checksum.begin() + 4);
    return base58_encode(extended);
}

std::string private_key_to_address(secp256k1_context* ctx, const unsigned char* priv_key) {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key))
        return "";

    unsigned char output[33];
    size_t output_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, output, &output_len, &pubkey, SECP256K1_EC_COMPRESSED);

    std::vector<unsigned char> hash_input(output, output + output_len);
    auto sha = sha256(hash_input);
    auto ripe = ripemd160(sha);

    std::vector<unsigned char> payload;
    payload.push_back(0x00);
    payload.insert(payload.end(), ripe.begin(), ripe.end());

    auto checksum = sha256(sha256(payload));
    payload.insert(payload.end(), checksum.begin(), checksum.begin() + 4);
    return base58_encode(payload);
}

uint128 secure_random(uint128 start, uint128 end, std::mt19937_64& gen) {
    uint128 range = end - start + 1;
    uint128 reject = UINT128_MAX - (UINT128_MAX % range + 1);
    while (true) {
        uint128 rnd = ((uint128(gen()) << 64) | gen());
        if (rnd <= reject)
            return (rnd % range) + start;
    }
}

void generate_private_key(unsigned char* priv_key, uint128 key_val) {
    memset(priv_key, 0, 32);
    for (int i = 0; i < 16; ++i)
        priv_key[31 - i] = (key_val >> (8 * i)) & 0xFF;
}

void scan_loop(uint128 start, uint128 end, std::atomic<uint64_t>& total, std::atomic<uint64_t>& wins, const std::string& target) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    std::random_device rd;
    std::mt19937_64 gen(rd());

    while (running.load(std::memory_order_relaxed)) {
        if (!running) break;  // Check early

        uint128 key_val = secure_random(start, end, gen);

        if (!running) break;  // Check again to exit early if another thread already found the match

        unsigned char priv_key[32];
        generate_private_key(priv_key, key_val);

        std::string address = private_key_to_address(ctx, priv_key);

        if (!running) break;  // Final early exit before checking

        std::string wif = private_key_to_wif(priv_key);
        std::string priv_hex = hex_str(priv_key, 32);

        total.fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lock(last_mutex);
            last_address = address;
            last_privkey = priv_hex;
            last_wif = wif;
        }

        if (address == target && running) {
            wins.fetch_add(1, std::memory_order_relaxed);

            {
                std::lock_guard<std::mutex> lock(last_mutex);
                last_address = address;
                last_privkey = priv_hex;
                last_wif = wif;
            }

            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << "\n[+] MATCH FOUND!\n"
                      << "Addr (compressed)  : " << address << "\n"
                      << "Private Key        : " << priv_hex << "\n"
                      << "WIF                : " << wif << "\n";

            std::ofstream out("match_found.txt", std::ios::app);
            out << "Address: " << address << "\n"
                << "Private Key: " << priv_hex << "\n"
                << "WIF: " << wif << "\n\n";
            out.close();

            running.store(false);
            break;
        }

    }

    secp256k1_context_destroy(ctx);
}

int main() {
auto begin_time = std::chrono::steady_clock::now();

    signal(SIGINT, signal_handler);

    uint128 start = (uint128(1) << 70);
    uint128 end   = (uint128(1) << 71) - 1;

    std::atomic<uint64_t> total(0);
    std::atomic<uint64_t> wins(0);

    std::string target_address;
    std::ifstream infile("address_71.txt");
    if (infile) {
        std::getline(infile, target_address);
    } else {
        std::cerr << "[-] Could not open address_71.txt\n";
        return 1;
    }

    unsigned int threads = std::thread::hardware_concurrency();
    std::cout << "[+] Starting " << threads << " thread(s)...\n";

    std::vector<std::thread> workers;
    for (unsigned int i = 0; i < threads; ++i) {
        workers.emplace_back(scan_loop, start, end, std::ref(total), std::ref(wins), std::ref(target_address));
    }

    std::cout << "\n\n\n\n\n\n"; // space for progress overwrite

    std::thread progress_thread([&]() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        std::string address, priv, wif;
        {
            std::lock_guard<std::mutex> lock(last_mutex);
            address = last_address;
            priv = last_privkey;
            wif = last_wif;
        }

        uint64_t total_keys = total.load();
        uint64_t total_wins = wins.load();

        std::lock_guard<std::mutex> lock(print_mutex);
        std::cout << "\033[6A"; // move up 6 lines (increased by 1 for the extra line)
        std::cout << "Target Address      : " << target_address << "                \n"
                  << "Total               : " << total_keys << "                    \n"
                  << "Wins                : " << total_wins << "                    \n"
                  << "Addr (compressed)   : " << address << "                      \n"
                  << "Private Key         : " << priv << "                         \n"
                  << "WIF                 : " << wif << "                          \n"
                  << std::flush;
    }

    // Show final match after scanning
    if (wins.load() > 0) {
        std::ifstream in("match_found.txt");
        if (in) {
            std::string line;
            std::string addr, priv, wif;
            while (std::getline(in, line)) {
                if (line.rfind("Address:", 0) == 0) addr = line.substr(8);
                else if (line.rfind("Private Key:", 0) == 0) priv = line.substr(13);
                else if (line.rfind("WIF:", 0) == 0) wif = line.substr(5);
            }
            in.close();

            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << "\n[+] Final Match:\n"
                      << "Addr (compressed)  : " << addr << "\n"
                      << "Private Key        : " << priv << "\n"
                      << "WIF                : " << wif << "\n";
        }
    }
});



    for (auto& t : workers)
        if (t.joinable()) t.join();

    if (progress_thread.joinable())
        progress_thread.join();

    auto end_time = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - begin_time).count() / 1000.0;

    std::cout << "\n[+] Time elapsed: " << elapsed << " seconds\n";
    std::cout << "[+] Keys checked: " << total.load() << "\n";
    std::cout << "[+] Speed: " << (total.load() / elapsed) << " keys/sec\n";

    return 0;
}

