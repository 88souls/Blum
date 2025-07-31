#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <random>
#include <chrono>
#include <iomanip>

// Глобальні змінні
std::atomic<bool> isRunning(false);
std::string outputFile;
std::vector<std::string> bloomFiles;
std::atomic<int> totalMnemonics(0);
std::atomic<int> totalHashes(0);
std::atomic<int> foundCount(0);

// Параметри для ентропії
std::string entropyFile;
std::string entropyInput;
int step = 1;
int n = 0;
bool useEntropyFile = false;
bool useEntropyInput = false;
bool continuousMode = false; // Новий параметр для безперервного режиму

// Змінна для поточної ентропії
std::string currentEntropy("");
std::mutex entropyMutex;

// Блюм-фільтр змінні
unsigned char* blooms[100] = {nullptr};
int blooms_count = 0;

// Параметр для 2009 режиму
bool use_2009_mode = false;

// Декларації функцій
void ProcessEntropy_2009(uint8_t* entropy, size_t entropy_len);
void EntropyFromFile_2009_Thread();
void DirectPrivateKey_2009_Thread();

// Базові функції (спрощені версії з оригінального коду)
#define BLOOM_SIZE (512*1024*1024)

// Hash functions for bloom filter
#define BH00(N) (N[0])
#define BH01(N) (N[1])
#define BH02(N) (N[2])
#define BH03(N) (N[3])
#define BH04(N) (N[4])
#define BH05(N) (N[0]<<16|N[1]>>16)
#define BH06(N) (N[1]<<16|N[2]>>16)
#define BH07(N) (N[2]<<16|N[3]>>16)
#define BH08(N) (N[3]<<16|N[4]>>16)
#define BH09(N) (N[4]<<16|N[0]>>16)
#define BH10(N) (N[0]<< 8|N[1]>>24)
#define BH11(N) (N[1]<< 8|N[2]>>24)
#define BH12(N) (N[2]<< 8|N[3]>>24)
#define BH13(N) (N[3]<< 8|N[4]>>24)
#define BH14(N) (N[4]<< 8|N[0]>>24)
#define BH15(N) (N[0]<<24|N[1]>> 8)
#define BH16(N) (N[1]<<24|N[2]>> 8)
#define BH17(N) (N[2]<<24|N[3]>> 8)
#define BH18(N) (N[3]<<24|N[4]>> 8)
#define BH19(N) (N[4]<<24|N[0]>> 8)

// Спрощена функція перевірки в блюм-фільтрі
static bool find_in_bloom(uint32_t* hash) {
    for (int b = 0; b < blooms_count; b++) {
        if (blooms[b] == nullptr) continue;
        
        unsigned char* bloom = blooms[b];
        unsigned int t;
        
        t = BH00(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH01(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH02(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH03(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH04(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH05(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH06(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH07(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH08(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH09(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH10(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH11(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH12(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH13(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH14(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH15(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH16(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH17(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH18(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        t = BH19(hash); if (((bloom[(t)>>3]>>((t)&7))&1) == 0) continue;
        
        return true; // Знайдено в цьому блюм-фільтрі
    }
    return false;
}

// Спрощена функція hash160
void hash160(const uint8_t* input, int input_len, uint8_t* output) {
    uint8_t sha256_hash[32];
    uint8_t ripemd160_hash[20];
    
    // SHA256
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, input, input_len);
    SHA256_Final(sha256_hash, &sha256_ctx);
    
    // RIPEMD160
    RIPEMD160_CTX ripemd160_ctx;
    RIPEMD160_Init(&ripemd160_ctx);
    RIPEMD160_Update(&ripemd160_ctx, sha256_hash, 32);
    RIPEMD160_Final(ripemd160_hash, &ripemd160_ctx);
    
    memcpy(output, ripemd160_hash, 20);
}

// Спрощена функція створення публічного ключа
int secp256k1_ec_pubkey_create(uint8_t* pubkey, const uint8_t* seckey) {
    // Спрощена реалізація - в реальності тут буде повна реалізація secp256k1
    memcpy(pubkey, seckey, 33);
    return 1;
}

// Функція для інкременту байтів
static bool Increment_byte(unsigned char* bytes, size_t length, int step) {
    for (int i = length - 1; i >= 0; i--) {
        int new_val = bytes[i] + step;
        bytes[i] = new_val & 0xFF;
        step = new_val >> 8;
        if (step == 0) break;
    }
    return step == 0;
}

// Функція для конвертації hex в байти
static void unhex(unsigned char* str, size_t str_sz, unsigned char* unhexed, size_t unhexed_sz) {
    // Спочатку заповнюємо нулями
    memset(unhexed, 0, unhexed_sz);
    
    // Простий варіант - обробляємо з початку
    for (size_t i = 0; i < str_sz && (i/2) < unhexed_sz; i += 2) {
        if (i + 1 < str_sz) {
            char hex[3] = {static_cast<char>(str[i]), static_cast<char>(str[i + 1]), 0};
            unhexed[i / 2] = strtol(hex, NULL, 16);
        }
    }
}

// Функція для роботи з ентропією з файлу
void EntropyFromFile_2009_Thread() {
    std::ifstream file(entropyFile);
    std::string line;
    
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        // Додаємо нулі спочатку якщо потрібно
        while (line.size() % 8 != 0 || line.size() < 8) {
            line.insert(0, "0");
        }
        
        uint8_t current_entropy[32];
        unhex((unsigned char*)line.data(), line.size(), current_entropy, line.size() / 2);
        
        // Завжди використовуємо інкремент, навіть якщо n = 0
        for (int i = 0; i <= n; i++) {
            ProcessEntropy_2009(current_entropy, line.size() / 2);
            Increment_byte(current_entropy, line.size() / 2, step);
        }
    }
}

// Функція для обробки ентропії
void ProcessEntropy_2009(uint8_t* entropy, size_t entropy_len) {
    uint8_t private_key[32];
    uint8_t public_key[33];
    uint8_t hash160_bytes[20];
    
    // Копіюємо ентропію як приватний ключ
    memcpy(private_key, entropy, 32);
    
    // Оновлюємо поточну ентропію для виводу
    std::string entropy_hex = "";
    for (int i = 0; i < 32; i++) {
        char hex[3];
        sprintf(hex, "%02x", entropy[i]);
        entropy_hex += hex;
    }
    std::lock_guard<std::mutex> lock(entropyMutex);
    currentEntropy = entropy_hex;
    
    // Створюємо публічний ключ
    secp256k1_ec_pubkey_create(public_key, private_key);
    
    // Обчислюємо hash160
    hash160(public_key, 33, hash160_bytes);
    
    // Перевіряємо в блюм-фільтрі
    uint32_t hash160_uint32[5];
    memcpy(hash160_uint32, hash160_bytes, 20);
    
    totalHashes++;
    
    if (find_in_bloom(hash160_uint32)) {
        // Знайдено збіг!
        foundCount++;
        std::cout << "\n" << std::endl;
        std::cout << "🎯 [FOUND] Private key for 2009 wallet!" << std::endl;
        std::cout << "🔑 Private key: ";
        for (int i = 0; i < 32; i++) {
            printf("%02x", private_key[i]);
        }
        std::cout << std::endl;
        
        // Конвертуємо hash160 в Base58 адресу для перевірки
        uint8_t address_bytes[25];
        address_bytes[0] = 0x00; // Version byte for mainnet
        memcpy(address_bytes + 1, hash160_bytes, 20);
        
        // Простий checksum (спрощено)
        uint8_t checksum[4] = {0, 0, 0, 0};
        memcpy(address_bytes + 21, checksum, 4);
        
        std::cout << "📍 Address: ";
        for (int i = 0; i < 25; i++) {
            printf("%02x", address_bytes[i]);
        }
        std::cout << std::endl;
        std::cout << "💾 Saved to: " << outputFile << std::endl;
        std::cout << std::endl;
        
        // Зберігаємо результат
        if (!outputFile.empty()) {
            std::ofstream out(outputFile, std::ios::app);
            out << "=== FOUND 2009 WALLET ===" << std::endl;
            out << "Private key: ";
            for (int i = 0; i < 32; i++) {
                out << std::hex << std::setw(2) << std::setfill('0') << (int)private_key[i];
            }
            out << std::endl;
            out << "Address: ";
            for (int i = 0; i < 25; i++) {
                out << std::hex << std::setw(2) << std::setfill('0') << (int)address_bytes[i];
            }
            out << std::endl;
            out << "Timestamp: " << std::time(nullptr) << std::endl;
            out << "========================" << std::endl;
            out.close();
        }
    }
}

// Функція для прямої генерації приватних ключів 2009 року
void DirectPrivateKey_2009_Thread() {
    uint8_t private_key[32];
    uint8_t public_key[33];
    uint8_t hash160_bytes[20];
    
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
    
    while (isRunning) {
        // Генеруємо випадковий приватний ключ напряму (як в 2009)
        for (int i = 0; i < 4; i++) {
            uint64_t random_val = dis(gen);
            memcpy(private_key + i * 8, &random_val, 8);
        }
        
        // Оновлюємо поточну ентропію для виводу
        std::string entropy_hex = "";
        for (int i = 0; i < 32; i++) {
            char hex[3];
            sprintf(hex, "%02x", private_key[i]);
            entropy_hex += hex;
        }
        std::lock_guard<std::mutex> lock(entropyMutex);
        currentEntropy = entropy_hex;
        
        // Створюємо публічний ключ
        secp256k1_ec_pubkey_create(public_key, private_key);
        
        // Обчислюємо hash160
        hash160(public_key, 33, hash160_bytes);
        
        // Перевіряємо в блюм-фільтрі
        uint32_t hash160_uint32[5];
        memcpy(hash160_uint32, hash160_bytes, 20);
        
        totalHashes++;
        
        if (find_in_bloom(hash160_uint32)) {
            // Знайдено збіг!
            foundCount++;
            std::cout << "\n" << std::endl;
            std::cout << "🎯 [FOUND] Private key for 2009 wallet!" << std::endl;
            std::cout << "🔑 Private key: ";
            for (int i = 0; i < 32; i++) {
                printf("%02x", private_key[i]);
            }
            std::cout << std::endl;
            
            // Конвертуємо hash160 в Base58 адресу для перевірки
            uint8_t address_bytes[25];
            address_bytes[0] = 0x00; // Version byte for mainnet
            memcpy(address_bytes + 1, hash160_bytes, 20);
            
            // Простий checksum (спрощено)
            uint8_t checksum[4] = {0, 0, 0, 0};
            memcpy(address_bytes + 21, checksum, 4);
            
            std::cout << "📍 Address: ";
            for (int i = 0; i < 25; i++) {
                printf("%02x", address_bytes[i]);
            }
            std::cout << std::endl;
            std::cout << "💾 Saved to: " << outputFile << std::endl;
            std::cout << std::endl;
            
            // Зберігаємо результат
            if (!outputFile.empty()) {
                std::ofstream out(outputFile, std::ios::app);
                out << "=== FOUND 2009 WALLET ===" << std::endl;
                out << "Private key: ";
                for (int i = 0; i < 32; i++) {
                    out << std::hex << std::setw(2) << std::setfill('0') << (int)private_key[i];
                }
                out << std::endl;
                out << "Address: ";
                for (int i = 0; i < 25; i++) {
                    out << std::hex << std::setw(2) << std::setfill('0') << (int)address_bytes[i];
                }
                out << std::endl;
                out << "Timestamp: " << std::time(nullptr) << std::endl;
                out << "========================" << std::endl;
                out.close();
            }
        }
    }
}

// Функція для безперервного режиму з інкрементом
void ContinuousSearch_2009_Thread() {
    uint8_t current_entropy[32];
    
    // Початкова ентропія з файлу
    std::ifstream file(entropyFile);
    std::string line;
    if (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        // Додаємо нулі спочатку якщо потрібно
        while (line.size() % 8 != 0 || line.size() < 8) {
            line.insert(0, "0");
        }
        
        unhex((unsigned char*)line.data(), line.size(), current_entropy, line.size() / 2);
    }
    file.close();
    
    // Безперервний цикл з інкрементом
    while (isRunning) {
        ProcessEntropy_2009(current_entropy, 32);
        Increment_byte(current_entropy, 32, step);
    }
}

// Функція для безперервного режиму з прямою ентропією
void ContinuousSearchDirect_2009_Thread() {
    uint8_t current_entropy[32];
    
    // Початкова ентропія
    std::string line = entropyInput;
    while (line.size() % 8 != 0 || line.size() < 8) {
        line.insert(0, "0");
    }
    
    unhex((unsigned char*)line.data(), line.size(), current_entropy, line.size() / 2);
    
    // Безперервний цикл з інкрементом
    while (isRunning) {
        ProcessEntropy_2009(current_entropy, 32);
        Increment_byte(current_entropy, 32, step);
    }
}

// Функція для завантаження блюм-фільтрів
bool loadBloomFilters() {
    for (int i = 0; i < bloomFiles.size(); i++) {
        blooms[i] = new unsigned char[BLOOM_SIZE];
        std::ifstream file(bloomFiles[i], std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to open bloom filter: " << bloomFiles[i] << std::endl;
            return false;
        }
        file.read((char*)blooms[i], BLOOM_SIZE);
        file.close();
        blooms_count++;
    }
    return true;
}

// Функція для виведення статистики
void printStats() {
    while (isRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        int hashes = totalHashes.load();
        int found = foundCount.load();
        std::string entropy = currentEntropy;
        
        int hash_speed = hashes / 5;
        
        // Завжди виводимо ентропію (якщо вона є)
        if (!entropy.empty()) {
            std::cout << "\rEnt: " << entropy 
                      << " | Checked: " << hashes 
                      << " | Speed: " << hash_speed << " hash/s" 
                      << " | Found: " << found << " [!]" << std::flush;
        } else {
            // Виводимо без ентропії (якщо вона порожня)
            std::cout << "\rChecked: " << hashes 
                      << " | Speed: " << hash_speed << " hash/s" 
                      << " | Found: " << found << " [!]" << std::flush;
        }
        
        totalHashes = 0;
    }
}

int main(int argc, char** argv) {
    std::cout << "MnemonicC++ 2009 Mode - Direct Private Key Generator" << std::endl;
    std::cout << "Started at: " << std::time(nullptr) << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Парсимо аргументи
    for (int arg = 1; arg < argc; ++arg) {
        if (strcmp(argv[arg], "--2009") == 0) {
            use_2009_mode = true;
            std::cout << "Using 2009 mode - direct private key generation" << std::endl;
        }
        else if (strcmp(argv[arg], "-b") == 0) {
            if (arg + 1 >= argc) {
                std::cerr << "Missing bloom file name after '-b'." << std::endl;
                return 1;
            }
            bloomFiles.push_back(argv[arg + 1]);
            arg++;
        }
        else if (strcmp(argv[arg], "-o") == 0) {
            if (arg + 1 >= argc) {
                std::cerr << "Missing output file name after '-o'." << std::endl;
                return 1;
            }
            outputFile = argv[arg + 1];
            arg++;
        }
        else if (strcmp(argv[arg], "-t") == 0) {
            if (arg + 1 >= argc) {
                std::cerr << "Missing value after '-t'." << std::endl;
                return 1;
            }
            int threads = std::stoi(argv[arg + 1]);
            arg++;
        }
        else if (strcmp(argv[arg], "-f") == 0) {
            if (arg + 1 >= argc) {
                std::cerr << "Missing entropy file name after '-f'." << std::endl;
                return 1;
            }
            entropyFile = argv[arg + 1];
            useEntropyFile = true;
            arg++;
        }
        else if (strcmp(argv[arg], "-entropy") == 0) {
            if (arg + 1 >= argc) {
                std::cerr << "Missing entropy value after '-entropy'." << std::endl;
                return 1;
            }
            entropyInput = argv[arg + 1];
            useEntropyInput = true;
            arg++;
        }
        else if (strcmp(argv[arg], "-step") == 0) {
            if (arg + 1 >= argc) {
                std::cerr << "Missing step value after '-step'." << std::endl;
                return 1;
            }
            step = std::stoi(argv[arg + 1]);
            arg++;
        }
        else if (strcmp(argv[arg], "-n") == 0) {
            if (arg + 1 >= argc) {
                std::cerr << "Missing n value after '-n'." << std::endl;
                return 1;
            }
            n = std::stoi(argv[arg + 1]);
            arg++;
        }
        else if (strcmp(argv[arg], "-continuous") == 0) {
            continuousMode = true;
            std::cout << "Running in continuous mode." << std::endl;
        }
        else if (strcmp(argv[arg], "-h") == 0 || strcmp(argv[arg], "--help") == 0) {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --2009           Use 2009 mode (direct private key generation)" << std::endl;
            std::cout << "  -b FILE          Bloom filter file" << std::endl;
            std::cout << "  -o FILE          Output file for results" << std::endl;
            std::cout << "  -t NUMBER        Number of threads" << std::endl;
            std::cout << "  -f FILE          Entropy file (hex format)" << std::endl;
            std::cout << "  -entropy HEX     Direct entropy input (hex format)" << std::endl;
            std::cout << "  -step NUMBER     Increment step (default: 1)" << std::endl;
            std::cout << "  -n NUMBER        Number of increments (default: 0)" << std::endl;
            std::cout << "  -continuous      Run in continuous mode (increment and output)" << std::endl;
            std::cout << "  -h, --help       Show this help" << std::endl;
            return 0;
        }
    }
    
    if (bloomFiles.empty()) {
        std::cerr << "No bloom filter files specified. Use -b FILE" << std::endl;
        return 1;
    }
    
    // Завантажуємо блюм-фільтри
    std::cout << "[!] Start Loading BloomFilters..." << std::endl;
    if (!loadBloomFilters()) {
        std::cerr << "Failed to load bloom filters!" << std::endl;
        return 1;
    }
    
    // Запускаємо потоки
    isRunning = true;
    int thread_count = 4; // За замовчуванням 4 потоки
    
    std::vector<std::thread> threads;
    
    if (useEntropyFile || useEntropyInput) {
        // Використовуємо ентропію з файлу або введення
        if (continuousMode) {
            // Безперервний режим
            if (useEntropyFile) {
                std::cout << "Using continuous mode with entropy from file: " << entropyFile << std::endl;
                std::cout << "Step: " << step << " (continuous increment)" << std::endl;
                
                // Запускаємо потоки для безперервного пошуку
                for (int i = 0; i < thread_count; i++) {
                    threads.emplace_back(ContinuousSearch_2009_Thread);
                }
            } else {
                std::cout << "Using continuous mode with direct entropy input: " << entropyInput << std::endl;
                std::cout << "Step: " << step << " (continuous increment)" << std::endl;
                
                // Запускаємо потоки для безперервного пошуку
                for (int i = 0; i < thread_count; i++) {
                    threads.emplace_back(ContinuousSearchDirect_2009_Thread);
                }
            }
        } else {
            // Звичайний режим з обмеженим інкрементом
            if (useEntropyFile) {
                std::cout << "Using entropy from file: " << entropyFile << std::endl;
                std::cout << "Step: " << step << ", N: " << n << std::endl;
                
                // Запускаємо потоки для обробки ентропії
                for (int i = 0; i < thread_count; i++) {
                    threads.emplace_back(EntropyFromFile_2009_Thread);
                }
            } else {
                std::cout << "Using direct entropy input: " << entropyInput << std::endl;
                std::cout << "Step: " << step << ", N: " << n << std::endl;
                
                // Обробляємо пряму ентропію
                std::string line = entropyInput;
                while (line.size() % 8 != 0 || line.size() < 8) {
                    line.insert(0, "0");
                }
                
                uint8_t current_entropy[32];
                unhex((unsigned char*)line.data(), line.size(), current_entropy, line.size() / 2);
                
                // Завжди використовуємо інкремент
                for (int i = 0; i <= n; i++) {
                    ProcessEntropy_2009(current_entropy, line.size() / 2);
                    Increment_byte(current_entropy, line.size() / 2, step);
                }
            }
        }
    } else {
        // Рендомна генерація
        std::cout << "Using random entropy generation" << std::endl;
        
        // Запускаємо потоки генерації
        for (int i = 0; i < thread_count; i++) {
            threads.emplace_back(DirectPrivateKey_2009_Thread);
        }
    }
    
    // Запускаємо потік статистики
    std::thread stats_thread(printStats);
    
    // Очікуємо завершення
    for (auto& t : threads) {
        t.join();
    }
    
    isRunning = false;
    stats_thread.join();
    
    std::cout << "\nSearch completed!" << std::endl;
    return 0;
} 