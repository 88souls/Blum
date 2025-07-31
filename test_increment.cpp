#include <iostream>
#include <cstring>
#include <cstdio>

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
    for (size_t i = 0; i < str_sz; i += 2) {
        char hex[3] = {static_cast<char>(str[i]), static_cast<char>(str[i + 1]), 0};
        unhexed[i / 2] = strtol(hex, NULL, 16);
    }
}

int main() {
    std::string input = "00000000000000000000000000000000";
    uint8_t entropy[32];
    
    unhex((unsigned char*)input.data(), input.size(), entropy, input.size() / 2);
    
    std::cout << "Original: ";
    for (int i = 0; i < 32; i++) {
        printf("%02x", entropy[i]);
    }
    std::cout << std::endl;
    
    for (int step = 0; step <= 5; step++) {
        Increment_byte(entropy, 32, 1);
        std::cout << "Step " << step + 1 << ": ";
        for (int i = 0; i < 32; i++) {
            printf("%02x", entropy[i]);
        }
        std::cout << std::endl;
    }
    
    return 0;
} 