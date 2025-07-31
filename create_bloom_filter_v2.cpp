#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define BLOOM_SIZE (512*1024*1024)  // 512MB
#define BLOOM_SET_BIT(N) (bloom[(N)>>3] = bloom[(N)>>3] | (1<<((N)&7)))
#define BLOOM_GET_BIT(N) ( ( bloom[(N)>>3]>>((N)&7) )&1)

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

// Base58 alphabet
static const char* base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Base58 decode function
bool decodeBase58(const std::string& str, uint8_t* result, size_t result_len) {
    std::vector<uint8_t> decoded;
    decoded.reserve(str.length());
    
    // Convert Base58 to decimal
    for (char c : str) {
        const char* pos = strchr(base58_chars, c);
        if (pos == nullptr) return false;
        
        int carry = pos - base58_chars;
        for (auto it = decoded.rbegin(); it != decoded.rend(); ++it) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        if (carry > 0) {
            decoded.insert(decoded.begin(), carry);
        }
    }
    
    // Remove leading zeros
    while (!decoded.empty() && decoded[0] == 0) {
        decoded.erase(decoded.begin());
    }
    
    // Copy to result
    if (decoded.size() > result_len) return false;
    
    memset(result, 0, result_len);
    size_t offset = result_len - decoded.size();
    memcpy(result + offset, decoded.data(), decoded.size());
    
    return true;
}

// Hash160 function (SHA256 + RIPEMD160)
void hash160(const uint8_t* input, int input_len, uint8_t* output) {
    uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
    uint8_t ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
    
    // SHA256
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, input, input_len);
    SHA256_Final(sha256_hash, &sha256_ctx);
    
    // RIPEMD160
    RIPEMD160_CTX ripemd160_ctx;
    RIPEMD160_Init(&ripemd160_ctx);
    RIPEMD160_Update(&ripemd160_ctx, sha256_hash, SHA256_DIGEST_LENGTH);
    RIPEMD160_Final(ripemd160_hash, &ripemd160_ctx);
    
    memcpy(output, ripemd160_hash, RIPEMD160_DIGEST_LENGTH);
}

// Set hash160 in bloom filter
void bloom_set_hash160(unsigned char* bloom, uint32_t* h) {
    unsigned int t;
    t = BH00(h); BLOOM_SET_BIT(t);
    t = BH01(h); BLOOM_SET_BIT(t);
    t = BH02(h); BLOOM_SET_BIT(t);
    t = BH03(h); BLOOM_SET_BIT(t);
    t = BH04(h); BLOOM_SET_BIT(t);
    t = BH05(h); BLOOM_SET_BIT(t);
    t = BH06(h); BLOOM_SET_BIT(t);
    t = BH07(h); BLOOM_SET_BIT(t);
    t = BH08(h); BLOOM_SET_BIT(t);
    t = BH09(h); BLOOM_SET_BIT(t);
    t = BH10(h); BLOOM_SET_BIT(t);
    t = BH11(h); BLOOM_SET_BIT(t);
    t = BH12(h); BLOOM_SET_BIT(t);
    t = BH13(h); BLOOM_SET_BIT(t);
    t = BH14(h); BLOOM_SET_BIT(t);
    t = BH15(h); BLOOM_SET_BIT(t);
    t = BH16(h); BLOOM_SET_BIT(t);
    t = BH17(h); BLOOM_SET_BIT(t);
    t = BH18(h); BLOOM_SET_BIT(t);
    t = BH19(h); BLOOM_SET_BIT(t);
}

int main() {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int rc;
    
    // Open database
    rc = sqlite3_open("target_addresses.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    
    // Check table structure
    const char* check_sql = "SELECT name FROM sqlite_master WHERE type='table';";
    sqlite3_stmt* check_stmt;
    rc = sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, NULL);
    if (rc == SQLITE_OK) {
        std::cout << "Available tables:" << std::endl;
        while (sqlite3_step(check_stmt) == SQLITE_ROW) {
            const char* table_name = (const char*)sqlite3_column_text(check_stmt, 0);
            std::cout << "  - " << table_name << std::endl;
        }
        sqlite3_finalize(check_stmt);
    }
    
    // Try different possible table names and column names
    std::vector<std::string> possible_tables = {"addresses", "address", "targets", "target"};
    std::vector<std::string> possible_columns = {"address", "addr", "hash", "hash160"};
    
    std::string correct_table, correct_column;
    bool found_table = false;
    
    for (const auto& table : possible_tables) {
        for (const auto& column : possible_columns) {
            std::string sql = "SELECT " + column + " FROM " + table + " LIMIT 1;";
            sqlite3_stmt* test_stmt;
            rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &test_stmt, NULL);
            if (rc == SQLITE_OK) {
                if (sqlite3_step(test_stmt) == SQLITE_ROW) {
                    correct_table = table;
                    correct_column = column;
                    found_table = true;
                    std::cout << "Found table: " << table << " with column: " << column << std::endl;
                    sqlite3_finalize(test_stmt);
                    break;
                }
                sqlite3_finalize(test_stmt);
            }
        }
        if (found_table) break;
    }
    
    if (!found_table) {
        std::cerr << "Could not find address table in database!" << std::endl;
        sqlite3_close(db);
        return 1;
    }
    
    // Prepare statement to get addresses
    std::string sql = "SELECT " + correct_column + " FROM " + correct_table + ";";
    rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }
    
    // Initialize bloom filter
    unsigned char* bloom = new unsigned char[BLOOM_SIZE];
    memset(bloom, 0, BLOOM_SIZE);
    
    int address_count = 0;
    int error_count = 0;
    
    // Process each address
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* address = (const char*)sqlite3_column_text(stmt, 0);
        if (address) {
            // Decode Base58 address
            uint8_t decoded[25];
            if (decodeBase58(address, decoded, 25)) {
                // Extract hash160 (skip version byte and checksum)
                uint8_t hash160_bytes[20];
                memcpy(hash160_bytes, decoded + 1, 20);
                
                // Convert to uint32_t array for bloom filter
                uint32_t hash160_uint32[5];
                memcpy(hash160_uint32, hash160_bytes, 20);
                
                // Add to bloom filter
                bloom_set_hash160(bloom, hash160_uint32);
                address_count++;
                
                if (address_count % 1000 == 0) {
                    std::cout << "Processed " << address_count << " addresses..." << std::endl;
                }
            } else {
                error_count++;
                if (error_count <= 10) {
                    std::cout << "Failed to decode address: " << address << std::endl;
                }
            }
        }
    }
    
    // Finalize statement
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    // Save bloom filter to file
    std::ofstream bloom_file("target_addresses.blf", std::ios::binary);
    if (bloom_file.is_open()) {
        bloom_file.write((char*)bloom, BLOOM_SIZE);
        bloom_file.close();
        std::cout << "Bloom filter created successfully!" << std::endl;
        std::cout << "Total addresses processed: " << address_count << std::endl;
        std::cout << "Failed to decode: " << error_count << " addresses" << std::endl;
        std::cout << "Bloom filter saved to: target_addresses.blf" << std::endl;
    } else {
        std::cerr << "Failed to create bloom filter file!" << std::endl;
    }
    
    delete[] bloom;
    return 0;
} 