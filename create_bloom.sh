#!/bin/bash

echo "Creating bloom filter from target_addresses.db..."

# Check if database exists
if [ ! -f "target_addresses.db" ]; then
    echo "Error: target_addresses.db not found!"
    exit 1
fi

# Try to compile and run
echo "Compiling bloom filter creator..."

# Try version 2 first (with OpenSSL)
if command -v g++ &> /dev/null; then
    echo "Using g++ compiler..."
    g++ -std=c++11 -O2 -Wall -o create_bloom_filter_v2 create_bloom_filter_v2.cpp -lsqlite3 -lssl -lcrypto
    
    if [ $? -eq 0 ]; then
        echo "Compilation successful!"
        echo "Running bloom filter creator..."
        ./create_bloom_filter_v2
        
        if [ $? -eq 0 ]; then
            echo "Bloom filter created successfully!"
            echo "File: target_addresses.blf"
            exit 0
        else
            echo "Error running bloom filter creator!"
            exit 1
        fi
    else
        echo "Compilation failed with OpenSSL, trying without..."
        # Try version 1 (without OpenSSL)
        g++ -std=c++11 -O2 -Wall -o create_bloom_filter create_bloom_filter.cpp -lsqlite3
        
        if [ $? -eq 0 ]; then
            echo "Compilation successful!"
            echo "Running bloom filter creator..."
            ./create_bloom_filter
            
            if [ $? -eq 0 ]; then
                echo "Bloom filter created successfully!"
                echo "File: target_addresses.blf"
                exit 0
            else
                echo "Error running bloom filter creator!"
                exit 1
            fi
        else
            echo "Compilation failed!"
            exit 1
        fi
    fi
else
    echo "Error: g++ compiler not found!"
    echo "Please install g++ and try again."
    exit 1
fi 