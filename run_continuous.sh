#!/bin/bash

echo "=== xblum++ 2009 Continuous Mode ==="
echo ""

# Перевіряємо чи існує блюм-фільтр
if [ ! -f "target_addresses.blf" ]; then
    echo "Error: target_addresses.blf not found!"
    echo "Please run create_bloom.sh first to create the bloom filter."
    exit 1
fi

# Компілюємо якщо потрібно
if [ ! -f "xblum_2009" ] || [ "Main_2009_Full.cpp" -nt "xblum_2009" ]; then
    echo "Compiling 2009 version..."
    make -f Makefile_2009
    if [ $? -ne 0 ]; then
        echo "Compilation failed!"
        exit 1
    fi
    echo "Compilation successful!"
fi

echo ""
echo "Starting continuous search mode..."
echo "This will continuously increment entropy and search"
echo "Searching for addresses in: target_addresses.blf"
echo "Results will be saved to: results_2009.txt"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Запускаємо програму в безперервному режимі
./xblum_2009 --2009 -b target_addresses.blf -o results_2009.txt -f entropy_2009.txt -step 1 -continuous -t 4 