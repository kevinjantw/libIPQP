#!/bin/bash

commands=(
    #"ctest -R ^spi_kem.+kyber_512"
    #"ctest -R ^spi_kem.+kyber_768"
    #"ctest -R ^spi_kem.+kyber_1024"
    "ctest -R ^spi_dsa.+dilithium_2"
    #"ctest -R ^spi_dsa.+dilithium_3"
    #"ctest -R ^spi_dsa.+dilithium_5"
    #"ctest -R ^uart_kem.+kyber_512"
    #"ctest -R ^uart_kem.+kyber_768"
    #"ctest -R ^uart_kem.+kyber_1024"
    #"ctest -R ^uart_dsa.+dilithium_2"
    #"ctest -R ^uart_dsa.+dilithium_3"
    #"ctest -R ^uart_dsa.+dilithium_5"
)

max=5
for i in $(seq 1 $max); do
    printf " ------------- \r\n"
    printf "| Round: %4d |\r\n" $i
    printf " ------------- \r\n"

    for cmd in "${commands[@]}"; do
        echo "Executing: $cmd"
        $cmd
    done

done
