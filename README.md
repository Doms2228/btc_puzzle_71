# btc_puzzle_71
puzzle-btc
cpu-version
version 1.0

compile : 
g++ doms_btc_puzzle_71.cpp -o doms_btc_puzzle_71 -lsecp256k1 -lgmp -lssl -lcrypto -pthread -O3

test file btc_puzzle_21.cpp
compile: 
g++ doms_btc_puzzle_21.cpp -o doms_btc_puzzle_21 -lsecp256k1 -lgmp -lssl -lcrypto -pthread -O3

run : ./doms_btc_puzzle_21


result : ./doms_btc_puzzle_21
[+] Starting 4 thread(s)...
Target Address      : 14oFNXucftsHiUMY8uctg6N487riuyXs4h
Total               : 782165
Wins                : 0
Addr (compressed)   : 1Pg8JtPmumqyLGaEbgPeUZykYWtS2Z85bQ
Private Key         : 00000000000000000000000000000000000000000000000000000000001f4e06
Target Address      : 14oFNXucftsHiUMY8uctg6N487riuyXs4h                LV
Total               : 784756
Wins                : 1
Addr (compressed)   : 1PGumgfsWXuaqVXzfwPz6BfhxK3HrT3gvN
Private Key         : 00000000000000000000000000000000000000000000000000000000001ab69f
WIF                 : KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rKwFvNMKgP8Q

[+] Final Match:
Addr (compressed)  :  14oFNXucftsHiUMY8uctg6N487riuyXs4h
Private Key        : 00000000000000000000000000000000000000000000000000000000001ba534
WIF                : KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rL6JJvw6XUry

[+] Time elapsed: 14.983 seconds
[+] Keys checked: 784987
[+] Speed: 52391.8 keys/sec

Please donate : 
Donate btc : 1GXcqgg6uMUf28b2jxMnoVmMjzJQ2ojveQ  
