# 🧠 QRH-256 Cryptographic Hash Algorithm

## 📝 Overview

🔒 QRH-256 is a custom cryptographic hash function implementation designed for educational purposes and demonstrating core cryptographic principles. This implementation provides a complete hashing solution with HMAC support, showcasing modern cryptographic design patterns and secure coding practices.

⚠️ **Note**: This is a custom/educational implementation intended for learning and demonstration purposes. For production systems, use well-established cryptographic libraries like OpenSSL.

## ✅ Features

- **QRH-256 Hash Algorithm**: Custom 256-bit cryptographic hash function
- **HMAC Support**: Keyed hashing for message authentication
- **Portable Implementation**: Written in C with standard library dependencies
- **Configurable Security Parameters**: Adjustable rounds and diffusion settings
- **Little-Endian Output**: Standard byte ordering for compatibility

## 💡 Technical Highlights

### Core Competencies Demonstrated

- **Cryptographic Algorithm Design**: Implementation of custom hash functions following established patterns
- **Memory Management**: Proper allocation, usage, and deallocation of dynamic memory
- **Bit Manipulation**: Efficient bitwise operations and rotation functions
- **Security Engineering**: HMAC construction and constant-time considerations
- **System Programming**: Low-level C programming with pointer arithmetic

### Security Features

- **Multiple Round Functions**: Configurable security levels through compile-time constants
- **Diffusion Operations**: Bit spreading across the hash state for avalanche effect
- **Length Padding**: Secure message length incorporation into final hash
- **Keyed Hashing**: HMAC variant for authenticated hashing applications

## ⚡ Performance Benchmarks

### Large Data Processing Performance

```
Large Data Benchmark Summary
==================================================
Average run time: 988.456 ms
Total time: 2965.367 ms
Total data processed: 576.00 MB
Total throughput: 194.24 MB/s

Benchmark config:
    Total Runs: 3
    Crypto input buffer size: 64 MB
    Hash algo used: QRH-256

Hashing benchmark:
    Total time: 1636.388 ms
    Average time: 545.463 ms
    Average throughput: 117.33 MB/s
```

### Avalanche Effect Analysis

The hash function demonstrates strong avalanche properties, which is critical for cryptographic security:

```
QRH-256 Hash Bit Flip Benchmark
================================
Test Strings:
    String 1: "The quick brown fox jumps over the lazy dog"
    String 2: "The quick brown fox jumps over the lazy dof"  (1 character difference)

Results:
    Hash string1: 17f474bce744ebf23a17ce10983ef09198c79cac62fbbdadc491353ddb15d6dd
    Hash string2: cc67cd66c8f5459edf063e828f68234e5c9aeb1c9bcbc280a0e20dc8a7625438
    Bits flipped: 143/256 (55.86%)
    
    HMAC string1: 876ae3d95ee7811404d291f6b1bbaf766c827a4454ccab8485a506b5fdffb77a
    HMAC string2: 223fc836db59adad8ed7f09105070123687789ead05c0b7e5bdc7ef9f2912069
    HMAC bits flipped: 132/256 (51.56%)
```

The 55.86% bit flip rate in the hash output demonstrates excellent avalanche effect, approaching the ideal 50% rate that indicates strong cryptographic behavior.

## 🛠️ API Reference

### Main Hash Functions

```c
// Generate QRH-256 hash of input data
void qrh_256(const uint8_t *input, const size_t input_len, uint8_t *out);

// Generate QRH-256 hash and allocate output buffer
uint8_t *qrh_alloc_256(const uint8_t *input, const size_t input_len);

// Generate HMAC using QRH-256 as the underlying hash function
uint8_t *qrh_256_hmac(const uint8_t *key, const size_t key_len, 
                      const uint8_t *bytes, const size_t bytes_len);
```

### Configuration Options

Compile-time constants allow performance/security trade-offs:

- `QRH_HALF_ROUNDS`: Number of half-round iterations (default: 4)
- `QRH_DIFFUSIONS`: Number of diffusion passes (default: 4)  
- `QRH_MATRIX_ROUNDS`: Heavy matrix operation rounds (default: 2)

## 🚀 Performance Considerations

The algorithm includes performance documentation:
> "Matrix rounds are very heavy - 20 MB/sec per additional round"

This demonstrates awareness of real-world performance implications in cryptographic implementations. Current performance characteristics show:
- **Hashing Throughput**: 117.33 MB/s average
- **Large Data Processing**: 194.24 MB/s sustained throughput
- **Security vs Performance**: Configurable parameters allow tuning based on requirements

## 💻 Usage Example

```c
#include "qrh_256.h"

// Simple hashing
uint8_t hash[32];
qrh_256(data, data_len, hash);

// HMAC generation
uint8_t *hmac = qrh_256_hmac(key, key_len, message, message_len);
// Remember to free(hmac) when done

// Auto-allocation hashing
uint8_t *allocated_hash = qrh_alloc_256(data, data_len);
// Remember to free(allocated_hash) when done
```

## 🔧 Implementation Details

### Architecture

- **Block Size**: 64 bytes (512 bits)
- **Hash Size**: 32 bytes (256 bits) 
- **Word Size**: 16 × 32-bit words
- **Endianness**: Little-endian output format

### Key Components

1. **State Processing**: Multi-round permutation function
2. **Message Scheduling**: Input block processing with padding
3. **Finalization**: Secure output generation
4. **HMAC Construction**: Standard keyed hashing approach

## 📚 Development Notes

This implementation demonstrates several important software engineering practices:

- **Modular Design**: Separated functionality into distinct functions
- **Documentation**: Comprehensive comments explaining purpose and operation
- **Error Handling**: Proper bounds checking and memory management
- **Code Reusability**: Helper functions for common operations
- **Performance Awareness**: Inline functions and optimization considerations
- **Benchmarking**: Systematic performance evaluation and analysis

## ⚠️ Disclaimer

This is an educational implementation created to demonstrate cryptographic concepts and C programming skills. While implemented with security best practices in mind, it has not undergone formal cryptanalysis or security auditing. Use established cryptographic libraries for production applications requiring security guarantees.
