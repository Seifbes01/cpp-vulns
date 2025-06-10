#include <iostream>
#include <cstring>

// Global function pointer (target for overwrite)
void (*logFunc)(const char*) = nullptr;

// Safe log function
void safeLogger(const char* msg) {
    std::cout << "[SAFE] " << msg << std::endl;
}

// Malicious function (RCE)
void maliciousLogger(const char* msg) {
    std::cout << "[MALICIOUS] Executing: " << msg << std::endl;
    system(msg);  // Attacker gains RCE here!
}

// Vulnerable function (buffer overflow)
void bufferOverflowExploit(const char* input) {
    char buffer[16];  // Small buffer
    strcpy(buffer, input);  // No bounds checking → overflow
}

int main(int argc, char* argv[]) {
    printf("maliciousLogger address: %p\n", maliciousLogger);
    return 0;
    logFunc = safeLogger;  // Initialize to safe function

    if (argc > 1) {
        bufferOverflowExploit(argv[1]);  // Trigger overflow with user input
    }

    logFunc("Hello World");  // If overflowed, calls maliciousLogger!
    return 0;
}