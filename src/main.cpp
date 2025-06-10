#include <iostream>
#include <cstring>
#include <cstdio>

void vulnerableBufferOverflow(const char* input) {
    char buffer[10];
    strcpy(buffer, input);  // Buffer overflow vulnerability
    std::cout << "Buffer: " << buffer << std::endl;
}

void vulnerableFormatString(char* input) {
    printf(input);  // Format string vulnerability
}

void vulnerableBufferOverflow(char* input) {
    char buffer[10];
    strcpy(buffer, input); // potential overflow
}
void useAfterFree() {
    char* data = (char*)malloc(10);
    free(data);
    printf("%s", data);  // use after free
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <input>" << std::endl;
        return 1;
    }

    vulnerableBufferOverflow(argv[1]);
    vulnerableFormatString(argv[1]);

    return 0;
}
