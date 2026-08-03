#include <cstdio>
#include <cstdlib>
#include <cstring>

const char* messages[] = {
    "Hello World - Small Build",
    "DefenderAtlas Research Dataset",
    "PE File Analysis Platform",
    "Compiled with MinGW GCC",
    "Unsigned Binary Sample",
    "Category A: Hello World",
    "This is a small compiled binary",
    "Used for Defender scanning research",
    "Multiple string literals for size",
    "End of message array"
};

int main() {
    for (int i = 0; i < 10; i++) {
        printf("Message %d: %s\n", i, messages[i]);
    }
    char buf[256];
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "Total messages: %d", 10);
    printf("%s\n", buf);
    return 0;
}
