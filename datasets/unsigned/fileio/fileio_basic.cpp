#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// File I/O operations - does NOT access any sensitive files
// Only uses the temp directory

#define TEMP_DIR "C:\\Windows\\Temp"
#define TEST_PREFIX "defenderatlas_test_"

void write_test_data(const char* filename, int num_records) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    fprintf(f, "ID,Name,Value,Timestamp\n");
    for (int i = 0; i < num_records; i++) {
        fprintf(f, "%d,Sample_%04d,%.6f,%ld\n",
            i, i, (double)(i * 1234.5678) / 1000.0, (long)time(NULL) + i);
    }
    fclose(f);
}

void read_and_verify(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    char line[256];
    int line_count = 0;
    while (fgets(line, sizeof(line), f)) {
        line_count++;
    }
    fclose(f);
    printf("  Read %d lines from %s\n", line_count, filename);
}

void write_binary_test(const char* filename, int size) {
    FILE* f = fopen(filename, "wb");
    if (!f) return;
    unsigned char* buf = (unsigned char*)malloc(size);
    for (int i = 0; i < size; i++) {
        buf[i] = (unsigned char)((i * 37 + 13) & 0xFF);
    }
    fwrite(buf, 1, size, f);
    fclose(f);
    free(buf);
}

void read_binary_test(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*)malloc(size);
    fread(buf, 1, size, f);
    fclose(f);
    unsigned int checksum = 0;
    for (long i = 0; i < size; i++) {
        checksum += buf[i];
    }
    printf("  Binary file: %ld bytes, checksum=%u\n", size, checksum);
    free(buf);
}

void test_file_operations() {
    char path[512];

    // CSV test
    snprintf(path, sizeof(path), "%s\\%sdata.csv", TEMP_DIR, TEST_PREFIX);
    printf("Writing CSV test data...\n");
    write_test_data(path, 1000);
    printf("Reading and verifying...\n");
    read_and_verify(path);

    // Binary test
    snprintf(path, sizeof(path), "%s\\%sbinary.bin", TEMP_DIR, TEST_PREFIX);
    printf("Writing binary test data (64KB)...\n");
    write_binary_test(path, 65536);
    printf("Reading and verifying...\n");
    read_binary_test(path);

    // Large file test
    snprintf(path, sizeof(path), "%s\\%slarge.dat", TEMP_DIR, TEST_PREFIX);
    printf("Writing large test data (256KB)...\n");
    write_binary_test(path, 262144);
    read_binary_test(path);

    // Text file with repeated writes (append mode)
    snprintf(path, sizeof(path), "%s\\%sappend.txt", TEMP_DIR, TEST_PREFIX);
    printf("Testing append mode...\n");
    for (int i = 0; i < 100; i++) {
        FILE* f = fopen(path, "a");
        if (f) {
            fprintf(f, "Line %d: This is an appended line of text for testing.\n", i);
            fclose(f);
        }
    }
    read_and_verify(path);

    // Temporary rename test
    char path2[512];
    snprintf(path2, sizeof(path2), "%s\\%srenamed.txt", TEMP_DIR, TEST_PREFIX);
    if (rename(path, path2) == 0) {
        printf("  Rename successful\n");
        read_and_verify(path2);
        remove(path2);
    }

    // Cleanup
    snprintf(path, sizeof(path), "%s\\%sdata.csv", TEMP_DIR, TEST_PREFIX);
    remove(path);
    snprintf(path, sizeof(path), "%s\\%sbinary.bin", TEMP_DIR, TEST_PREFIX);
    remove(path);
    snprintf(path, sizeof(path), "%s\\%slarge.dat", TEMP_DIR, TEST_PREFIX);
    remove(path);
    printf("  Cleanup complete\n");
}

int main() {
    printf("Category H: File I/O\n");
    printf("Tests basic file read/write operations in temp directory\n\n");
    test_file_operations();
    printf("\n=== Complete ===\n");
    return 0;
}
