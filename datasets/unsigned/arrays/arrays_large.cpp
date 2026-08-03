#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

// Large static arrays to inflate .data and .bss sections
static unsigned char tiny_array[10240];
static unsigned char small_array[51200];
static unsigned char medium_array[102400];
static int int_array_small[2560];
static int int_array_medium[12800];
static int int_array_large[128000];
static double double_array_small[1280];
static double double_array_medium[6400];
static double double_array_large[64000];
static float float_array_medium[25600];

// Initialized data arrays
static char initialized_buffer[102400];

// Struct arrays
typedef struct {
    int id;
    double x, y, z;
    char name[64];
    double values[8];
} SampleRecord;

static SampleRecord records[500];

void init_records() {
    for (int i = 0; i < 500; i++) {
        records[i].id = i;
        records[i].x = sin((double)i) * 1000.0;
        records[i].y = cos((double)i) * 1000.0;
        records[i].z = tan((double)i * 0.01) * 100.0;
        snprintf(records[i].name, 64, "Record_%04d_Sample", i);
        for (int j = 0; j < 8; j++) {
            records[i].values[j] = (double)(i * 8 + j) * 3.14159;
        }
    }
}

void process_arrays() {
    // Fill tiny array
    for (int i = 0; i < 10240; i++) {
        tiny_array[i] = (unsigned char)((i * 37 + 13) & 0xFF);
    }

    // Fill small array
    for (int i = 0; i < 51200; i++) {
        small_array[i] = (unsigned char)((i * 73 + 29) & 0xFF);
    }

    // Fill medium array
    for (int i = 0; i < 102400; i++) {
        medium_array[i] = (unsigned char)(i % 256);
    }

    // Integer arrays
    for (int i = 0; i < 128000; i++) {
        int_array_large[i] = i * 6364136223846793005LL & 0x7FFFFFFF;
    }
    for (int i = 0; i < 12800; i++) {
        int_array_medium[i] = int_array_large[i];
    }
    for (int i = 0; i < 2560; i++) {
        int_array_small[i] = int_array_large[i];
    }

    // Double arrays
    for (int i = 0; i < 64000; i++) {
        double_array_large[i] = sin((double)i * 0.001) * 1000.0;
    }
    for (int i = 0; i < 6400; i++) {
        double_array_medium[i] = double_array_large[i];
    }
    for (int i = 0; i < 1280; i++) {
        double_array_small[i] = double_array_large[i];
    }

    // Float array
    for (int i = 0; i < 25600; i++) {
        float_array_medium[i] = (float)cos((double)i * 0.01);
    }

    // Initialized buffer
    const char* fill = "DefenderAtlas Dataset - Arrays Category - Padding data for size inflation - ";
    int fillLen = strlen(fill);
    for (int i = 0; i < 102400; i++) {
        initialized_buffer[i] = fill[i % fillLen];
    }
}

double compute_array_stats() {
    double sum = 0.0;
    for (int i = 0; i < 128000; i++) {
        sum += (double)int_array_large[i];
    }
    return sum;
}

int main() {
    printf("Category C: Large Global Arrays\n");
    printf("Binary contains multiple large static arrays\n\n");

    init_records();
    process_arrays();

    printf("Tiny array: %d bytes\n", (int)sizeof(tiny_array));
    printf("Small array: %d bytes\n", (int)sizeof(small_array));
    printf("Medium array: %d bytes\n", (int)sizeof(medium_array));
    printf("Int large array: %d bytes\n", (int)sizeof(int_array_large));
    printf("Double large array: %d bytes\n", (int)sizeof(double_array_large));
    printf("SampleRecord array: %d bytes (%d records)\n",
        (int)sizeof(records), 500);
    printf("Initialized buffer: %d bytes\n", (int)sizeof(initialized_buffer));

    double stats = compute_array_stats();
    printf("\nSum of int_array_large: %.0f\n", stats);

    // Print some records
    printf("\nSample records:\n");
    for (int i = 0; i < 5; i++) {
        printf("  [%d] id=%d name='%s' x=%.2f y=%.2f z=%.2f\n",
            i, records[i].id, records[i].name,
            records[i].x, records[i].y, records[i].z);
    }

    printf("\nFirst 32 bytes of tiny_array (hex):\n  ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", tiny_array[i]);
    }
    printf("\n");

    printf("\n=== Complete ===\n");
    return 0;
}
