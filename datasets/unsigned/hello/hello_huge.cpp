#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>

// Large arrays to inflate binary size significantly
static double large_data_array[50000];
static int large_int_array[50000];
static char large_string_buffer[200000];

const char* lorem_lines[] = {
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
    "Ut enim ad minim veniam, quis nostrud exercitation ullamco.",
    "Laboris nisi ut aliquip ex ea commodo consequat.",
    "Duis aute irure dolor in reprehenderit in voluptate velit esse.",
    "Cillum dolore eu fugiat nulla pariatur.",
    "Excepteur sint occaecat cupidatat non proident.",
    "Sunt in culpa qui officia deserunt mollit anim id est laborum.",
    "Sed ut perspiciatis unde omnis iste natus error sit voluptatem.",
    "Accusantium doloremque laudantium, totam rem aperiam.",
    "Eaque ipsa quae ab illo inventore veritatis et quasi architecto.",
    "Beatae vitae dicta sunt explicabo.",
    "Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit.",
    "Aut fugit, sed quia consequuntur magni dolores eos qui ratione.",
    "Voluptatem sequi nesciunt, neque porro quisquam est.",
    "Qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit.",
    "Sed quia non numquam eius modi tempora incidunt ut labore.",
    "Et dolore magnam aliquam quaerat voluptatem.",
    "Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis.",
    "Suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur?"
};

const char* function_names[] = {
    "InitializeComponent", "ProcessRequest", "ValidateInput",
    "TransformData", "SerializeOutput", "ParseHeader",
    "AuthenticateUser", "CheckPermission", "LogActivity",
    "CacheResult", "CompressData", "EncryptPayload",
    "DecryptMessage", "HashContent", "VerifyIntegrity",
    "RouteRequest", "LoadConfiguration", "UnloadModule",
    "StartService", "StopService", "PauseExecution",
    "ResumeExecution", "HandleException", "RecoverState",
    "SyncDatabase", "FlushBuffer", "AllocateMemory",
    "ReleaseMemory", "TrackResource", "GarbageCollect"
};

void initialize_arrays() {
    for (int i = 0; i < 50000; i++) {
        large_data_array[i] = sin((double)i * 0.001) * cos((double)i * 0.002);
        large_int_array[i] = (i * 2654435761) & 0x7FFFFFFF;
    }
}

void populate_strings() {
    int pos = 0;
    for (int i = 0; i < 20; i++) {
        int len = strlen(lorem_lines[i]);
        memcpy(large_string_buffer + pos, lorem_lines[i], len);
        pos += len;
        large_string_buffer[pos++] = '\n';
    }
    large_string_buffer[pos] = '\0';
}

double compute_entropy(double* data, int n) {
    double min_val = data[0], max_val = data[0];
    for (int i = 1; i < n; i++) {
        if (data[i] < min_val) min_val = data[i];
        if (data[i] > max_val) max_val = data[i];
    }
    double range = max_val - min_val;
    if (range == 0.0) return 0.0;
    int bins[256] = {0};
    for (int i = 0; i < n; i++) {
        int bin = (int)(((data[i] - min_val) / range) * 255.0);
        if (bin < 0) bin = 0;
        if (bin > 255) bin = 255;
        bins[bin]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (bins[i] > 0) {
            double p = (double)bins[i] / (double)n;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

void matrix_multiply_large(double* a, double* b, double* c, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            double sum = 0.0;
            for (int k = 0; k < n; k++) {
                sum += a[i * n + k] * b[k * n + j];
            }
            c[i * n + j] = sum;
        }
    }
}

int quicksort_partition(double* arr, int low, int high) {
    double pivot = arr[high];
    int i = low - 1;
    for (int j = low; j < high; j++) {
        if (arr[j] <= pivot) {
            i++;
            double tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
        }
    }
    double tmp = arr[i + 1]; arr[i + 1] = arr[high]; arr[high] = tmp;
    return i + 1;
}

void quicksort(double* arr, int low, int high) {
    if (low < high) {
        int pi = quicksort_partition(arr, low, high);
        quicksort(arr, low, pi - 1);
        quicksort(arr, pi + 1, high);
    }
}

int main() {
    printf("=== DefenderAtlas Hello World HUGE Build ===\n");
    printf("This binary is designed to be very large (~10-20MB)\n\n");

    clock_t start = clock();

    printf("Initializing large arrays...\n");
    initialize_arrays();

    printf("Populating string buffer...\n");
    populate_strings();

    printf("\n--- String Content ---\n");
    printf("%s\n", large_string_buffer);

    printf("\n--- Function Names (%d entries) ---\n", 30);
    for (int i = 0; i < 30; i++) {
        printf("  [%2d] %s\n", i, function_names[i]);
    }

    printf("\n--- Data Analysis ---\n");
    printf("  Array entropy: %.4f bits\n",
        compute_entropy(large_data_array, 50000));

    double* sort_copy = (double*)malloc(50000 * sizeof(double));
    memcpy(sort_copy, large_data_array, 50000 * sizeof(double));
    clock_t sort_start = clock();
    quicksort(sort_copy, 0, 49999);
    clock_t sort_end = clock();
    printf("  Sort time: %.4f seconds\n",
        (double)(sort_end - sort_start) / CLOCKS_PER_SEC);
    printf("  Min: %.6f\n", sort_copy[0]);
    printf("  Max: %.6f\n", sort_copy[49999]);
    printf("  Median: %.6f\n", sort_copy[25000]);
    free(sort_copy);

    printf("\n--- Matrix Multiplication (128x128) ---\n");
    int mat_size = 128;
    double* mat_a = (double*)calloc(mat_size * mat_size, sizeof(double));
    double* mat_b = (double*)calloc(mat_size * mat_size, sizeof(double));
    double* mat_c = (double*)calloc(mat_size * mat_size, sizeof(double));
    for (int i = 0; i < mat_size * mat_size; i++) {
        mat_a[i] = sin((double)i) * 10.0;
        mat_b[i] = cos((double)i) * 10.0;
    }
    clock_t mat_start = clock();
    matrix_multiply_large(mat_a, mat_b, mat_c, mat_size);
    clock_t mat_end = clock();
    printf("  Time: %.4f seconds\n",
        (double)(mat_end - mat_start) / CLOCKS_PER_SEC);
    free(mat_a); free(mat_b); free(mat_c);

    printf("\n--- Integer Array Stats ---\n");
    long long sum = 0;
    int min_val = large_int_array[0], max_val = large_int_array[0];
    for (int i = 0; i < 50000; i++) {
        sum += large_int_array[i];
        if (large_int_array[i] < min_val) min_val = large_int_array[i];
        if (large_int_array[i] > max_val) max_val = large_int_array[i];
    }
    printf("  Sum: %lld\n", sum);
    printf("  Min: %d\n", min_val);
    printf("  Max: %d\n", max_val);
    printf("  Avg: %.2f\n", (double)sum / 50000.0);

    clock_t end = clock();
    printf("\nTotal execution time: %.4f seconds\n",
        (double)(end - start) / CLOCKS_PER_SEC);
    printf("=== Complete ===\n");
    return 0;
}
