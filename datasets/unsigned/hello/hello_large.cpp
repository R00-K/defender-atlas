#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>

const char* banner_lines[] = {
    "================================================================",
    "  DefenderAtlas Research Dataset - Hello World Large Build",
    "  Category A: Hello World - Large Size Target",
    "  This binary is designed to reach ~500KB+ file size",
    "  Contains extensive code and data sections",
    "  Compiled with MinGW GCC for Windows x64",
    "================================================================"
};

const char* sample_strings[] = {
    "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot",
    "Golf", "Hotel", "India", "Juliet", "Kilo", "Lima",
    "Mike", "November", "Oscar", "Papa", "Quebec", "Romeo",
    "Sierra", "Tango", "Uniform", "Victor", "Whiskey", "X-ray",
    "Yankee", "Zulu", "Alpha-2", "Bravo-2", "Charlie-2", "Delta-2"
};

double matrix_a[64][64];
double matrix_b[64][64];
double matrix_c[64][64];

void init_matrices() {
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            matrix_a[i][j] = sin((double)(i + j)) * 100.0;
            matrix_b[i][j] = cos((double)(i - j)) * 50.0;
            matrix_c[i][j] = 0.0;
        }
    }
}

void multiply_matrices() {
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            for (int k = 0; k < 64; k++) {
                matrix_c[i][j] += matrix_a[i][k] * matrix_b[k][j];
            }
        }
    }
}

double trace_matrix(double m[64][64]) {
    double t = 0.0;
    for (int i = 0; i < 64; i++) {
        t += m[i][i];
    }
    return t;
}

void transpose_matrix(double src[64][64], double dst[64][64]) {
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            dst[j][i] = src[i][j];
        }
    }
}

int fibonacci(int n) {
    if (n <= 1) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}

double factorial(int n) {
    double result = 1.0;
    for (int i = 2; i <= n; i++) {
        result *= i;
    }
    return result;
}

void generate_histogram(double* data, int n, int* bins, int num_bins) {
    double min_val = data[0], max_val = data[0];
    for (int i = 1; i < n; i++) {
        if (data[i] < min_val) min_val = data[i];
        if (data[i] > max_val) max_val = data[i];
    }
    double range = max_val - min_val;
    if (range == 0.0) range = 1.0;
    for (int i = 0; i < num_bins; i++) bins[i] = 0;
    for (int i = 0; i < n; i++) {
        int bin = (int)(((data[i] - min_val) / range) * (num_bins - 1));
        if (bin < 0) bin = 0;
        if (bin >= num_bins) bin = num_bins - 1;
        bins[bin]++;
    }
}

int main() {
    printf("=== DefenderAtlas Large Hello World ===\n\n");
    for (int i = 0; i < 6; i++) {
        printf("%s\n", banner_lines[i]);
    }

    printf("\n--- NATO Alphabet ---\n");
    for (int i = 0; i < 30; i++) {
        printf("  %2d: %s\n", i + 1, sample_strings[i]);
    }

    printf("\n--- Fibonacci Sequence ---\n");
    for (int i = 0; i < 30; i++) {
        printf("  F(%2d) = %d\n", i, fibonacci(i));
    }

    printf("\n--- Factorials ---\n");
    for (int i = 1; i <= 20; i++) {
        printf("  %2d! = %.0f\n", i, factorial(i));
    }

    printf("\n--- Matrix Operations (64x64) ---\n");
    clock_t start = clock();
    init_matrices();
    multiply_matrices();
    clock_t end = clock();
    printf("  Matrix multiply: %.4f seconds\n",
        (double)(end - start) / CLOCKS_PER_SEC);
    printf("  Trace(A): %.4f\n", trace_matrix(matrix_a));
    printf("  Trace(B): %.4f\n", trace_matrix(matrix_b));
    printf("  Trace(C=A*B): %.4f\n", trace_matrix(matrix_c));

    double transposed[64][64];
    transpose_matrix(matrix_a, transposed);
    printf("  Trace(A^T): %.4f\n", trace_matrix(transposed));

    printf("\n--- Histogram ---\n");
    double hist_data[1000];
    for (int i = 0; i < 1000; i++) {
        hist_data[i] = sin((double)i * 0.01) * 100.0 + 100.0;
    }
    int bins[20];
    generate_histogram(hist_data, 1000, bins, 20);
    for (int i = 0; i < 20; i++) {
        printf("  Bin %2d: %d\n", i, bins[i]);
    }

    printf("\n--- String Operations ---\n");
    char combined[2048];
    combined[0] = '\0';
    for (int i = 0; i < 30; i++) {
        strcat(combined, sample_strings[i]);
        strcat(combined, " ");
    }
    printf("  Combined: %s\n", combined);
    printf("  Length: %zu\n", strlen(combined));

    printf("\n=== Complete ===\n");
    return 0;
}
