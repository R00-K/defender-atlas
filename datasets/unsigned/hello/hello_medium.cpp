#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

const char* messages[] = {
    "Hello World - Medium Build",
    "DefenderAtlas Research Dataset - Extended",
    "This binary contains more code and data",
    "Category A: Hello World - Medium Size",
    "Multiple functions and string literals",
    "PE file structure analysis target",
    "Compiled for Windows x64 architecture",
    "MinGW GCC compiler used for build",
    "Unsigned executable - no digital signature",
    "Research use only - not malware",
    "Extended message buffer for size increase",
    "Mathematical operations included",
    "String manipulation routines present",
    "Standard library imports visible",
    "Process scan analysis target"
};

double compute_sum(double* arr, int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

double compute_average(double* arr, int n) {
    return compute_sum(arr, n) / n;
}

double compute_stddev(double* arr, int n) {
    double avg = compute_average(arr, n);
    double sum_sq = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = arr[i] - avg;
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq / n);
}

void bubble_sort(double* arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                double tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            }
        }
    }
}

int main() {
    for (int i = 0; i < 15; i++) {
        printf("[%02d] %s\n", i, messages[i]);
    }

    double data[100];
    for (int i = 0; i < 100; i++) {
        data[i] = (double)(i * 7 + 3) / (double)(i + 1);
    }

    printf("\nStatistical Analysis:\n");
    printf("  Sum: %.4f\n", compute_sum(data, 100));
    printf("  Average: %.4f\n", compute_average(data, 100));
    printf("  StdDev: %.4f\n", compute_stddev(data, 100));

    bubble_sort(data, 100);
    printf("  Median: %.4f\n", data[50]);

    char result[512];
    snprintf(result, sizeof(result),
        "Statistical summary complete. Sum=%.4f Avg=%.4f StdDev=%.4f Median=%.4f",
        compute_sum(data, 100), compute_average(data, 100),
        compute_stddev(data, 100), data[50]);
    printf("\n%s\n", result);

    return 0;
}
