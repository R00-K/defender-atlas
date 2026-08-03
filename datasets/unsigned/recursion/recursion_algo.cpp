#include <cstdio>
#include <cstdlib>
#include <cstring>

// Recursive algorithms - creates stack usage patterns

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int fibonacci(int n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int gcd(int a, int b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

int power(int base, int exp) {
    if (exp == 0) return 1;
    if (exp % 2 == 0) {
        int half = power(base, exp / 2);
        return half * half;
    }
    return base * power(base, exp - 1);
}

int sum_digits(int n) {
    if (n < 10) return n;
    return (n % 10) + sum_digits(n / 10);
}

int count_bits(unsigned int n) {
    if (n == 0) return 0;
    return (n & 1) + count_bits(n >> 1);
}

void hanoi(int n, char from, char to, char aux) {
    if (n == 0) return;
    hanoi(n - 1, from, aux, to);
    printf("  Move disk %d from %c to %c\n", n, from, to);
    hanoi(n - 1, aux, to, from);
}

void merge(int arr[], int left, int mid, int right) {
    int n1 = mid - left + 1;
    int n2 = right - mid;
    int* L = (int*)malloc(n1 * sizeof(int));
    int* R = (int*)malloc(n2 * sizeof(int));
    for (int i = 0; i < n1; i++) L[i] = arr[left + i];
    for (int j = 0; j < n2; j++) R[j] = arr[mid + 1 + j];
    int i = 0, j = 0, k = left;
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) arr[k++] = L[i++];
        else arr[k++] = R[j++];
    }
    while (i < n1) arr[k++] = L[i++];
    while (j < n2) arr[k++] = R[j++];
    free(L);
    free(R);
}

void merge_sort(int arr[], int left, int right) {
    if (left >= right) return;
    int mid = left + (right - left) / 2;
    merge_sort(arr, left, mid);
    merge_sort(arr, mid + 1, right);
    merge(arr, left, mid, right);
}

void quicksort(int arr[], int low, int high) {
    if (low >= high) return;
    int pivot = arr[high];
    int i = low - 1;
    for (int j = low; j < high; j++) {
        if (arr[j] < pivot) {
            i++;
            int tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
        }
    }
    int tmp = arr[i + 1]; arr[i + 1] = arr[high]; arr[high] = tmp;
    int pi = i + 1;
    quicksort(arr, low, pi - 1);
    quicksort(arr, pi + 1, high);
}

int tree_height(int n) {
    if (n == 0) return 0;
    return 1 + tree_height(n / 2);
}

int ackermann(int m, int n) {
    if (m == 0) return n + 1;
    if (n == 0) return ackermann(m - 1, 1);
    return ackermann(m - 1, ackermann(m, n - 1));
}

int collatz_length(long long n) {
    if (n == 1) return 0;
    if (n % 2 == 0) return 1 + collatz_length(n / 2);
    return 1 + collatz_length(3 * n + 1);
}

int main() {
    printf("Category G: Recursive Algorithms\n\n");

    printf("--- Factorial ---\n");
    for (int i = 0; i <= 15; i++) {
        printf("  %2d! = %d\n", i, factorial(i));
    }

    printf("\n--- Fibonacci (naive recursion) ---\n");
    for (int i = 0; i <= 20; i++) {
        printf("  fib(%2d) = %d\n", i, fibonacci(i));
    }

    printf("\n--- GCD ---\n");
    printf("  gcd(48, 18) = %d\n", gcd(48, 18));
    printf("  gcd(100, 75) = %d\n", gcd(100, 75));
    printf("  gcd(1071, 462) = %d\n", gcd(1071, 462));

    printf("\n--- Power ---\n");
    for (int i = 0; i <= 10; i++) {
        printf("  2^%d = %d\n", i, power(2, i));
    }

    printf("\n--- Sum of Digits ---\n");
    printf("  sum_digits(12345) = %d\n", sum_digits(12345));
    printf("  sum_digits(999999) = %d\n", sum_digits(999999));

    printf("\n--- Bit Count ---\n");
    for (int i = 0; i <= 16; i++) {
        printf("  count_bits(%2d) = %d\n", i, count_bits(i));
    }

    printf("\n--- Tower of Hanoi (4 disks) ---\n");
    hanoi(4, 'A', 'C', 'B');

    printf("\n--- Merge Sort ---\n");
    int arr1[] = {38, 27, 43, 3, 9, 82, 10, 55, 12, 7, 41, 63};
    int n1 = 12;
    printf("  Before: ");
    for (int i = 0; i < n1; i++) printf("%d ", arr1[i]);
    printf("\n");
    merge_sort(arr1, 0, n1 - 1);
    printf("  After:  ");
    for (int i = 0; i < n1; i++) printf("%d ", arr1[i]);
    printf("\n");

    printf("\n--- Quick Sort ---\n");
    int arr2[] = {10, 7, 8, 9, 1, 5, 3, 4, 2, 6};
    int n2 = 10;
    printf("  Before: ");
    for (int i = 0; i < n2; i++) printf("%d ", arr2[i]);
    printf("\n");
    quicksort(arr2, 0, n2 - 1);
    printf("  After:  ");
    for (int i = 0; i < n2; i++) printf("%d ", arr2[i]);
    printf("\n");

    printf("\n--- Tree Height ---\n");
    for (int i = 1; i <= 1024; i *= 2) {
        printf("  tree_height(%d) = %d\n", i, tree_height(i));
    }

    printf("\n--- Ackermann ---\n");
    for (int m = 0; m <= 3; m++) {
        for (int n = 0; n <= 6; n++) {
            printf("  A(%d,%d) = %d\n", m, n, ackermann(m, n));
        }
    }

    printf("\n--- Collatz Sequence Length ---\n");
    for (int i = 1; i <= 20; i++) {
        printf("  collatz(%2d) = %d steps\n", i, collatz_length(i));
    }

    printf("\n=== Complete ===\n");
    return 0;
}
