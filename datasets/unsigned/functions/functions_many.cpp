#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

// Many distinct functions to create a larger .text section

double func_001(double a, double b) { return a + b; }
double func_002(double a, double b) { return a - b; }
double func_003(double a, double b) { return a * b; }
double func_004(double a, double b) { return b != 0 ? a / b : 0; }
double func_005(double a) { return a * a; }
double func_006(double a) { return a * a * a; }
double func_007(double a) { return sqrt(fabs(a)); }
double func_008(double a) { return fabs(a); }
double func_009(double a) { return -a; }
double func_010(double a) { return 1.0 / a; }
double func_011(double a, double b) { return fmax(a, b); }
double func_012(double a, double b) { return fmin(a, b); }
double func_013(double base, double exp) { return pow(base, exp); }
double func_014(double a) { return log(a > 0 ? a : 1.0); }
double func_015(double a) { return exp(a); }
double func_016(double a) { return sin(a); }
double func_017(double a) { return cos(a); }
double func_018(double a) { return tan(a); }
double func_019(double a) { return asin(fmax(-1.0, fmin(1.0, a))); }
double func_020(double a) { return acos(fmax(-1.0, fmin(1.0, a))); }
double func_021(double a) { return atan(a); }
double func_022(double a, double b) { return atan2(a, b); }
double func_023(double a) { return ceil(a); }
double func_024(double a) { return floor(a); }
double func_025(double a) { return round(a); }
double func_026(double a) { return trunc(a); }
double func_027(double a) { return fmod(a, 3.0); }
double func_028(double a) { return sinh(a); }
double func_029(double a) { return cosh(a); }
double func_030(double a) { return tanh(a); }
int func_031(int a, int b) { return a & b; }
int func_032(int a, int b) { return a | b; }
int func_033(int a, int b) { return a ^ b; }
int func_034(int a) { return ~a; }
int func_035(int a, int b) { return a << b; }
int func_036(int a, int b) { return a >> b; }
int func_037(int a, int b) { return a + b; }
int func_038(int a, int b) { return a - b; }
int func_039(int a, int b) { return a * b; }
int func_040(int a, int b) { return b != 0 ? a / b : 0; }
int func_041(int a, int b) { return b != 0 ? a % b : 0; }
int func_042(int a) { return a > 0 ? a : -a; }
int func_043(int a, int b) { return a > b ? a : b; }
int func_044(int a, int b) { return a < b ? a : b; }
int func_045(int a) { int r=1; for(int i=0;i<a&&i<20;i++) r*=2; return r; }
int func_046(int n) { int s=0; for(int i=1;i<=n;i++) s+=i; return s; }
int func_047(int n) { int f=1; for(int i=2;i<=n;i++) f*=i; return f; }
int func_048(int n) { int a=0,b=1; for(int i=2;i<=n;i++){int t=a+b;a=b;b=t;} return b; }
int func_049(int n) { int c=0; while(n){n&=(n-1);c++;} return c; }
int func_050(int n) { int r=0; while(n){r=r*10+n%10;n/=10;} return r; }
void func_051(int arr[], int n) {
    for (int i = 0; i < n-1; i++)
        for (int j = 0; j < n-i-1; j++)
            if (arr[j] > arr[j+1]) { int t=arr[j]; arr[j]=arr[j+1]; arr[j+1]=t; }
}
void func_052(int arr[], int n) {
    for (int i = 1; i < n; i++) {
        int key = arr[i], j = i - 1;
        while (j >= 0 && arr[j] > key) { arr[j+1] = arr[j]; j--; }
        arr[j+1] = key;
    }
}
int func_053(int arr[], int n, int target) {
    for (int i = 0; i < n; i++) if (arr[i] == target) return i;
    return -1;
}
int func_054(int arr[], int n, int target) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (arr[mid] == target) return mid;
        if (arr[mid] < target) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}
void func_055(int arr[], int n) {
    for (int i = 0, j = n-1; i < j; i++, j--) { int t=arr[i]; arr[i]=arr[j]; arr[j]=t; }
}
void func_056(int a[], int b[], int c[], int n) {
    for (int i = 0; i < n; i++) c[i] = a[i] + b[i];
}
void func_057(int src[], int dst[], int n) {
    for (int i = 0; i < n; i++) dst[i] = src[i];
}
int func_058(int arr[], int n) { int m=arr[0]; for(int i=1;i<n;i++) if(arr[i]>m) m=arr[i]; return m; }
int func_059(int arr[], int n) { int m=arr[0]; for(int i=1;i<n;i++) if(arr[i]<m) m=arr[i]; return m; }
double func_060(int arr[], int n) { long long s=0; for(int i=0;i<n;i++) s+=arr[i]; return (double)s/n; }
void func_061(double arr[], int n) {
    for (int i = 0; i < n-1; i++)
        for (int j = 0; j < n-i-1; j++)
            if (arr[j] > arr[j+1]) { double t=arr[j]; arr[j]=arr[j+1]; arr[j+1]=t; }
}
double func_062(double arr[], int n) {
    double s = 0;
    for (int i = 0; i < n; i++) s += arr[i] * arr[i];
    return sqrt(s);
}
double func_063(double a[], double b[], int n) {
    double dot = 0;
    for (int i = 0; i < n; i++) dot += a[i] * b[i];
    return dot;
}
void func_064(double a[], double b[], double c[], int n) {
    for (int i = 0; i < n; i++) c[i] = a[i] * b[i];
}
double func_065(double a[], int n) {
    double m = func_060((int*)0, 0);
    double sum = 0;
    for (int i = 0; i < n; i++) {
        double diff = a[i] - m;
        sum += diff * diff;
    }
    return sum / n;
}

int main() {
    printf("Category E: Many Functions\n");
    printf("Binary contains 65+ distinct functions\n\n");

    printf("Math operations:\n");
    printf("  2 + 3 = %.0f\n", func_001(2, 3));
    printf("  2 * 3 = %.0f\n", func_003(2, 3));
    printf("  sqrt(144) = %.0f\n", func_007(144));
    printf("  sin(pi/2) = %.4f\n", func_016(3.14159265 / 2));
    printf("  cos(0) = %.4f\n", func_017(0));

    printf("\nInteger operations:\n");
    printf("  5 & 3 = %d\n", func_031(5, 3));
    printf("  5 | 3 = %d\n", func_032(5, 3));
    printf("  5 ^ 3 = %d\n", func_033(5, 3));
    printf("  popcount(255) = %d\n", func_049(255));
    printf("  reverse(12345) = %d\n", func_050(12345));
    printf("  fib(10) = %d\n", func_048(10));
    printf("  factorial(10) = %d\n", func_047(10));

    printf("\nArray operations:\n");
    int arr[] = {64, 25, 12, 22, 11, 90, 45, 73, 18, 55};
    int n = 10;
    printf("  Before sort: ");
    for (int i = 0; i < n; i++) printf("%d ", arr[i]);
    printf("\n");
    func_051(arr, n);
    printf("  After sort:  ");
    for (int i = 0; i < n; i++) printf("%d ", arr[i]);
    printf("\n");
    printf("  Min: %d, Max: %d\n", func_059(arr, n), func_058(arr, n));
    printf("  Search(22): index=%d\n", func_053(arr, n, 22));

    double darr[] = {3.14, 2.71, 1.41, 1.73, 2.23};
    printf("  Vector norm: %.4f\n", func_062(darr, 5));

    printf("\n=== Complete ===\n");
    return 0;
}
