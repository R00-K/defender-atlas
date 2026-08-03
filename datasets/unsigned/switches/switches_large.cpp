#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

// Large switch statements to create complex control flow

int process_month(int month) {
    switch (month) {
        case 1: return 31;
        case 2: return 28;
        case 3: return 31;
        case 4: return 30;
        case 5: return 31;
        case 6: return 30;
        case 7: return 31;
        case 8: return 31;
        case 9: return 30;
        case 10: return 31;
        case 11: return 30;
        case 12: return 31;
        default: return -1;
    }
}

const char* month_name(int month) {
    switch (month) {
        case 1: return "January";
        case 2: return "February";
        case 3: return "March";
        case 4: return "April";
        case 5: return "May";
        case 6: return "June";
        case 7: return "July";
        case 8: return "August";
        case 9: return "September";
        case 10: return "October";
        case 11: return "November";
        case 12: return "December";
        default: return "Unknown";
    }
}

const char* day_of_week(int day) {
    switch (day) {
        case 0: return "Sunday";
        case 1: return "Monday";
        case 2: return "Tuesday";
        case 3: return "Wednesday";
        case 4: return "Thursday";
        case 5: return "Friday";
        case 6: return "Saturday";
        default: return "Invalid";
    }
}

int classify_ascii(int ch) {
    switch (ch) {
        case 0x20: return 1; // space
        case 0x09: return 2; // tab
        case 0x0A: return 3; // newline
        case 0x0D: return 4; // carriage return
        case 0x21: case 0x40: case 0x23: case 0x24:
        case 0x25: case 0x5E: case 0x26: case 0x2A:
        case 0x28: case 0x29: case 0x2D: case 0x5F:
        case 0x2B: case 0x3D: case 0x7B: case 0x7D:
        case 0x5B: case 0x5D: case 0x7C: case 0x5C:
        case 0x3A: case 0x3B: case 0x22: case 0x27:
        case 0x3C: case 0x3E: case 0x2C: case 0x2E:
        case 0x2F: case 0x3F: case 0x60: case 0x7E:
            return 5; // special char
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x34: case 0x35: case 0x36: case 0x37:
        case 0x38: case 0x39:
            return 6; // digit
        default:
            if (ch >= 0x41 && ch <= 0x5A) return 7; // uppercase
            if (ch >= 0x61 && ch <= 0x7A) return 8; // lowercase
            return 9; // other
    }
}

const char* classify_name(int cls) {
    switch (cls) {
        case 1: return "Space";
        case 2: return "Tab";
        case 3: return "Newline";
        case 4: return "CR";
        case 5: return "Special";
        case 6: return "Digit";
        case 7: return "Uppercase";
        case 8: return "Lowercase";
        case 9: return "Other";
        default: return "Unknown";
    }
}

double compute_operation(int op, double a, double b) {
    switch (op) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return b != 0 ? a / b : 0;
        case 4: return b != 0 ? fmod(a, b) : 0;
        case 5: return pow(a, b);
        case 6: return fmax(a, b);
        case 7: return fmin(a, b);
        case 8: return fabs(a - b);
        case 9: return sqrt(a * a + b * b);
        case 10: return atan2(a, b);
        case 11: return log(a > 0 ? a : 1) - log(b > 0 ? b : 1);
        default: return 0;
    }
}

const char* op_name(int op) {
    switch (op) {
        case 0: return "ADD";
        case 1: return "SUB";
        case 2: return "MUL";
        case 3: return "DIV";
        case 4: return "MOD";
        case 5: return "POW";
        case 6: return "MAX";
        case 7: return "MIN";
        case 8: return "ABS_DIFF";
        case 9: return "HYPOT";
        case 10: return "ATAN2";
        case 11: return "LOG_RATIO";
        default: return "UNKNOWN";
    }
}

const char* state_name(int state) {
    switch (state) {
        case 0: return "IDLE";
        case 1: return "INITIALIZING";
        case 2: return "RUNNING";
        case 3: return "PAUSED";
        case 4: return "STOPPING";
        case 5: return "STOPPED";
        case 6: return "ERROR";
        case 7: return "RECOVERING";
        case 8: return "MAINTENANCE";
        case 9: return "STANDBY";
        case 10: return "OFFLINE";
        case 11: return "ONLINE";
        case 12: return "SYNCING";
        case 13: return "READY";
        case 14: return "PROCESSING";
        case 15: return "COMPLETE";
        default: return "UNDEFINED";
    }
}

int process_large_switch(int x) {
    int result = 0;
    for (int i = 0; i < 100; i++) {
        switch ((x + i) % 20) {
            case 0: result += i * 1; break;
            case 1: result += i * 2; break;
            case 2: result += i * 3; break;
            case 3: result += i * 4; break;
            case 4: result += i * 5; break;
            case 5: result += i * 6; break;
            case 6: result += i * 7; break;
            case 7: result += i * 8; break;
            case 8: result += i * 9; break;
            case 9: result += i * 10; break;
            case 10: result -= i * 1; break;
            case 11: result -= i * 2; break;
            case 12: result -= i * 3; break;
            case 13: result -= i * 4; break;
            case 14: result -= i * 5; break;
            case 15: result -= i * 6; break;
            case 16: result ^= i * 7; break;
            case 17: result ^= i * 8; break;
            case 18: result |= i * 9; break;
            case 19: result &= (i * 10 + 1); break;
        }
    }
    return result;
}

int main() {
    printf("Category F: Large Switch Statements\n\n");

    printf("--- Month Processing ---\n");
    for (int m = 1; m <= 12; m++) {
        printf("  %s: %d days\n", month_name(m), process_month(m));
    }

    printf("\n--- Day of Week ---\n");
    for (int d = 0; d < 7; d++) {
        printf("  %d = %s\n", d, day_of_week(d));
    }

    printf("\n--- ASCII Classification ---\n");
    const char* test_chars = "Hello World! 123 @#$";
    for (int i = 0; test_chars[i]; i++) {
        int cls = classify_ascii(test_chars[i]);
        printf("  '%c' (0x%02X) = %s\n", test_chars[i], test_chars[i], classify_name(cls));
    }

    printf("\n--- Math Operations ---\n");
    for (int op = 0; op < 12; op++) {
        printf("  %s(10, 3) = %.4f\n", op_name(op), compute_operation(op, 10, 3));
    }

    printf("\n--- State Machine ---\n");
    for (int s = 0; s <= 15; s++) {
        printf("  State %2d = %s\n", s, state_name(s));
    }

    printf("\n--- Large Switch Computation ---\n");
    for (int x = 0; x < 10; x++) {
        printf("  process_large_switch(%d) = %d\n", x, process_large_switch(x));
    }

    printf("\n=== Complete ===\n");
    return 0;
}
