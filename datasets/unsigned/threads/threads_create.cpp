#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")

// Thread creation - creates threads that do minimal work

volatile int shared_counter = 0;
volatile int stop_flag = 0;

CRITICAL_SECTION cs;

DWORD WINAPI worker_thread(LPVOID param) {
    int thread_id = *(int*)param;
    int iterations = 0;

    while (!stop_flag && iterations < 100000) {
        EnterCriticalSection(&cs);
        shared_counter++;
        LeaveCriticalSection(&cs);
        iterations++;

        // Simulate some work
        volatile int x = 0;
        for (int i = 0; i < 10; i++) {
            x += i;
        }
    }

    printf("  Thread %d finished after %d iterations\n", thread_id, iterations);
    return 0;
}

DWORD WINAPI io_thread(LPVOID param) {
    int thread_id = *(int*)param;
    char buffer[1024];

    for (int i = 0; i < 100 && !stop_flag; i++) {
        snprintf(buffer, sizeof(buffer),
            "Thread %d: Processing item %d", thread_id, i);
        volatile int len = strlen(buffer);

        // Simulate processing
        volatile int result = 0;
        for (int j = 0; j < len; j++) {
            result += buffer[j];
        }
    }

    printf("  IO Thread %d finished\n", thread_id);
    return 0;
}

DWORD WINAPI timer_thread(LPVOID param) {
    int count = 0;
    while (!stop_flag && count < 50) {
        Sleep(10);
        count++;
    }
    printf("  Timer thread finished after %d ticks\n", count);
    return 0;
}

int main() {
    printf("Category J: Thread Creation\n");
    printf("Creates multiple threads with synchronization\n\n");

    InitializeCriticalSection(&cs);

    #define NUM_WORKERS 4
    #define NUM_IO 2

    HANDLE worker_handles[NUM_WORKERS];
    HANDLE io_handles[NUM_IO];
    HANDLE timer_handle;
    int worker_ids[NUM_WORKERS];
    int io_ids[NUM_IO];

    printf("Starting %d worker threads...\n", NUM_WORKERS);
    for (int i = 0; i < NUM_WORKERS; i++) {
        worker_ids[i] = i;
        worker_handles[i] = CreateThread(NULL, 0, worker_thread,
            &worker_ids[i], 0, NULL);
    }

    printf("Starting %d IO threads...\n", NUM_IO);
    for (int i = 0; i < NUM_IO; i++) {
        io_ids[i] = i;
        io_handles[i] = CreateThread(NULL, 0, io_thread,
            &io_ids[i], 0, NULL);
    }

    printf("Starting timer thread...\n");
    timer_handle = CreateThread(NULL, 0, timer_thread, NULL, 0, NULL);

    // Wait for all threads
    printf("\nWaiting for all threads...\n");
    WaitForMultipleObjects(NUM_WORKERS, worker_handles, TRUE, INFINITE);
    WaitForMultipleObjects(NUM_IO, io_handles, TRUE, INFINITE);
    WaitForSingleObject(timer_handle, INFINITE);

    // Signal stop and wait for timer
    stop_flag = 1;
    WaitForSingleObject(timer_handle, INFINITE);

    // Close handles
    for (int i = 0; i < NUM_WORKERS; i++) CloseHandle(worker_handles[i]);
    for (int i = 0; i < NUM_IO; i++) CloseHandle(io_handles[i]);
    CloseHandle(timer_handle);

    DeleteCriticalSection(&cs);

    printf("\nFinal shared counter: %d\n", shared_counter);
    printf("All threads completed.\n");
    printf("=== Complete ===\n");
    return 0;
}
