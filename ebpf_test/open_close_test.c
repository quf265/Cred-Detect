#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

int main(void) {
    int i;
    int file_descriptor;
    clock_t start, end;
    double cpu_time_used;
    sleep(1);
    start = clock();

    for (i = 0; i < 100000; i++) {
        file_descriptor = open("open_close_test_file", O_RDONLY);

        if (file_descriptor < 0) {
            perror("File open error");
            return 1;
        }

        if (close(file_descriptor) < 0) {
            perror("File close error");
            return 1;
        }

    }

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("Time used: %f seconds\n", cpu_time_used);

    return 0;
}
