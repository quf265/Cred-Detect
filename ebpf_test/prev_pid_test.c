#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define NUM_THREADS 8

// 공유 변수
int a = 0;

// 스레드에서 실행될 함수
void* add_one(void* arg) {
    for(int i = 0 ; i < 10000000 ; ++i)
    {
            a += 1;
            usleep(10000);
    }
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];

    // 스레드 생성
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, add_one, NULL) != 0) {
            fprintf(stderr, "Error creating thread\n");
            return 1;
        }
    }

    // 스레드 종료 대기
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "Error joining thread\n");
            return 2;
        }
    }

    // 결과 출력
    printf("Final value of a: %d\n", a);

    return 0;
}
