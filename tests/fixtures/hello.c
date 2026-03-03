#include <stdio.h>

int add_numbers(int a, int b) {
    return a + b;
}

int main(void) {
    printf("Hello %d\n", add_numbers(1, 2));
    return 0;
}
