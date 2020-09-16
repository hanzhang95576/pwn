#include <stdio.h>
#include <stdlib.h>
long long  array[10] = {0};
void goal(){
	    system("sh");
}
int main(){
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);
	int idx;
	while(1){
		printf("index:");
		scanf("%d", &idx);
		printf("value:");
		scanf("%lld", &array[idx]);
		for (int i = 0; i < 10; ++i) {
			printf("%lld ", array[i]);
		}
		puts("");
	}
	return 0;
}
