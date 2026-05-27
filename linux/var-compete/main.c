#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

int comp(const void *a, const void *b) {
    return ((*(int **)a)[0] - (*(int **)b)[0]);
}

int solution(int** info, size_t info_rows, size_t info_cols, int n, int m) {
    int answer = 0;
    int bnswer = 0;
    int** sortasc_for_a = malloc(info_rows * sizeof(int*));
    for(int i = 0; i < info_rows; i++){
        bnswer += info[i][1];
        sortasc_for_a[i] = info[i];
    }
    qsort(sortasc_for_a, info_rows, sizeof(int*), comp);
    if(bnswer < m){
        goto end;
    }
    for(int i = 0; i < info_rows; i++){
        answer += sortasc_for_a[i][0];
        bnswer -= sortasc_for_a[i][1];
        if(answer < n && bnswer < m){
            goto end;
        }
        if(answer >= n && bnswer >= m){
            answer = -1;
            break;
        }   
    }
end:
    free(sortasc_for_a);
    return answer;
}




int main(){
    int **info = malloc(3 * sizeof(int*));
    for(int i = 0; i < 3; i++){
        info[i] = malloc(2 * sizeof(int));
    }
    info[0][0] = 1;
    info[0][1] = 2;
    info[1][0] = 2;
    info[1][1] = 3;
    info[2][0] = 2;
    info[2][1] = 1;
    int ans = solution(info, 3, 2, 4, 4);
    printf("%d\n", ans);
    return 0;
}