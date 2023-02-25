#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

//https://blog.51cto.com/u_13919520/3153010

#define MAX_INFO_LEN 64

int intialize_data (char *vector_file, int** vector, size_t *cnt)
{
    ssize_t nread;
    size_t len, alloc_len, item_len = 0, item_cnt = 0;
    int rc, *record;
    char *line = NULL, *hitcnt_info, api_name[MAX_INFO_LEN], hitcnt_str[MAX_INFO_LEN];
    FILE *vfp;

    vfp = fopen(vector_file, "rb");
    if (!vfp) {
        printf("Fatal: can not open file %s\n", vector_file);
        return -1;
    }

    alloc_len = 1024;
    record = malloc(alloc_len*sizeof(int));

    while ((nread = getline(&line, &len, vfp)) != -1) {
        memset(api_name, 0, sizeof(api_name));
        memset(hitcnt_str, 0, sizeof(hitcnt_str));
        rc = sscanf(line, "%s %s\n", api_name, hitcnt_str);
        assert(rc == 2);
        record[item_cnt] = strtoul(hitcnt_str, NULL, 16);
        if (item_cnt++ >= alloc_len) {
            alloc_len *= 2;
            record = realloc(record, alloc_len);
        }
    }
    free(line);
    fclose(vfp);
    *vector = record;
    *cnt = item_cnt;

    return 0;
}

int main (int argc, char *argv[])
{
    int rc, i, *vector1, *vector2;
    size_t bp_cnt1, bp_cnt2;
    double numerator = 0, denominator = 0, d1 = 0, d2 = 0, sim;

    if (argc != 3) {
        printf("Usage: %s <vector file1> <vector file2>\n", argv[0]);
        return -1;
    }
    rc = intialize_data(argv[1], &vector1, &bp_cnt1);
    assert(rc == 0);
    rc = intialize_data(argv[2], &vector2, &bp_cnt2);
    assert(rc == 0);
    assert(bp_cnt1 == bp_cnt2);

    for (i = 0; i < bp_cnt1; i++) {
        numerator += vector1[i]*vector2[i];
        d1 += vector1[i]*vector1[i];
        d2 += vector2[i]*vector2[i];
    }
    if (d1 == 0 || d2 == 0) {
        printf("Invalid input, no hitcnt\n");
        return 0;
    }

    denominator = sqrt(d1*d2);
    sim = numerator/denominator;
    printf("Simularity cosine =  %f\n", sim);
}
