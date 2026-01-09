#include "c_struct.h"






void* StructCopyThreadForSarr(void* targ){


    FILE* fp;

    fp = fopen("sarr.txt", "a");


    struct StructWithArr t_sarr;


    t_sarr = *(struct StructWithArr*)targ;

    char name[MAX_MEMBER_ARR_LEN] = {0};

    sprintf(name, "%d", t_sarr.name);

    fprintf(fp, "%s\n", name);

    fprintf(fp, "before org: %s\n", ((struct StructWithArr*)targ)->comment);

    fprintf(fp, "before cp: %s\n", t_sarr.comment);


    strcpy(t_sarr.comment, "comment for sarr: modified");

    fprintf(fp, "after: %s\n", t_sarr.comment);

    fclose(fp);

}

void* StructCopyThreadForSptr(void* targ){


    FILE* fp;

    fp = fopen("sptr.txt", "a");

    struct StructWithPtr t_sptr;

    t_sptr = *(struct StructWithPtr*)targ;

    char name[MAX_MEMBER_ARR_LEN] = {0};

    sprintf(name, "%d", t_sptr.name);

    fprintf(fp, "%s\n", name);

    fprintf(fp, "before: %s\n", t_sptr.comment);

    strcpy(t_sptr.comment, "comment for sptr: modified");

    fprintf(fp, "after: %s\n", t_sptr.comment);

    fclose(fp);

}



