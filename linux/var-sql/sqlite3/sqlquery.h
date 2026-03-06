#ifndef _SQLITE_QUERY_H_
#define _SQLITE_QUERY_H_

#include <stdio.h>
#include <sqlite3.h>


int get_headcount_by_depname(sqlite3 *db, char* depname);

int update_headcount_by_depname(sqlite3 *db, char* depname, int headcount);





#endif