
#include "sqlquery.h"


int update_headcount_by_depname(sqlite3 *db, char* depname, int headcount){


    int result = -1;

    sqlite3_stmt *stmt;

    result = sqlite3_prepare_v2(db, sqlite3_mprintf("UPDATE department SET head_count = (%d) WHERE name = (%Q)", headcount, depname), -1, &stmt, NULL);

    if(result != SQLITE_OK){

        printf("failed to update\n");
        return -1;
    } else {

        printf("update success\n");

    }

    sqlite3_finalize(stmt);

    return result;
}


int get_headcount_by_depname(sqlite3 *db, char* depname){

    int result = -1;

    sqlite3_stmt *stmt;

    sqlite3_prepare_v2(db, sqlite3_mprintf("SELECT head_count from department WHERE name = (%Q)", depname), -1, &stmt, NULL);

    int got  = 0;
	while (sqlite3_step(stmt) != SQLITE_DONE) {
		int i;
		int num_cols = sqlite3_column_count(stmt);
		
		for (i = 0; i < num_cols; i++){
			switch (sqlite3_column_type(stmt, i)){
			/*
            case (SQLITE3_TEXT):
				printf("%s, ", sqlite3_column_text(stmt, i));
				break;
            */
			case (SQLITE_INTEGER):
                result = sqlite3_column_int(stmt, i);
                got = 1;
				break;
            /*
			case (SQLITE_FLOAT):
				printf("%g, ", sqlite3_column_double(stmt, i));
				break;
            */
			default:
                got = 1;
				break;
			}

            if (got == 1){
                break;
            }
		}

        if(got == 1){
            break;
        }
    }
    sqlite3_finalize(stmt);

    return result;
}




int main(void)
{
	sqlite3 *db;
	
	sqlite3_open("company.db", &db);

	if (db == NULL){

		printf("failed to open DB\n");
		return -1;
	}

    int hc = get_headcount_by_depname(db, "yoyo");

    printf("head count of yoyo: %d\n", hc);

    int res = update_headcount_by_depname(db, "yoyo", 15);

    hc = get_headcount_by_depname(db, "yoyo");

    printf("new head count of yoyo: %d\n", hc);

	sqlite3_close(db);

	return 0;
}