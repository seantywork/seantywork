package core

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func DbEstablish(db_id string, db_pw string, db_addr string, db_name string) error {

	var err error

	db_info := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true", db_id, db_pw, db_addr, db_name)

	DB, err = sql.Open("mysql", db_info)

	if err != nil {

		return fmt.Errorf("failed to open db: %s", err.Error())
	}

	DB.SetConnMaxLifetime(time.Second * 10)
	DB.SetConnMaxIdleTime(time.Second * 5)
	DB.SetMaxOpenConns(10)
	DB.SetMaxIdleConns(10)

	return nil
}

func DbQuery(query string, args []any) (*sql.Rows, error) {

	var empty_row *sql.Rows

	results, err := DB.Query(query, args[0:]...)

	if err != nil {

		return empty_row, fmt.Errorf("db query: %s", err.Error())

	}

	return results, err

}

func DbExec(query string, args []any) error {

	result, err := DB.Exec(query, args[0:]...)

	if err != nil {
		return fmt.Errorf("db exec: %s", err.Error())
	}

	_, err = result.RowsAffected()

	if err != nil {

		return fmt.Errorf("db exec: rows: %s", err.Error())
	}

	return nil

}
