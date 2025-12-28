package main

import (
	"fmt"
	"log"

	pkgdbquery "github.com/seantywork/linuxyz/go/mysql-query/core"
)

type DB_User struct {
	UserId   int    `json:"user_id"`
	UserName string `json:"user_name"`
	UserPass string `json:"user_pass"`
}

func GetUsers() ([]DB_User, error) {

	var dbuser_records []DB_User

	q := `
	
		SELECT
			user_id,
			user_name,
			user_pass
		FROM
			user
	
	`

	a := []any{}

	res, err := pkgdbquery.DbQuery(q, a)

	if err != nil {

		return nil, fmt.Errorf("failed to get user: %s", err.Error())

	}

	defer res.Close()

	for res.Next() {

		dbuser := DB_User{}

		err = res.Scan(
			&dbuser.UserId,
			&dbuser.UserName,
			&dbuser.UserPass,
		)

		if err != nil {

			return nil, fmt.Errorf("failed to get user: row: %s", err.Error())
		}

		dbuser_records = append(dbuser_records, dbuser)
	}

	return dbuser_records, nil

}

func GetUserByName(name string) (*DB_User, error) {

	var dbuser_records []DB_User

	var dbuser DB_User

	q := `
	
		SELECT
			user_id,
			user_pass
		FROM
			user
		WHERE
			user_name = ?
	
	`

	a := []any{
		name,
	}

	res, err := pkgdbquery.DbQuery(q, a)

	if err != nil {

		return nil, fmt.Errorf("failed to get user: %s", err.Error())

	}

	defer res.Close()

	for res.Next() {

		dbuser := DB_User{}

		err = res.Scan(
			&dbuser.UserId,
			&dbuser.UserPass,
		)

		if err != nil {

			return nil, fmt.Errorf("failed to get user: row: %s", err.Error())
		}

		dbuser_records = append(dbuser_records, dbuser)
	}

	rlen := len(dbuser_records)

	if rlen != 1 {
		return nil, nil
	}

	dbuser = dbuser_records[0]

	return &dbuser, nil
}

func SetUser(name string, pass string) error {

	check, err := GetUserByName(name)

	if err != nil {

		return fmt.Errorf("set user: %s", err.Error())
	}

	var q string

	a := make([]any, 0)

	if check != nil {

		log.Printf("user: %s: already exists: overriding\n", name)

		q = `
		
			UPDATE
				user
			SET
				user_pass = ?
			WHERE
				user_id = ?

		
		`

		a = append(a, pass)

		a = append(a, check.UserId)

	} else {

		log.Printf("user: %s: doesn't exist: create\n", name)

		q = `
		
			INSERT INTO
				user(
					user_name,
					user_pass
				)
				VALUES(
					?,
					?
				)

		
		`

		a = append(a, name)
		a = append(a, pass)
	}

	err = pkgdbquery.DbExec(q, a)

	if err != nil {
		return fmt.Errorf("failed to set user: %s", err.Error())
	}

	return nil
}

func run() error {

	err := pkgdbquery.DbEstablish(
		"mysqldb",
		"universalpassword",
		"localhost:3306",
		"mysqldb",
	)

	if err != nil {

		return fmt.Errorf("failed to establish db conn: %s", err.Error())
	}

	urecall, err := GetUsers()

	if err != nil {

		return fmt.Errorf("failed to get all users: %s\n", err.Error())

	}

	ulen := len(urecall)

	for i := 0; i < ulen; i++ {

		fmt.Printf("user: %d ===================\n", i)
		fmt.Printf("id    : %d\n", urecall[i].UserId)
		fmt.Printf("name  : %s\n", urecall[i].UserName)
		fmt.Printf("pw    : %s\n", urecall[i].UserPass)
		fmt.Printf("=============================\n")

	}

	newuser := "test2"
	newpw := "test2pw"

	err = SetUser(newuser, newpw)

	if err != nil {
		return fmt.Errorf("failed to set new user: %s", err.Error())
	}

	urecall2, err := GetUsers()

	if err != nil {

		return fmt.Errorf("failed to get all users 2: %s\n", err.Error())

	}

	ulen2 := len(urecall2)

	for i := 0; i < ulen2; i++ {

		fmt.Printf("user: %d ===================\n", i)
		fmt.Printf("id    : %d\n", urecall2[i].UserId)
		fmt.Printf("name  : %s\n", urecall2[i].UserName)
		fmt.Printf("pw    : %s\n", urecall2[i].UserPass)
		fmt.Printf("=============================\n")

	}

	return nil
}

func main() {

	if err := run(); err != nil {

		log.Fatal(err)
	}

}
