#!/bin/bash

rm -rf company.db

sqlite3 company.db <<EOF
CREATE TABLE department (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, head_count INTEGER);
INSERT INTO department (name, head_count) values ('yoyo',10);
EOF