CREATE USER 'mysqldb'@'%' IDENTIFIED BY 'universalpassword';

GRANT ALL PRIVILEGES ON *.* TO 'mysqldb'@'%';

CREATE DATABASE mysqldb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE mysqldb;


CREATE TABLE user (

    user_id INT NOT NULL AUTO_INCREMENT,
    user_name VARCHAR(128),
    user_pass TEXT,
    PRIMARY KEY (user_id)

);



INSERT INTO 
    user (
        user_name,
        user_pass
    )
    VALUES (

        "test1",
        "test1pw"
    );

COMMIT;