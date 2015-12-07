# docker-mod_imagereceiver

## db

```
sudo docker run -e MYSQL_DATABASE=mydb -e MYSQL_USER=userfoo -e MYSQL_PASSWORD=secret  -e MYSQL_ROOT_PASSWORD=verysecret --name mysqld -d mysql
sudo docker run --link  mysqld:mysql -it --rm mysql sh -c 'exec mysql -h"$MYSQL_PORT_3306_TCP_ADDR" -P"$MYSQL_PORT_3306_TCP_PORT" -uroot -p"$MYSQL_ENV_MYSQL_ROOT_PASSWORD" mydb -e "CREATE TABLE users(id int, name text);"'
```

```
sudo docker build -t dbdtest .
sudo docker run  -d --link  mysqld:mysql  -p 8080:80 -t dbdtest
```

