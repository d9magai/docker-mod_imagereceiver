# docker-mod_imagereceiver

## db

```
sudo docker run -e MYSQL_DATABASE=mydb -e MYSQL_USER=userfoo -e MYSQL_PASSWORD=secret  -e MYSQL_ROOT_PASSWORD=verysecret --name mysqld -d mysql
```

```
CREATE TABLE users(id int, name text);
```

```
sudo docker run  -d --link  mysqld:mysql  -p 8080:80 -t dbdtest
```

