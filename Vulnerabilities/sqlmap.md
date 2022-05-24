```shell
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
```
Usage: sqlmap.py [options]

## Options:

  -h, --help            Show basic help message and exit
  -hh                   Show advanced help message and exit
  --version             Show program's version number and exit
  -v VERBOSE            Verbosity level: 0-6 (default 1)

##  一、Target:目标，注入目标的格式的选项
    At least one of these options has to be provided to define the
    target(s)

    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")，常用的方式，后面跟攻击目标的URL
    -d DIRECT           Connection string for direct database connection
    -l LOGFILE          Parse target(s) from Burp or WebScarab proxy log file
    -m BULKFILE         Scan multiple targets given in a textual file
    -r REQUESTFILE      Load HTTP request from a file，常用的方式，可以将POST类型的请求包存在TXT文件中，后面跟路径文件
    -g GOOGLEDORK       Process Google dork results as target URLs
    -c CONFIGFILE       Load options from a configuration INI file

##  二、Request:
    These options can be used to specify how to connect to the target URL

    -A AGENT, --user..  HTTP User-Agent header value
    -H HEADER, --hea..  Extra header (e.g. "X-Forwarded-For: 127.0.0.1")
    --method=METHOD     Force usage of given HTTP method (e.g. PUT)，请求方式，GET、POST、PUT等等
    --data=DATA         Data string to be sent through POST (e.g. "id=1")
    --param-del=PARA..  Character used for splitting parameter values (e.g. &)
    --cookie=COOKIE     HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")，常用参数，携带认证凭据
    --cookie-del=COO..  Character used for splitting cookie values (e.g. ;)
    --live-cookies=L..  Live cookies file used for loading up-to-date values
    --load-cookies=L..  File containing cookies in Netscape/wget format
    --drop-set-cookie   Ignore Set-Cookie header from response
    --mobile            Imitate smartphone through HTTP User-Agent header
    --random-agent      Use randomly selected HTTP User-Agent header value，随机使用一个user-agent
    --host=HOST         HTTP Host header value
    --referer=REFERER   HTTP Referer header value
    --headers=HEADERS   Extra headers (e.g. "Accept-Language: fr\nETag: 123")
    --auth-type=AUTH..  HTTP authentication type (Basic, Digest, Bearer, ...)
    --auth-cred=AUTH..  HTTP authentication credentials (name:password)
    --auth-file=AUTH..  HTTP authentication PEM cert/private key file
    --ignore-code=IG..  Ignore (problematic) HTTP error code (e.g. 401)
    --ignore-proxy      Ignore system default proxy settings
    --ignore-redirects  Ignore redirection attempts
    --ignore-timeouts   Ignore connection timeouts
    --proxy=PROXY       Use a proxy to connect to the target URL，常用参数，代理，有socks5://127.0.0.1:1089或者http://127.0.0.1.8090
    --proxy-cred=PRO..  Proxy authentication credentials (name:password)
    --proxy-file=PRO..  Load proxy list from a file
    --proxy-freq=PRO..  Requests between change of proxy from a given list
    --tor               Use Tor anonymity network
    --tor-port=TORPORT  Set Tor proxy port other than default
    --tor-type=TORTYPE  Set Tor proxy type (HTTP, SOCKS4 or SOCKS5 (default))
    --check-tor         Check to see if Tor is used properly
    --delay=DELAY       Delay in seconds between each HTTP request，常用参数，可以设定两个HTTP(S)请求间的延迟，后面直接跟数字
    --timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)，常用参数，
    --retries=RETRIES   Retries when the connection timeouts (default 3)
    --retry-on=RETRYON  Retry request on regexp matching content (e.g. "drop")
    --randomize=RPARAM  Randomly change value for given parameter(s)
    --safe-url=SAFEURL  URL address to visit frequently during testing
    --safe-post=SAFE..  POST data to send to a safe URL
    --safe-req=SAFER..  Load safe HTTP request from a file
    --safe-freq=SAFE..  Regular requests between visits to a safe URL
    --skip-urlencode    Skip URL encoding of payload data
    --csrf-token=CSR..  Parameter used to hold anti-CSRF token
    --csrf-url=CSRFURL  URL address to visit for extraction of anti-CSRF token
    --csrf-method=CS..  HTTP method to use during anti-CSRF token page visit
    --csrf-retries=C..  Retries for anti-CSRF token retrieval (default 0)
    --force-ssl         Force usage of SSL/HTTPS
    --chunked           Use HTTP chunked transfer encoded (POST) requests
    --hpp               Use HTTP parameter pollution method
    --eval=EVALCODE     Evaluate provided Python code before the request (e.g.
                        "import hashlib;id2=hashlib.md5(id).hexdigest()")

##  三、Optimization:优化
    These options can be used to optimize the performance of sqlmap

    -o                  Turn on all optimization switches
    --predict-output    Predict common queries output
    --keep-alive        Use persistent HTTP(s) connections
    --null-connection   Retrieve page length without actual HTTP response body
    --threads=THREADS   Max number of concurrent HTTP(s) requests (default 1)，常用参数，线程，

##  四、Injection:注入
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)，常用参数，指定注入点进行攻击
    --skip=SKIP         Skip testing for given parameter(s)
    --skip-static       Skip testing parameters that not appear to be dynamic
    --param-exclude=..  Regexp to exclude parameters from testing (e.g. "ses")
    --param-filter=P..  Select testable parameter(s) by place (e.g. "POST")
    --dbms=DBMS         Force back-end DBMS to provided value，常用参数，指定数据库类型，Mysql、Oracle、PostgreSQL等
    --dbms-cred=DBMS..  DBMS authentication credentials (user:password)
    --os=OS             Force back-end DBMS operating system to provided value
    --invalid-bignum    Use big numbers for invalidating values
    --invalid-logical   Use logical operations for invalidating values
    --invalid-string    Use random strings for invalidating values
    --no-cast           Turn off payload casting mechanism
    --no-escape         Turn off string escaping mechanism
    --prefix=PREFIX     Injection payload prefix string
    --suffix=SUFFIX     Injection payload suffix string
    --tamper=TAMPER     Use given script(s) for tampering injection data，常用参数，用于绕过防御

##  五、Detection:侦查
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)，常用参数，执行测试的等级，数字越高测试越深入仔细
    --risk=RISK         Risk of tests to perform (1-3, default 1)，执行测试的风险（1-3，默认值1）
    --string=STRING     String to match when query is evaluated to True
    --not-string=NOT..  String to match when query is evaluated to False
    --regexp=REGEXP     Regexp to match when query is evaluated to True
    --code=CODE         HTTP code to match when query is evaluated to True
    --smart             Perform thorough tests only if positive heuristic(s)
    --text-only         Compare pages based only on the textual content
    --titles            Compare pages based only on their titles

##  六、Techniques:技术手法，用于调整特定SQL注入技术
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")，常用参数，指定攻击模式，联合注入（U）、报错注入（E）、布尔盲注（B）、时间盲注（T）等
    --time-sec=TIMESEC  Seconds to delay the DBMS response (default 5)
    --union-cols=UCOLS  Range of columns to test for UNION query SQL injection
    --union-char=UCHAR  Character to use for bruteforcing number of columns
    --union-from=UFROM  Table to use in FROM part of UNION query SQL injection
    --dns-domain=DNS..  Domain name used for DNS exfiltration attack，重要参数，设置dns通道，sqlmap+OOB能减少时间盲注的时间
    --second-url=SEC..  Resulting page URL searched for second-order response
    --second-req=SEC..  Load second-order HTTP request from file

##  七、Fingerprint:指纹
    -f, --fingerprint   Perform an extensive DBMS version fingerprint

##  八、Enumeration:枚举
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user，获取当前用户名称
    --current-db        Retrieve DBMS current database，获取当前数据库名称
    --hostname          Retrieve DBMS server hostname，当前主机名
    --is-dba            Detect if the DBMS current user is DBA，检测当前用户是否是数据库管理权限
    --users             Enumerate DBMS users，获取当前DBMS所有用户
    --passwords         Enumerate DBMS users password hashes，获取当前所有dbms用户密码
    --privileges        Enumerate DBMS users privileges，查看用户权限(–privileges -U root) -U #指定数据库用户
    --roles             Enumerate DBMS users roles
    --dbs               Enumerate DBMS databases，常用参数，查询数据库
    --tables            Enumerate DBMS database tables，常用参数，查表
    --columns           Enumerate DBMS database table columns，常用参数，查列名
    --schema            Enumerate DBMS schema，枚举模式列表下包含的所有数据库 表 列 以及它们的类型
    --count             Retrieve number of entries for table(s)，只计算表的数量
    --dump              Dump DBMS database table entries，下载数据，慎用，用前先看法律
    --dump-all          Dump all DBMS databases tables entries
    --search            Search column(s), table(s) and/or database name(s)
    --comments          Check for DBMS comments during enumeration
    --statements        Retrieve SQL statements being run on DBMS
    -D DB               DBMS database to enumerate，指定数据库
    -T TBL              DBMS database table(s) to enumerate，指定表名
    -C COL              DBMS database table column(s) to enumerate，指定列名
    -X EXCLUDE          DBMS database identifier(s) to not enumerate
    -U USER             DBMS user to enumerate
    --exclude-sysdbs    Exclude DBMS system databases when enumerating tables
    --pivot-column=P..  Pivot column name
    --where=DUMPWHERE   Use WHERE condition while table dumping
    --start=LIMITSTART  First dump table entry to retrieve
    --stop=LIMITSTOP    Last dump table entry to retrieve
    --first=FIRSTCHAR   First query output word character to retrieve
    --last=LASTCHAR     Last query output word character to retrieve
    --sql-query=SQLQ..  SQL statement to be executed
    --sql-shell         Prompt for an interactive SQL shell，执行SQL
    --sql-file=SQLFILE  Execute SQL statements from given file(s)

##  九、Brute force:暴力校验
    These options can be used to run brute force checks

    --common-tables     Check existence of common tables
    --common-columns    Check existence of common columns
    --common-files      Check existence of common files

##  十、User-defined function injection:自定义函数注入
    These options can be used to create custom user-defined functions

    --udf-inject        Inject custom user-defined functions
    --shared-lib=SHLIB  Local path of the shared library

##  十一、File system access:访问文件系统
    These options can be used to access the back-end database management
    system underlying file system

    --file-read=FILE..  Read a file from the back-end DBMS file system，重要参数，读取对应文件 （绝对路径）
    --file-write=FIL..  Write a local file on the back-end DBMS file system，重要参数
    --file-dest=FILE..  Back-end DBMS absolute filepath to write to，重要参数，写入文件 与--file_write一起写

##  十二、Operating system access:操作系统访问
    These options can be used to access the back-end database management
    system underlying operating system

    --os-cmd=OSCMD      Execute an operating system command
    --os-shell          Prompt for an interactive operating system shell，重要参数，执行系统命令
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC
    --os-smbrelay       One click prompt for an OOB shell, Meterpreter or VNC
    --os-bof            Stored procedure buffer overflow exploitation
    --priv-esc          Database process user privilege escalation
    --msf-path=MSFPATH  Local path where Metasploit Framework is installed
    --tmp-path=TMPPATH  Remote absolute path of temporary files directory

##  十三、Windows registry access:Windows注册表访问
    These options can be used to access the back-end database management
    system Windows registry

    --reg-read          Read a Windows registry key value
    --reg-add           Write a Windows registry key value data
    --reg-del           Delete a Windows registry key value
    --reg-key=REGKEY    Windows registry key
    --reg-value=REGVAL  Windows registry key value
    --reg-data=REGDATA  Windows registry key value data
    --reg-type=REGTYPE  Windows registry key value type

##  十四、General:通用项
    These options can be used to set some general working parameters

    -s SESSIONFILE      Load session from a stored (.sqlite) file
    -t TRAFFICFILE      Log all HTTP traffic into a textual file
    --answers=ANSWERS   Set predefined answers (e.g. "quit=N,follow=N")
    --base64=BASE64P..  Parameter(s) containing Base64 encoded data
    --base64-safe       Use URL and filename safe Base64 alphabet (RFC 4648)
    --batch             Never ask for user input, use the default behavior，常用参数，用于sqlmap执行过程中选择默认选项
    --binary-fields=..  Result fields having binary values (e.g. "digest")
    --check-internet    Check Internet connection before assessing the target
    --cleanup           Clean up the DBMS from sqlmap specific UDF and tables
    --crawl=CRAWLDEPTH  Crawl the website starting from the target URL
    --crawl-exclude=..  Regexp to exclude pages from crawling (e.g. "logout")
    --csv-del=CSVDEL    Delimiting character used in CSV output (default ",")
    --charset=CHARSET   Blind SQL injection charset (e.g. "0123456789abcdef")
    --dump-format=DU..  Format of dumped data (CSV (default), HTML or SQLITE)
    --encoding=ENCOD..  Character encoding used for data retrieval (e.g. GBK)
    --eta               Display for each output the estimated time of arrival
    --flush-session     Flush session files for current target
    --forms             Parse and test forms on target URL
    --fresh-queries     Ignore query results stored in session file
    --gpage=GOOGLEPAGE  Use Google dork results from specified page number
    --har=HARFILE       Log all HTTP traffic into a HAR file
    --hex               Use hex conversion during data retrieval
    --output-dir=OUT..  Custom output directory path，自定义输出目录路径
    --parse-errors      Parse and display DBMS error messages from responses
    --preprocess=PRE..  Use given script(s) for preprocessing (request)
    --postprocess=PO..  Use given script(s) for postprocessing (response)
    --repair            Redump entries having unknown character marker (?)
    --save=SAVECONFIG   Save options to a configuration INI file
    --scope=SCOPE       Regexp for filtering targets
    --skip-heuristics   Skip heuristic detection of vulnerabilities
    --skip-waf          Skip heuristic detection of WAF/IPS protection
    --table-prefix=T..  Prefix used for temporary tables (default: "sqlmap")
    --test-filter=TE..  Select tests by payloads and/or titles (e.g. ROW)
    --test-skip=TEST..  Skip tests by payloads and/or titles (e.g. BENCHMARK)
    --web-root=WEBROOT  Web server document root directory (e.g. "/var/www")

##  十五、Miscellaneous:杂项
    These options do not fit into any other category

    -z MNEMONICS        Use short mnemonics (e.g. "flu,bat,ban,tec=EU")
    --alert=ALERT       Run host OS command(s) when SQL injection is found
    --beep              Beep on question and/or when vulnerability is found
    --dependencies      Check for missing (optional) sqlmap dependencies
    --disable-coloring  Disable console output coloring
    --list-tampers      Display list of available tamper scripts
    --offline           Work in offline mode (only use session data)
    --purge             Safely remove all content from sqlmap data directory
    --results-file=R..  Location of CSV results file in multiple targets mode
    --shell             Prompt for an interactive sqlmap shell
    --tmp-dir=TMPDIR    Local directory for storing temporary files
    --unstable          Adjust options for unstable connections
    --update            Update sqlmap
    --wizard            Simple wizard interface for beginner users

