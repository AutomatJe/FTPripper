# FTPripper

Скрипт для обхода FTP-серверов и получения списка, хранящихся на них
файлов.

```usage: FTPripper.py [-h] [-m {host,file,nmap}] [-p PORT] [-t THREADS]
                    [--timeout TIMEOUT]
                    input output

Get list of files from FTP servers

positional arguments:
  input                 host or file
  output                path to save list of files

optional arguments:
  -h, --help            show this help message and exit
  -m {host,file,nmap}, --mode {host,file,nmap}
                        input type
  -p PORT, --port PORT  port number
  -t THREADS, --threads THREADS
                        number of threads
  --timeout TIMEOUT     timeout in seconds for FTP operations
```

#### Примеры использования

* Обход одного FTP-сервера

python3 FTPripper.py 198.115.143.200 out.txt

* Обход FTP-серверов, перечисленных в файле ftp.txt

python3 FTPripper.py -m file ftp.txt out.txt

* Обход FTP-серверов, из результатов сканирования nmap (опция -oX) nmap.xml

python3 FTPripper.py -m nmap nmap.xml out.txt
