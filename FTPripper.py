import argparse
import collections
import concurrent.futures
import datetime
import ftplib
import pathlib
import re
import signal
import time
import threading
import urllib.parse
import xml.etree.ElementTree as et


LOCK = threading.Lock()
STOP_EVENT = threading.Event()
BANNER = """
 _____ _____ ____       _                       
|  ___|_   _|  _ \ _ __(_)_ __  _ __   ___ _ __ 
| |_    | | | |_) | '__| | '_ \| '_ \ / _ \ '__|
|  _|   | | |  __/| |  | | |_) | |_) |  __/ |   
|_|     |_| |_|   |_|  |_| .__/| .__/ \___|_|   
                         |_|   |_|              
"""
PROGRESS_MSG = 'Working with {}:{} server. {} directory left, {} files found.'
DONE_MSG = 'Done with {}:{} server. {} files found.'
ERROR_MSG = 'Error on {}:{} server. {}'
STOP_MSG = 'Stopped working with {}:{} server.'

# Исключение которое выбрасывается если программа не
# может определить тип (файл или каталог) по строке,
# приходящей от FTP-сервера на команду LIST.
class FtpStringException(Exception):

    def __init__(self, string):
        self.string = string

    def __str__(self):
        return 'Unsupported string format: ' + self.string

def signal_handler(signum, frame):
    print('\nStopping...')
    STOP_EVENT.set()

def parse_args():
    parser = argparse.ArgumentParser(description='Get list of files from FTP servers')
    parser.add_argument('-m', '--mode', 
        help='input type',
        choices=['host', 'file', 'nmap'],
        default='host')
    parser.add_argument('-p', '--port',
        help='port number',
        type=int,
        default=21)
    parser.add_argument('-t', '--threads',
        help='number of threads',
        type=int,
        default=None)
    parser.add_argument('--timeout',
        help='timeout in seconds for FTP operations',
        type=int,
        default=60)
    parser.add_argument('input',
        help='host or file')
    parser.add_argument('output',
        help='path to save list of files')
    return parser.parse_args()

# Получение алреса хоста и порта из строки
# Аргументы: string - строка, default_port - номер порта по-умолчанию,
# который используется, если порт не указан явно
def get_host_from_sting(string, default_port):
    pattern = re.compile(r'(?P<host>[\d\w.]+)(:(?P<port>[\d]+))?')
    match = pattern.fullmatch(string)
    if match:
        if match.group('port'):
            host = (match.group('host'), int(match.group('port')))
        else:
            host = (match.group('host'), default_port)
    else:
        host = None
    return host

# Чтение списка хостов из файла
def get_hosts_from_file(filename, default_port):
    hosts = []
    with open(filename) as in_file:
        for line in in_file:
            host = get_host_from_sting(line.replace('\n', ''), default_port)
            if host:
                hosts.append(host)
    return hosts

# Получение списка хостов из XML файла с результатами
# сканирования nmap (опция nmap -oX)
def get_hosts_from_nmap_xml(filename):
    tree = et.parse(filename)
    hosts = tree.getroot().findall('.//host')
    results = []
    for host in hosts:
        addr = host.find('address').attrib['addr']
        ports = host.findall('./ports/port')
        for port in ports:
            portid = int(port.attrib['portid'])
            state = port.find('./state').attrib['state']
            service = port.find('./service').attrib['name']
            if state == 'open' and service == 'ftp':
                results.append((addr, portid))
    return results

# Функция вывода статистики, counter - объект collections.Counter
def print_stats(counter):
    print('Total: {} files'.format(sum((counter[key] for key in counter.keys()))))
    for key in sorted([key for key in counter.keys() if key != '']):
        print(' {}: {}'.format(key, counter[key]))
    if '' in counter:
        print(' Unknown files: {}'.format(counter['']))

# Функция для получения списков файлов и директорий на FTP-сервере.
# Аргументы: ftp - объект ftplib.FTP, path - путь до директори на сервере.
# Возвращает: список директорий и список файлов.
def get_content(ftp, path):
    dirs, files = [], []
    ftp.cwd(path)
    names = [name for name in ftp.nlst() if name not in ('.', '..')]

    lines = []
    def callback(string):
        lines.append(string)

    ftp.retrlines('LIST', callback=callback)
    for name in names:
        for line in lines:
            if line.endswith(name):
                if line[0] == 'd' or '<DIR>' in line:
                    dirs.append(path+name+'/')
                elif line[0] == '-' or '<DIR>' not in line:
                    files.append(path+name)
                else:
                    raise FtpStringException(line)
                lines.pop(lines.index(line))
                break
    return dirs, files

# Функция для получения полных путей до файлов на FTP-сервере.
# Аргументы: host - словарь, содержащий адрес и порт сервера,
# args - аргументы командной строки.
# Возвращает: список путей до файлов на FTP-сервере в формате
# ftp://'хост':'порт'/'путь до файла'.
def process_ftp(host, args):
    if STOP_EVENT.is_set():
        with LOCK:
            print(STOP_MSG.format(host[0], host[1]))
        return []
    ftp = ftplib.FTP(timeout=args.timeout)
    ftp.connect(host[0], port=host[1])
    ftp.login()
    # Определение начальной директории
    try:
        ftp.cwd('/')
    except ftplib.error_perm:
        dirs = ['']
    else:
        dirs = ['/']
    files = []
    # Обход директорий на сервере
    while dirs:
        if STOP_EVENT.is_set():
            with LOCK:
                print(STOP_MSG.format(host[0], host[1]))
            break
        with LOCK:
            print(PROGRESS_MSG.format(host[0], host[1], len(dirs), len(files)))
        path = dirs[0]
        try:
            new_dirs, new_files = get_content(ftp, path)
        # Пропуск директрий с ошибками
        except ftplib.error_perm:
            dirs.pop(0)
            continue
        files += new_files
        dirs.pop(0)
        dirs = new_dirs + dirs
    ftp.close()
    for f in files:
        if not f.startswith('/'):
            f = '/' + f
    with LOCK:
        print(DONE_MSG.format(host[0], host[1], len(files)))
    return files

# Функция, выполняющая основную работу, отвечает за запуск пула потоков,
# сбор статистики, вывод результатов.
# Аргументы: hosts - список хостов, каждый хост - tuple, содержащий
# адрес и порт, args - аргументы командной строки.
def do_work(hosts, args):
    total = collections.Counter() # Общая статистика по всем хостам
    out_file = open(args.output, 'w')
    print('Total number of hosts: {}'.format(len(hosts)))
    start = int(time.time())

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Для каждого хоста запускается отдельный поток, в котором будет выполняться
        # обход FTP-сервера
        futures = {executor.submit(process_ftp, host, args): host for host in hosts}
        for ft in concurrent.futures.as_completed(futures):
            host = futures[ft]
            try:
                files= ft.result()
            except Exception as e:
                with LOCK:
                    print(ERROR_MSG.format(host[0], host[1], e))
                continue
            for f in files:
                out_file.write('ftp://{}:{}{}\n'.format(host[0], host[1], urllib.parse.quote(f)))

            # Подсчёт статистики по хосту, подсчитывается кол-во файлов с различными
            # расширениями
            stats = collections.Counter([pathlib.Path(f).suffix for f in files])
            total += stats

    stop = int(time.time())
    print('Elasped time: {}'.format(datetime.timedelta(seconds=stop-start)))
    print('SUMMARY STATISTICS')
    print_stats(total)
    out_file.close()

def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_args()
    print(BANNER)

    # Получение списка хостов в зависимости от указанного
    # опцией -m режима.
    if args.mode == 'file':
        hosts = get_hosts_from_file(args.input, args.port)
    elif args.mode == 'nmap':
        hosts = get_hosts_from_nmap_xml(args.input)
    else:
        hosts = [get_host_from_sting(args.input, args.port)]

    do_work(hosts, args)


if __name__ == '__main__':
    main()
