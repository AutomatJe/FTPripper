import argparse
import collections
import concurrent.futures
import datetime
import ftplib
import pathlib
import signal
import time
import threading
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


# Исключение которое выбрасывается если программа не
# может определить тип (файл или каталог) по строке,
# приходящей от FTP-сервера на команду LIST.
class FtpStringException(Exception):

    def __init__(self, string):
        self.string = string

    def __str__(self):
        return 'Unsupported string format: ' + self.string


def parse_args():
    parser = argparse.ArgumentParser(description='Get list of files from FTP servers')
    parser.add_argument('-v', '--verbose',
        help='verbose mode',
        action='store_true')
    parser.add_argument('-m', '--mode', 
        help='input type',
        choices=['host', 'file', 'nmap'],
        required=True)
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
# ftp://'хост':'порт'/'путь до файла' и список ошибок, полученных
# при обходе сервера.
def process_ftp(host, args):
    if STOP_EVENT.is_set():
        return [], ['Stoped']
    ftp = ftplib.FTP(timeout=args.timeout)
    ftp.connect(host['addr'], port=host['port'])
    ftp.login()

    if ftp.pwd() != '/':
        dirs = ['']
        template = 'ftp://{}:{}/{}'
    else:
        dirs = ['/']
        template = 'ftp://{}:{}{}'

    files = []
    errors = []
    while dirs:
        if STOP_EVENT.is_set():
            errors.append('Stoped')
            break
        path = dirs[0]
        try:
            if args.verbose:
                with LOCK:
                    print('Getting content from '+template.format(host['addr'], host['port'], path))
            new_dirs, new_files = get_content(ftp, path)
        except ftplib.error_perm as e:
            dirs.pop(0)
            errors.append('{}:{} Path: {} Error: {}'.format(host['addr'], host['port'], path, e))
            continue
        files += [template.format(host['addr'], host['port'], f) for f in new_files]
        dirs.pop(0)
        dirs = new_dirs + dirs

    ftp.close()
    return files, errors

# Чтение списка хостов из файла
def get_hosts_from_file(filename):
    hosts = []
    with open(filename) as in_file:
        for line in in_file:
            host = line[:-1]
            if host:
                host = host.split(':')
                if len(host) == 1:
                    hosts.append({'addr': host[0], 'port': None})
                elif len(host) == 2:
                    hosts.append({'addr': host[0], 'port': int(host[1])})
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
            portid = port.attrib['portid']
            state = port.find('./state').attrib['state']
            service = port.find('./service').attrib['name']
            if state == 'open' and service == 'ftp':
                results.append({'addr': addr, 'port': int(portid)})
    return results

# Получение хоста из интерфейса командной строки,
# формат 'хост':'порт'
def get_host_from_cli(string):
    host = string.split(':')
    if len(host) == 1:
        return [{'addr': host[0], 'port': None}]
    elif len(host) == 2:
        return [{'addr': host[0], 'port': int(host[1])}]
    else:
        return []

# Функция вывода статистики, counter - объект collections.Counter
def print_stats(counter):
    print('Total: {} files'.format(sum((counter[key] for key in counter.keys()))))
    for key in sorted([key for key in counter.keys() if key != '']):
        print(' {}: {}'.format(key, counter[key]))
    if '' in counter:
        print(' Unknown files: {}'.format(counter['']))

# Функция, выполняющая основную работу, отвечает за запуск пула потоков,
# сбор статистики, вывод результатов.
# Аргументы: hosts - список хостов, каждый хост - словарь с ключами
# 'addr' и 'port', args - аргументы командной строки.
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
            try:
                files, errors = ft.result()
            except Exception as e:
                print('{}:{} {}'.format(futures[ft]['addr'], futures[ft]['port'], e))
                print('='*60)
                continue
            print('Done with {}:{}'.format(futures[ft]['addr'], futures[ft]['port']))
            for f in files:
                out_file.write(f+'\n')

            # Подсчёт статистики по хосту, подсчитывается кол-во файлов с различными
            # расширениями
            stats = collections.Counter([pathlib.Path(f).suffix for f in files])
            total += stats
            print_stats(stats)

            # Вывод ошибок полученных во время обхода FTP-сервера.
            print('Errors: {}'.format(len(errors)))
            for e in errors:
                print(' {}'.format(e))
            print('='*60)

    stop = int(time.time())
    print('Elasped time: {}'.format(datetime.timedelta(seconds=stop-start)))
    print('SUMMARY STATISTICS')
    print_stats(total)
    out_file.close()

def signal_handler(signum, frame):
    print('\nStopping...')
    STOP_EVENT.set()

def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_args()
    print(BANNER)

    # Получение списка портов в зависимости от указанного
    # опцией -m режима.
    if args.mode == 'file':
        hosts = get_hosts_from_file(args.input)
    elif args.mode == 'nmap':
        hosts = get_hosts_from_nmap_xml(args.input)
    else:
        hosts = get_host_from_cli(args.input)

    # Если номер порта явно не указан, выбирается порт из
    # args.port (по-умолчанию 21).
    for host in hosts:
        if host['port'] == None:
            host['port'] = args.port
    do_work(hosts, args)


if __name__ == '__main__':
    main()
