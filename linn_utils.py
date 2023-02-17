import datetime
import paramiko
import psutil
import re
import socket
import time


def etc_rule_check(filepath, ruleset: dict, ignored_char):
    scan_res = []
    with open(filepath, 'r') as etc_file:
        etcs = etc_file.readlines()
        for etc in etcs:
            if not etc.startswith(ignored_char):
                for check in ruleset['checks']:
                    if re.match(check['rules'], etc):
                        danger = [check['id'], check['description']]
                        scan_res.append(danger)
    return scan_res


def remote_ssh_conn(info):
    # 连接到远程主机
    transport = paramiko.Transport((info['ip'], 22))
    transport.connect(username=info['user'], password=info['passwd'])
    # ssh = paramiko.SSHClient()
    # ssh._transport = transport
    sftp = paramiko.SFTPClient.from_transport(transport)
    return sftp
    # # 在远程主机上支持命令，并获取返回结果（以元组形式返回输入，输出和错误）
    # stdin, stdout, stderr = ssh.exec_command("ifconfig")
    # print(stdout.read().decode())
    # # 上传文件到远程主机
    # sftp.put(r'D:\test-base64.html', r'/tmp/test-base64.html')
    # # 从远程主机上下载文件
    # sftp.get('/etc/passwd', r'D:\passwd')


def receive_log():
    receive = socket.socket()
    receive.bind(("0.0.0.0", 1122))
    receive.listen()
    chanel, client = receive.accept()
    while True:
        receive = chanel.recv(4096).decode()
        if not receive == '':
            print(receive)
            with open(f'/tmp/linn/logs/remote.log', 'a+') as file:
                file.write(receive)


def local_monitor(time):
    # cpu的使用率
    cup_per = psutil.cpu_percent(interval=time)
    # 内存信息
    mem_info = psutil.virtual_memory()
    # 硬盘信息
    disk_info = psutil.disk_usage('/')
    # cpu的使用率
    cup_per = psutil.cpu_percent(interval=time)
    # 内存信息
    mem_info = psutil.virtual_memory()
    # 硬盘信息
    disk_info = psutil.disk_usage('/')
    # 网络使用情况  收发多少数据
    net = psutil.net_io_counters()
    sys_status = {'cup': str(cup_per) + '%', 'memory': str(mem_info.percent) + '%',
                  'disk': str(disk_info.percent) + '%',
                  'net': ['%.2f' % (net.bytes_recv / 1024 / 1024), '%.2f' % (net.bytes_sent / 1024 / 1024)]}
    if cup_per > 95:
        log = {'time': current_time, 'method': 'localhost', 'url': 'cup负载过高', 'level': '8',
                       'title': '主机状态监控'}
        tools.alert_log(log)
        print('cup负载过高')
    elif mem_info.percent > 95:
        log = {'time': current_time, 'method': 'localhost', 'url': '内存占用过高', 'level': '8',
                       'title': '主机状态监控'}
        tools.alert_log(log)
        rint('内存占用过高')
    elif disk_info.percent > 95:
        log = {'time': current_time, 'method': 'localhost', 'url': '硬盘占用过高', 'level': '8',
                       'title': '主机状态监控'}
        tools.alert_log(log)
        print('硬盘占用过高')
    print(sys_status)


def classify_log(mlog_path):
    # print(mlog_path)
    origin_log = open(file=mlog_path,mode='r')
    origin_log.seek(0, 2) # 直接定位到文件末尾
    print("================ 开始分类远程日志信息 ================")
    while True:
        try:
            list = origin_log.readlines()		# 每一次均读取最新内容，此处并不需要使用f.tell()，因为readlines会读取到最后位置
            if len(list) > 0:
                for line in list:
                    rhost = line.split('::')[0]
                    logtype = line.split('::')[1]
                    log = line.split('::')[2]
                    with open(f'/tmp/linn/logs/{rhost}_{logtype}', 'a+') as file:
                        file.write(log)   
        except:
            file.close()    