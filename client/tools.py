import yaml,os,socket,time,psutil,datetime,json
from interval import Interval
from loguru import logger

def foreach_rules(file_list: list):
    """
    获取规则列表
    :param file_list:  规则文件路径
    :return: 
    """
    rules = []
    for i in file_list:
        rules.append(decode_yaml(i)['checks'])
    return rules[0]

def decode_yaml(path):
    """
    读取yaml文件，并转化为字典
    :param path: 文件路径
    :return: dict
    """
    file = open(path, 'r', encoding="utf-8")
    file_data = file.read()
    data = yaml.load(file_data, yaml.Loader)
    file.close()
    return data

def socket_conn(ip,port:int):
    client = socket.socket()
    client.connect((ip, port))
    return client

#socket连接发送日志（tcp连接）
def monitor_log(client,logpath):
        file = open(file=logpath,mode='r')
        file.seek(0, 2) # 直接定位到文件末尾
        logger.info(f"================ 开始实时读取日志信息{logpath} ================")
        # client.send(logpath.encode())
        while True:
            try:
                list = file.readlines()		# 每一次均读取最新内容，此处并不需要使用f.tell()，因为readlines会读取到最后位置
                logger.info(len(list))
                if len(list) > 0:
                    for line in list:
                        logger.info((logpath+'::'+line).encode())
                        log_name = logpath.split('/')[-1]
                        client.sendall(('192.168.10.133::'+log_name+'::'+line).encode())
                time.sleep(5)
            except:
                logger.info('error')

def monitor_system(client,time):
    # cpu的使用率
    cup_per = psutil.cpu_percent(interval=time)
    # 内存信息
    mem_info = psutil.virtual_memory()
    # 硬盘信息
    disk_info = psutil.disk_usage('/')
    # 网络使用情况  收发多少数据
    net = psutil.net_io_counters()
    # 获取当前系统时间
    current_time = datetime.datetime.now().strftime("%F %T")  # %F年月日 %T时分秒
    sys_status={'time':current_time,'cup':str(cup_per)+'%','memory':str(mem_info.percent)+'%','disk':str(disk_info.percent)+'%','net':['%.2f'%(net.bytes_recv/1024/1024),'%.2f'%(net.bytes_sent/1024/1024)]}
    send_info = json.dumps(sys_status)
    logger.info('system.log::'+send_info)
    client.sendall(('192.168.10.133::system.log::'+send_info+'\n').encode())

#socket发送日志（udp连接）
