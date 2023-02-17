import yaml
import os
import re
import json
import time
import base64


class CountRule:
    _instance = None
    rule_count = {}
    rule_time = {}

    def __init__(self):
        self.time = 60

    def check_rule(self, rule):
        """
        检测规则预警次数
        :param rule: 规则
        """
        # 记录规则次数和时间

        # 判断是否需要检测规则预警次数
        if 'if' in rule and 'rule' not in rule:
            # 判断指定规则预警次数，是否大于限定次数
            # print(self.rule_count)
            if str(rule['if']['id']) in self.rule_count:
                if self.rule_count[str(rule['if']['id'])] >= rule['if']['number']:
                    rule['url'] = "id " + str(rule['id'])
                    self.rule_count[str(rule['if']['id'])] = 0
                    self.rule_time[str(rule['if']['id'])] = time.time()
                    self.add_number(rule['id'])
                    alert_log(rule)
        else:
            self.add_number(rule['id'])
        # print(self.rule_count)

    def add_number(self, id):
        """
        主要用于计算rule运行次数
        :param id: 规则ID
        """
        id = str(id)
        if id in self.rule_count:
            self.rule_count[id] += 1
            # 更新时间和次数，默认一分钟
            if time.time() - self.rule_time[id] > self.time:
                self.rule_time[id] = time.time()
                self.rule_count[id] = 1
        else:
            self.rule_count[id] = 1
            self.rule_time[id] = time.time()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(CountRule, cls).__new__(cls, *args, **kwargs)
            # print('ssss')
        return cls._instance


def find_file(search_path, exclude_dir=None):
    """
    查找指定目录下所有的文件（不包含以__开头和结尾的文件）或指定格式的文件，若不同目录存在相同文件名，只返回第1个文件的路径
    :param search_path: 查找的目录路径
    :param exclude_dir: 设置白名单，默认为[]
    :return 返回目录下所有文件的绝对路径
    """
    if exclude_dir is None:
        exclude_dir = []
    files = []
    
    # 获取路径下所有文件
    if not os.path.isdir(search_path):
        print("未发现目录")
        return
    file_or_dir = os.listdir(search_path)
    for file_dir in file_or_dir:
        file_or_dir_path = os.path.join(search_path, file_dir)
        # 判断该路径是不是路径，如果是，递归调用
        if os.path.isdir(file_or_dir_path):
            # print('Path: '+ file_or_dir_path)
            # 白名单跳过
            if file_or_dir_path in exclude_dir:
                # print(file_or_dir_path)
                continue
            # 递归，最终会将所有找到的文件，添加到files列表
            files = files + find_file(file_or_dir_path)
        else:
            # print(file_or_dir_path)
            files.append(file_or_dir_path)
    return files


def merge(dicts):
    """
    合并字典列表
    :param dicts: 字典列表
    :return: dict
    """
    sum = {}
    for i in dicts:
        sum.update(i)
    return sum


def decode_yaml(path):
    """
    读取yaml文件，并转化为字典
    :param path: 文件路径
    :return: dict
    """
    file = open(path, 'r')
    file_data = file.read()
    data = yaml.load(file_data, yaml.Loader)
    file.close()
    return data


def foreach_rules(file_list: list):
    """
    获取规则列表
    :param file_list:  规则文件路径
    :return: 返回规则字典
    """
    rules = []
    for i in file_list:
        # print(decode_yaml(i))
        rules += decode_yaml(i)
    return rules


def check_value(pcre, log):
    """
    正则表达式匹配文本
    :param pcre:  正则表达式
    :param log:  一行日志
    :return: 返回布尔值
    """
    search_obj = re.findall(pcre, log, re.M | re.I)
    # print(search_obj)
    if search_obj:
        return True
    return False


def extract_fields(pcre, log, fields):
    """
    提取字段
    :param pcre: 正则表达式，需要提取的字段用括号括起来
    :param log: 日志
    :param fields: 字段，必须和正则表达式里的括号数量一致
    :return: 返回由字段和提取的值组合成的字典
    """
    # pcre = pcre.replace("\\\\", "\\")
    find = re.findall(pcre, log)
    # print(find)
    return dict(zip(fields, find[0]))


def alert_log(log_dict):
    """
    预警，添加预警到/logs/alert.log中
    :param log_dict: 解码后的字典
    : 咧子：{time: "", method: "", url: "", level: "", title: ""}
    """
    log_dict['time'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log = "{} {} {} level：{} 类型：{}\n".format(log_dict['time'], log_dict['method'], log_dict['url'],
                                               log_dict['level'], log_dict['title'])
    with open("./logs/alert.log", mode="a") as file:
        file.write(log)
    with open("./logs/alert_json.log", mode="a") as file:
        file.write(json.dumps(log_dict) + '\n')
    config = decode_yaml("./conf/config.yml")['checkFile']
    alert_level = config['set_send_email_and_block']
    send = config['set_send_email']
    to = config['set_get_email']
    passwd = config['set_token_email']
    if log_dict['level'] >= alert_level:
        # 发送邮箱IP
        sed_email(log, send, to, base64.b64decode(passwd).decode())
        # print("log_dict")


def sed_email(log, send, to, passwd):
    # 直接导入内置模块
    import smtplib  # smtplib模块主要用于处理SMTP协议
    # email模块主要处理邮件的头和正文等数据
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    print("发送邮件")
    # 定义发件人和收件人
    sender = send  # 发送邮箱
    receiver = to  # 接收邮箱

    # 构建邮件的主体对象
    msg = MIMEMultipart()
    msg['Subject'] = '预警信息'
    msg['From'] = sender
    msg['To'] = receiver

    content = MIMEText(log, 'html', 'utf-8')
    msg.attach(content)

    # 建立与邮件服务器的连接并发送邮件
    smtp_obj = smtplib.SMTP()  # 如果基于SSL，则 smtplib.SMTP_SSL
    smtp_obj.connect('smtp.qq.com', '25')
    smtp_obj.login(user=send, password=passwd)
    smtp_obj.sendmail(sender, receiver, str(msg))
    smtp_obj.quit()


def run_shell(command):
    # 执行命令
    array = os.popen(command).readlines()
    return array


def block(srcip):
    cmd = f"iptables -I INPUT -s {srcip} -p tcp --dport 80  -j DROP"
    res = os.popen(cmd).read()
    if 'success' in res:
        print(f"成功封禁攻击源{srcip}!")


# 远程日志接收
def system_monitor():
    while True:
        linn_utils.local_monitor(1)


# 本地主机状态监控
def receive_log():
    linn_utils.receive_log()
