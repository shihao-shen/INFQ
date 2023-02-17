import time
import sys
import threading
import os
sys.path.append("..")
from lib import tools


class DirCheck:
    def __init__(self, config, rules):
        # 设置时间戳，用来判定是否检测目录文件
        self.time = time.time()
        self.config = config
        # 遍历需要检测的目录
        self.check_dir = []
        for i in self.config['checkFile']['dir']:
            if not os.path.isdir(i):
                continue

            self.check_dir = self.check_dir + tools.find_file(i, self.config['checkFile']['exclude_dir'])
        # 获取规则
        self.rules = rules
    
    def check_dir_value(self, path):
        # print(path)
        with open(path, "r+b") as f:
            payload = f.read()
            # 规则匹配检测文件内容
            for rule in self.rules:
                # 对配置文件进行过滤
                if tools.check_value(rule['pcre'].encode(), payload):
                    rule['url'] = path
                    tools.alert_log(rule)

    def check_file(self):
        while True:
            print("开始检测目录")
            for i in self.check_dir:
                self.check_dir_value(i)
            time.sleep(self.config['checkFile']['set_ck_dir_time'])

    def run(self):
        check_file = threading.Thread(target=self.check_file)
        check_file.setDaemon(True)
        check_file.start()
