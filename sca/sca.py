import sys
import threading
import time
import os
from loguru import logger
sys.path.append("..")
from lib import tools


class Sca:
    def __init__(self, rules, files, config):
        # 获取配置文件
        self.config = config
        # 获取规则列表
        self.rules = rules
        # 获取监控文件列表
        self.files = files

    def read_files(self):
        # 读取文件
        while True:
            for i in self.files:
                # 打开文件
                if not os.path.isfile(i):
                    continue
                with open(i, "r+b") as file:
                    value = file.read()
                    self.check_file(value, i)
            time.sleep(self.config['checkFile']['set_ck_sca_time'])

    def check_file(self, value, path):
        """
        循环匹配规则
        value: 文本
        path: 路径
        """
        for rule in self.rules:
            # logger.info(i)
            if tools.check_value(rule['rules'].encode(), value):
                rule['url'] = path
                tools.alert_log(rule)
        return False

    def run(self):
        sca = threading.Thread(target=self.read_files)
        sca.setDaemon(True)
        sca.start()
