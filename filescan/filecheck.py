import pyinotify
import threading
import time
import sys
import os
sys.path.append("..")
from lib import tools
from loguru import logger


class MyEventHandler(pyinotify.ProcessEvent):
    """
    监控文件状态
    """

    def __init__(self, **args):
        super().__init__(**args)
        self.method = "文件状态"
        self.url = ""
        self.title = ""
        self.id = 0

    def process_IN_DELETE(self, event):
        self.url = event.pathname
        self.title = "文件被删除"
        self.id = 2001
        self.alert()

    def process_IN_MODIFY(self, event):
        self.url = event.pathname
        self.title = "文件修改"
        self.id = 2002
        self.alert()

    def process_IN_CREATE(self, event):
        self.url = event.pathname
        self.title = "文件新增加"
        self.id = 2003
        self.alert()

    def alert(self):
        # logger.info(self.title+":"+self.url)
        logs = {"method": self.method, "url": self.url, "title": self.title, "level": 5, "id": self.id}
        tools.alert_log(logs)


class FileCheck:
    """
        监控日志，并解析和告警
    """

    def __init__(self, dirs, log, rules, decoders):
        super(FileCheck, self).__init__()
        self.dir = dirs
        self.log = log
        self.rules = rules
        self.wm = pyinotify.WatchManager()
        self.handler = MyEventHandler()
        self.log_file = []
        self.decoders = decoders
        self.notifier = None
        self.check_rules_number = tools.CountRule()
        for i in self.log:
            # logger.info("开始监控："+i)
            if not os.path.isfile(i):
                continue
            f = open(i)
            f.seek(0, 2)
            self.log_file.append(f)

    def check_rules(self, value):
        """
        遍历规则，判断vale是否合法
        :param value: 需要校验的日志
        """
        # 规则匹配
        for rule in self.rules:
            # 如果匹配成功，则说明有害
            if 'if' not in rule:
                # 匹配规则
                if tools.check_value(rule['rules'], value):

                    pcre = self.decoders[rule['decoder_key']]['pcre']
                    logs = value
                    # 计算规则预警次数
                    self.check_rules_number.check_rule(rule)
                    fields = self.decoders[rule['decoder_key']]['fields']
                    # 设置预警格式
                    rule.update(tools.extract_fields(pcre, logs, fields))

                    tools.alert_log(rule)
            elif 'if' in rule:
                # 检查规则次数
                tools.CountRule().check_rule(rule)

    def check_log(self):
        """
            实时监控日志
        """
        while True:
            # logger.info("正在监控文件")
            for f in self.log_file:
                array = f.readlines()
                if len(array) > 0:
                    # 循环遍历添加的内容
                    for line in array:
                        # 规则匹配
                        self.check_rules(line)

            time.sleep(5)

    def __del__(self):
        """
            关闭文件
        """
        for f in self.log_file:
            f.close()

    def check_dir(self):
        """
        :return: dict
        """
        self.notifier = pyinotify.Notifier(self.wm, self.handler)
        mask = pyinotify.IN_DELETE | pyinotify.IN_MODIFY | pyinotify.IN_CREATE
        for file in self.dir:
            self.wm.add_watch(file, mask)

    def run(self):
        logger.info("监控目录")
        self.check_dir()
        check_dir = threading.Thread(target=self.notifier.loop)
        check_dir.setDaemon(True)
        check_dir.start()
        logger.info("监控日志")
        check_log = threading.Thread(target=self.check_log)
        check_log.setDaemon(True)
        check_log.start()
