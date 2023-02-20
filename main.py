from lib import tools
from filescan.filecheck import FileCheck
from exec.exec_shell import ExecShell
from dircheck.dircheck import DirCheck
from loguru import logger
from sca.sca import Sca
import threading
import linn_utils
import time
import flow
import sys
import os


class Ids:
    # 规则列表，主要存放/conf/rules/下的所有规则文件路径
    log_rules = {}
    dir_rules = {}
    # 监控文件，主要存放需要监控的规则文件路径
    log_files = []
    dir_files = []
    # 配置
    config = {}

    def __init__(self):
        logger.info("加载配置文件")
        # yaml解码
        self.config = tools.decode_yaml("./conf/config.yml")
        # 日志文件路径列表
        if self.config['checkFile'].__contains__("log"):
            self.log_files = self.config['checkFile']['log']
        else:
            self.log_files = []
        # 需要监控的目录路径列表
        if self.config['checkFile'].__contains__("log"):
            self.dir_files = self.config['checkFile']['dir']
        else:
            self.dir_files = []
            

        logger.info("加载日志文件")
        # [{'id': 1, 'title': '标题', 'description': '描述', 'level': '等级', 'action': 'drop', 'rules': '规则 - "rules"'},
        # {'id': 2, 'title': '标题', 'description': '描述', 'level': '等级', 'action': 'drop', 'rules': '规则 - "rules"'}]
        self.log_rules = tools.foreach_rules(tools.find_file('./conf/rules/nids'))
        self.dir_rules = tools.foreach_rules(tools.find_file('./conf/rules/hids'))
        
        self.decoder = tools.merge(tools.foreach_rules(tools.find_file('./conf/decoder/')))
        # for i in self.decoder:

        self.command = tools.foreach_rules(tools.find_file('./conf/command/'))
        self.dircheck_rule = tools.foreach_rules(tools.find_file('./conf/dir'))
        self.sca_rules = tools.foreach_rules(tools.find_file('./conf/sca'))
        # logger.info(self.sca_rules)
        self.etc_files = self.config['checkFile']['etc']
        # 需要远程监控主机信息
        self.rhost_info = self.config['checkFile']['rhost']
        # FileCheck文件监控
        self.filecheck = FileCheck(self.dir_files, self.log_files, self.dir_rules, self.decoder)

        # 定时运行命令
        self.exec_shell = ExecShell(self.command)

        # 定时检测目录文件
        self.dir_check = DirCheck(self.config, self.dircheck_rule)
        # 流量监测
        self.Capture = flow.Capture(self.log_rules, self.decoder, self.config)
        # 配置文件监控
        self.sca = Sca(self.sca_rules, self.config['checkFile']['sca'], self.config)
        # logger.info(self.decoder)
        # self.etc_rules = tools.decode_yaml('./conf/rules/hids/cis_linn.yml')

    def remote_etc_check(self):
        scan_res = {}
        rhost_info = self.rhost_info
        # 遍历需要检查的远程主机信息
        for info in rhost_info:
            # 与远程服务器建立连接
            sftp = linn_utils.remote_ssh_conn(info)
            # 遍历需要检查的配置文件
            for file in self.etc_files:
                # 下载远程主机上的配置文件
                localpath = f"/tmp/linn/etc/{info['ip']}_{file.split('/')[-1]}"
                if not os.path.isdir("/tmp/linn/etc"):
                    os.makedirs("/tmp/linn/etc")
                sftp.get(file, localpath)

    def run(self):
        try:
            # 是否开启远程监控
            if self.config['checkFile']['remote']:
                remote_etc = threading.Thread(target=self.remote_etc_check)
                remote_etc.setDaemon(True)
                remote_etc.start()
                remote_log = threading.Thread(target=self.recive_log)
                remote_log.setDaemon(True)
                remote_log.start()
                log_classfy = threading.Thread(target=linn_utils.classify_log, args=('/tmp/linn/logs/remote.log',))
                log_classfy.setDaemon(True)
                log_classfy.start()
            # 多线程
            # 扫描流量
            scan = threading.Thread(target=self.Capture.new_thread)
            scan.setDaemon(True)
            scan.start()

            self.filecheck.run()
            self.dir_check.run()
            self.sca.run()
            while True:
                logger.info("正在监控则规")
                self.exec_shell.run()
                time.sleep(self.config['checkFile']['set_ck_file_time'])
        except KeyboardInterrupt:
            import os
            logger.info("退出程序")
            if self.config['checkFile']:
                os.system("iptables -D INPUT -j NFQUEUE --queue-num 1 --queue-bypass")
            sys.exit()


# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    ids = Ids()
    ids.run()
