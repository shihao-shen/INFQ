import sys
import time

sys.path.append("..")
from lib import tools


class ExecShell:
    """
        定时执行命令，命令格式
        [{'id': 1, 'time': 10, 'shell': 'netstat -anpt'}]
    """

    def __init__(self, shells):
        self.shell_list = shells
        self.set_time()

    def set_time(self):
        for i in self.shell_list:
            i['timestamp'] = time.time()

    def run(self):
        timestamp = time.time()
        # print(timestamp)
        for i in self.shell_list:
            if i['timestamp'] < timestamp - i['time']:
                with open(r'logs/command.log', 'a') as f:
                    # 执行命令并返回结果，写到日志
                    for j in tools.run_shell(i['shell']):
                        f.write(j)
                self.set_time()
        time.sleep(1)
