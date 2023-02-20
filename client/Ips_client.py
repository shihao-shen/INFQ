import tools
import threading
import time
from loguru import logger

class ips_client:
    rhost_info = []
    loacl_etc = []
    local_log = []
    loacl_status = []
    client = object

    def __init__(self):
        data = tools.decode_yaml('./config.yml')
        self.rhost_info = data['rhost']
        self.loacl_etc = data['etc']
        self.local_logs = data['logs']
        self.loacl_status = data['status']
        self.client = tools.socket_conn(self.rhost_info['ip'],(self.rhost_info['port']))

    def send_log(self):
        for log in self.local_logs:
            logger.info(f'创建一个线程发送{log}')
            a = threading.Thread(target=tools.monitor_log,args=(self.client,log))
            a.start()
    
    def send_sys_status(self):
        while True:
            tools.monitor_system(self.client,1)
            time.sleep(10)

    def send_etc(self):
        pass

if __name__ == "__main__":
    ipc = ips_client()
    a = threading.Thread(target=ipc.send_log())
    a.start()
    b = threading.Thread(target=ipc.send_sys_status())
    b.start()



# data = tools.decode_yaml('./config.yml')
# logger.info(data['etc'])

  