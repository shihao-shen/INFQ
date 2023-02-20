from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP
from lib import tools
import re
import os
import time
from loguru import logger

class Capture:
    def __init__(self, rules, decoder, config) -> None:
        # 规则
        self.rules = rules
        # 解码
        self.decoder = decoder
        # 流量类型
        self.code = {'http': b'HTTP/'}
        # 限制次数
        self.number = config['checkFile']['number']
        # 设置阈值有效时间
        self.set_ck_net_outtime = config['checkFile']['set_ck_net_outtime']
        # 流量协议
        self.protocol = config['checkFile']['protocol']
        # 请求类型和下标
        self.method = {'GET': 0, 'POST': -1}
        # ip访问次数
        self.srcip_dropip = {}
        # ip访问时间
        self.srcip_time = {}
        # ip白名单
        self.white_ip = config['checkFile']['white_ip']
        # 是否开启nfq
        self.nfq = config['checkFile']['nfqueue']
        # 设置监听队列
        self.queue = config['checkFile']['queue']
        # 设置监听网卡
        self.iface = config['checkFile']['iface']
        # 流量裁决
        self.verdict = 'accept'
        # 是否打印流量
        print_net = config['checkFile']['logger.info_net']
        # 用于记录规则调用次数
        self.check_rule_number = tools.CountRule()

    def pcre(self, p):
        # logger.info(p)遍li
        # 遍历规则长度
        for i in range(len(self.rules)):
            # 正则匹配rules

            if 'if' in self.rules[i]:
                self.check_rule_number.check_rule(self.rules[i])
            else:
                # logger.info(tools.check_value(self.rules[i]['rules'], p))
                if tools.check_value(self.rules[i]['rules'], p):
                    # logger.info(self.rules[i])
                    self.check_rule_number.check_rule(self.rules[i])
                    self.decoder_extract(p, self.rules[i])
                    # self.check_rule_number.check_rule(self.rules[i])
                    self.verdict = "drop"

    def decoder_extract(self, p, rule):
        key = rule['decoder_key']
        log = tools.extract_fields(self.decoder[key]['pcre'], p, self.decoder[key]['fields'])
        log['method'] = "NET"
        log.update(rule)
        tools.alert_log(log)

    def action(self, srcip):
        logger.debug("疑似遭受到cc和dos攻击" + self.code['http'].decode())
        logger.debug("封禁IP" + srcip)
        tools.block(srcip)

    def check_ip(self, srcip):
        # 判断IP是否在字典里
        if srcip in self.srcip_dropip:
            # 在的话就加1
            self.srcip_dropip[srcip] = self.srcip_dropip[srcip] + 1
            # 判断时间区间
            if time.time() - self.srcip_time[srcip] <= self.set_ck_net_outtime:
                # 判断访问次数
                if self.srcip_dropip[srcip] > self.number:
                    # 对攻击ip进行管理
                    self.action(srcip)
                    # 重新初始化次数和时间
                    self.srcip_dropip[srcip] = 1
                    self.srcip_time[srcip] = time.time()
            else:
                # 更新时间
                self.srcip_time[srcip] = time.time()
        else:
            # 不在就等于1，并且记录当前时间
            self.srcip_dropip[srcip] = 1
            self.srcip_time[srcip] = time.time()

    def run(self, pkt):
        x = pkt
        self.verdict = 'accept'
        if self.nfq:
            # 将NFQ监听的流量，转化为s
            x = IP(pkt.get_payload())
        if self.code[self.protocol] in x.lastlayer().original:

            # 替换换行和回车为逗号
            request_body = x.lastlayer().original.decode().replace('\r\n', ',')
            if self.print_net:
                logger.info(request_body)
            # 获取源IP地址
            srcip = x.src
            # 白名单跳过
            if srcip in self.white_ip:
                if self.nfq:
                    eval(f"pkt.{self.verdict}()")
                return
            # 限制一定时间内的连接次数
            self.check_ip(srcip)
            self.pcre(request_body)
        if self.nfq:
            eval(f"pkt.{self.verdict}()")

    def new_thread(self):

        try:
            logger.info("正在对网络进行进行监控")
            if not self.nfq:
                logger.info("使用SCAPY进行流量监控")
                sniff(filter="tcp", iface=self.iface, prn=lambda x: self.run(x))
            else:
                logger.info("使用IPTABLES NFQUEUE进行流量监控")
                os.system("iptables -I INPUT -j NFQUEUE --queue-num 1 --queue-bypass")
                queue = NetfilterQueue()
                queue.bind(self.queue, lambda x: self.run(x))
                queue.run()
        except KeyboardInterrupt:
            if self.nfq:
                os.system("iptables -D INPUT -j NFQUEUE --queue-num 1 --queue-bypass")
