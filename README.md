INFQ（IDS + Iptable-nfqueue）实现的一个入侵检测系统，可以实现对日志、目录、文件和流量的检查，通过iptable-nfqueue还可以对流量进行实时监控和决策（ACCEPT和DROP）

## 安裝INFQ

环境：Centos 7，python 3.8

1. 安装虚拟环境

   ```sh
   python -m venv venv
   . venv/bin/activate
   ```

2. 安裝依赖包

   ```sh
   pip3 install --upgrade pip
   pip3 install -r requirements.txt
   ```

3. 运行`python3 main`

   ![Snipaste_2023-02-20_12-13-43](https://shihao-icu-1304033786.cos.ap-shanghai.myqcloud.com/shihao.icu/Snipaste_2023-02-20_12-13-43.png)



## INFQ 配置

```yaml
checkFile:
  # 设置扫描目录间隔，单位秒 
  set_ck_dir_time: 100
  # 需要监控的目录
  dir:
    # - /opt/lampp/htdocs
  # 白名单
  exclude_dir:
    # - /opt/lampp/htdocs/test
  # 设置扫描日志的时间
  set_ck_file_time: 100
  # 需要监控的日志文件，单位秒
  log:
    # - /var/log/secure
    # - /opt/lampp/logs/access_log
    # - logs/command.log
  # 对配置文件进行检测
  sca:
    # - /opt/lampp/etc/php.ini
  # 打印网络流量
  logger.info_net: true
  # 设置配置文件扫描时间
  set_ck_sca_time: 10000
  # 设置多少等级发送邮件和封闭IP
  set_send_email_and_block: 10
  # 设置邮箱配置信息
  # 发件人
  set_send_email: email
  # 收件人
  set_get_email: email
  # 设置密码
  set_token_email: ssss
  # 设置检测协议
  protocol: http
  # 设置白名单
  white_ip:
    - 192.168.33.28
  # 设置IP访问阈值
  number: 20 # 单位次数
  # 设置IP访问时间
  set_ck_net_outtime: 1 # 单位s
  # 设置NF监听流量
  nfqueue: true
  # 设置监听信道
  queue: 1
  # 设置网卡
  iface: ens33
  # 运程监控配置文件列表
  # 是否开启远程服务
  remote: false
  etc:
    # - '/opt/lampp/etc/php.ini'
  # 远程主机
  rhost:
    - hostnum: 1
      ip: 192.168.235.137
      user: root
      passwd: '1'

```



## Hids规则配置案例

```yaml
# id: 为规则编号，唯一，用来给规则做标识
# title: 为规则标题
# level: 等级，1-12，12代表危险程度最高
# decoder_key: 为解码器的名字
# type: 默认为文本日志（text），可以设置为command
# method: 声明什么方式触发的事件
# url：声明源头
- id: 3001
  title: sql注入攻击
  level: 4
  decoder_key: apache_access 
  rules: select%20|union%20
  method: log
- id: 3002
  title: 反弹shell
  decoder_key: netstat
  method: netstat
  url: netstat -anpt # 针对命令，用于标识日志出处
  level: 12
  rules: \S+:\d+\s+ESTABLISHED\s+\d+\/bash

- id: 3003 # 唯一
  title: 遭受大量SQL注入攻击 # 标题兼加描述
  # decoder_key: sql # 绑定解码器
  level: 7 # 预警等级，10级后发送邮件
  # action: reject # 针对于NFQ，用于操作流量，可选参数，reject、drop或accept
  if:
    id: 3001
    number: 10
    time: 10
  method: log # 规则类型，目前可以输入任意值、

```

## NIDS规则案例

```yaml
- id: 1001 # 唯一
  title: 疑似sql注入攻击 # 标题兼加描述
  decoder_key: sql # 绑定解码器
  level: 2 # 预警等级，10级后发送邮件
  action: drop # 针对于NFQ，用于操作流量，可选参数，reject、drop或accept
  rules: union%20|select%20 # 匹配g
  method: NET # 规则类型，目前可以输入任意值、

- id: 1002 # 唯一
  title: 遭受大量SQL注入攻击 # 标题兼加描述
  # decoder_key: sql # 绑定解码器
  level: 7 # 预警等级，10级后发送邮件
  # action: reject # 针对于NFQ，用于操作流量，可选参数，reject、drop或accept
  if:
    id: 1001
    number: 10
    time: 10
  method: NET # 规则类型，目前可以输入任意值、

- id: 1003 # 唯一
  title: 访问敏感数据 # 标题兼加描述
  decoder_key: phpinfo # 绑定解码器
  level: 2 # 预警等级，10级后发送邮件
  action: drop # 针对于NFQ，用于操作流量，可选参数，reject、drop或accept
  rules: phpinfo\.php # 匹配g
  method: NET # 规则类型，目前可以输入任意值、
```

## 目录监控规则案例

```yaml
- id: 1
  title: 一句话木马
  pcre: eval\(
  method: File
  url: ~
  level: 9
```

## 解码器规则案例

```yaml
- apache_access:
     id: 1
     pcre: (\d+\.\d+\.\d+\.\d+).+\[.+\]\s+"(\S+)\s+(\S+)
     fields: ['ip', 'method', 'url']
- netstat:
     pcre: (\S+:\d+)\s+\S+\s+(\d+\/bash)
     fields: ['destip', 'pid']
- sql:
     pcre: (\S+)\s+(\S+)
     fields: ['method', 'url']
- phpinfo:
     pcre: (phpinfo\.php)
     fields: ['url']
```

## 效果图展示

下面是NFQUEUE的拦截演示，下面运行INFQ

![Snipaste_2023-02-20_13-14-47](https://shihao-icu-1304033786.cos.ap-shanghai.myqcloud.com/shihao.icu/Snipaste_2023-02-20_13-14-47.png)

对靶机进行简单的sql注入：http://192.168.79.128/dashboard/?union%20select

![INFQ](https://shihao-icu-1304033786.cos.ap-shanghai.myqcloud.com/shihao.icu/INFQ.gif)

