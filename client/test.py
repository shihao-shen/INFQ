# import time
# from threading import Thread


# # 自定义线程函数
# def my_threadfunc(name,times:int):
#     for i in range(times):
#         logger.info("hello", name)
#         time.sleep(1)


# # 创建线程01，不指定参数
# thread_01 = Thread(target=my_threadfunc,args=('linn',20))
# # 启动线程01
# thread_01.start()


# # 创建线程02,指定参数，注意逗号不要少，否则不是一个tuple
# thread_01 = Thread(target=my_threadfunc, args=('Curry',50))
# # 启动线程02
# thread_01.start()

while True:
    logger.info(1)
