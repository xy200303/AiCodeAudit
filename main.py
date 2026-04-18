import argparse
import os
from loguru import logger

from audit.service import run_audit
from config import C
from utils import is_cmd_mode


def init():
    logger.add(sink="app.log", rotation="50 MB", format="{time} | {level} | {message}")
    logger.info("加载配置文件 config.yaml")
    logger.info("当前模型:{}，超时:{}秒，并发上限:{}", C.openai.model, C.openai.timeout_seconds, C.openai.max_concurrency)
    logger.info("当前命令行模式:{}", is_cmd_mode())

    parser = argparse.ArgumentParser(description="AI 代码审计工具")
    parser.add_argument('-d', type=str, help='目标项目目录路径', default="./演示项目/openssh-9.9p1")
    parser.add_argument('-o', type=str, default="./output", help="输出文件目录，默认是 ./output")
    parser.add_argument('-b', type=int, default=10, help="每批任务数，默认是10")

    args = parser.parse_args()
    logger.info("当前项目目录:{}", args.d)
    logger.info("当前输出目录:{}", args.o)
    if not os.path.exists(args.o):
        os.makedirs(args.o)
    return args

def main():
    args = init()
    run_audit(args.d, args.o, args.b)


if __name__ == "__main__":
    main()
