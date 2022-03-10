import logging
import os

pid = os.getpid()

handler = logging.FileHandler('/tmp/python-probe.{}.log'.format(pid))
formatter = logging.Formatter("%(asctime)s | %(levelname)-8s | %(filename)20s:%(lineno)-4d ] %(message)s")

handler.setFormatter(formatter)

logger = logging.getLogger('rasp')

logger.propagate = False
logger.setLevel(logging.INFO)
logger.addHandler(handler)
