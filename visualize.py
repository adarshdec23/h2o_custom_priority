import os
import time
log_file = "/home/toor/h2o/log.txt"
token_info = "*****+++++"
token_url = "*****====="

def get_relavent_lines():
    lines = []
    with open(log_file, "r") as f:
        for line in f:
            line.strip()
            if len(line) < 10:
                continue
            prefix = line[:10]
            if prefix == token_info or prefix == token_url:
                lines.append(line[10:-1])
    return lines

def move_log_file():
    os.rename(log_file, log_file+'_'+str(int(time.time())))

lines = get_relavent_lines()
move_log_file()
