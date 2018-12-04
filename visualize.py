import os
import time
import json
from graphviz import Digraph
from tabulate import tabulate

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

def make_exclusive(tree, new_parent):
    for node in tree:
        if node['dependency'] == new_parent['dependency']:
            node['dependency'] = new_parent['stream_id']

def build_tree(lines):
    tree = []
    for line in lines:
        try:
            line_dict = json.loads(line)
            if 'dependency' in line_dict:
                tree.append(line_dict)
        except:
            print("ERROR parsing line: ", line)

    ret_tree = [] # The final tree that we return
    for node in tree:
        if node['exclusive'] == 1:
            # Exclusively depends on the parent. If the parent has children we need to change them
            make_exclusive(ret_tree, node)    
        if node not in ret_tree:
            ret_tree.append(node)
    return ret_tree


def draw_tree(tree):
    u = Digraph("deps")
    u.attr(size='6,6')
    u.node_attr.update(color='lightblue2', style='filled')
    for node in tree:
        u.edge(str(node['stream_id']), str(node['dependency']), label=str(node['weight']))
    
    u.view()

def get_file_type(url):
    """Do a best effort to guess the file type from the URL
       return unknown if it cannot be guessed
    """
    if '.css' in url:
        return "CSS"
    if '.html' in url or '.php' in url:
        return "HTML/PAGE"
    if '.js' in url:
        return "JS"
    if '.png' in url or '.jpeg' in url or '.svg' in url or '.jpg' in url:
        return "IMAGE"
    if '.ico' in url:
        return 'ICON'
    return "unknown"

def print_legend(lines):
    table = []
    for line in lines:
        if 'url' in line:
            try:
                j = json.loads(line)
                if len(j["url"])<=60:
                    url = j["url"]
                else:
                    url = "..."+ j["url"][-60:]
                table.append([j["stream_id"], url, get_file_type(j["url"])])  
            except:
                #print("Something went wrong with line: ", line)
                pass
    print(tabulate(table, ["Stream ID", "URL", "Type"], "fancy_grid"))

def run():
    lines = get_relavent_lines()
    move_log_file()
    tree = build_tree(lines)
    draw_tree(tree)
    print_legend(lines)


run()
