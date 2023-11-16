#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2023/11/14 14:24
# @Author  : ltaicd
# @File    : FscanBeautify.py
# @Software: PyCharm
# @Version: 1.0
import os.path
import re
import sys
import time

import pandas as pd
from rich.console import Console
from rich.table import Table
from rich import box

cs = Console(log_path=False)


class FscanBeautify:
    def __init__(self, file):
        self.p = ['存活IP段', '开放端口', '系统', 'Exp', 'Poc', '网站标题', '弱口令', '指纹']
        self.AliveIp = []
        self.OpenPort = []
        self.OsList = []
        self.ExpList = []
        self.PocList = []
        self.TitleList = []
        self.WeakPasswd = []
        self.Finger = []
        self.filePath: str = file

    def readFile(self) -> str:
        with open(self.filePath, "r", encoding="utf-8", errors='ignore') as f:
            for i in f.readlines():
                yield i.strip("\n").replace('\x1b[36m', "").replace('\x1b[0m', "")

    def parserData(self):
        for data in self.readFile():
            OpenPort = "".join(re.findall(r'^\d\S+', data))
            if OpenPort:
                self.OpenPort.append({
                    "IP": OpenPort.split(":")[0],
                    "Port": OpenPort.split(":")[-1],
                })

            AliveIp = "".join(re.findall(r"\[\*]\sLiveTop\s\d+\.\d+\.\d+\.\d+/\d+.*", data))
            if AliveIp:
                cidr = "".join(re.findall(r"\d+\.\d+\.\d+\.\d+/\d+", AliveIp))
                count = "".join(re.findall(r"\d+$", AliveIp))
                self.AliveIp.append({
                    "Cidr": cidr,
                    "Count": int(count)
                })

            OsList = "".join(re.findall(r"\[\*]\s\d+\.\d+\.\d+\.\d+.*", data))
            if OsList:
                ip = "".join(re.findall(r"\d+\.\d+\.\d+\.\d+", OsList))
                for s in ["[*]", '\t', "\x01", '\x02', ip]:
                    OsList.replace(s, "")
                oss = OsList.strip()

                self.OsList.append({
                    "IP": ip,
                    "OS": oss
                })

            ExpList = "".join(re.findall(r"\[\+]\s\d+\.\d+\.\d+\.\d+.*", data))
            if ExpList:
                ip = "".join(re.findall(r"\d+\.\d+\.\d+\.\d+", ExpList))
                exp = ExpList.replace(ip, '').replace("[+]", "").replace('\t', '').strip()
                self.ExpList.append({
                    "IP": ip,
                    "Exp": exp
                })

            PocList = "".join(re.findall(r"\[\+]\shttp\S.*", data))
            if PocList:
                url = "".join(re.findall(r"(https?://\S+)", PocList))
                poc = PocList.replace(url, '').replace("[+]", "").replace('\t', '').strip()
                self.PocList.append({
                    "Url": url,
                    "Poc": poc
                })

            TitleList = "".join(re.findall(r'\[\*]\sWebTitle.*', data))
            if TitleList:
                url = "".join(re.findall(r"http\S+", TitleList)[0])
                code = "".join(re.findall(r'(?<=code:)\S+', TitleList))
                length = "".join(re.findall(r'(?<=len:)\S+', TitleList))
                title = "".join(re.findall(r'(?<=title:).*', TitleList))
                self.TitleList.append({
                    "Url": url,
                    "StatusCode": int(code),
                    "Length": int(length),
                    "Title": title
                })

            WeakPasswd = re.findall(r'((ftp|mysql|mssql|SMB|RDP|Postgres|SSH|oracle|SMB2-shares)(:|\s).*)', data, re.I)
            if WeakPasswd:
                WeakPasswd = WeakPasswd[0][0].split(":")
                try:
                    passwd = WeakPasswd[3]
                except IndexError as e:
                    passwd = ''
                protocol = WeakPasswd[0]
                port = WeakPasswd[2]
                ip = "".join(re.findall(r"\d+\.\d+\.\d+\.\d+", str(WeakPasswd[1])))
                self.WeakPasswd.append({
                    "Protocol": protocol,
                    "IP": ip,
                    "Port": int(port),
                    "User&Passwd": passwd,
                    "Info": ''
                })

            WeakPasswd = re.findall(r'((redis|Mongodb)(:|\s).*)', data, re.I)
            if WeakPasswd:
                rd_all = WeakPasswd[0][0].split(" ")
                passwd = rd_all[-1] if 'file' not in "".join(rd_all[-2:]) else rd_all[1]
                if "".join(rd_all[1:4]) == 'likecanwrite':
                    passwd = ''
                protocol = WeakPasswd[0][1]
                if protocol.lower() == 'redis':
                    if "".join(rd_all[1:4]) != 'likecanwrite':
                        info = " ".join(rd_all[2:])
                    else:
                        info = " ".join(rd_all[1:])
                else:
                    info = ''
                port = (rd_all[0].split(":"))[2]
                ip = "".join(re.findall(r"\d+\.\d+\.\d+\.\d+", WeakPasswd[0][0]))
                self.WeakPasswd.append({
                    "Protocol": protocol,
                    "IP": ip,
                    "Port": int(port),
                    "User&Passwd": passwd,
                    "Info": info
                })

            WeakPasswd = re.findall(r"((Memcached)(:|\s).*)", data, re.I)
            if WeakPasswd:
                mc_all = WeakPasswd[0][0].split(" ")
                passwd = mc_all[2]
                protocol = mc_all[0]
                port = (mc_all[1].split(":"))[-1]
                ip = "".join(re.findall(r"\d+\.\d+\.\d+\.\d+", WeakPasswd[0][0]))
                self.WeakPasswd.append({
                    "Protocol": protocol,
                    "IP": ip,
                    "Port": int(port),
                    "User&Passwd": passwd,
                    "Info": ''
                })
            Finger = "".join(re.findall(r'.*InfoScan.*', data))
            if Finger:
                url = "".join(re.findall(r'http\S+', Finger))
                finger = Finger.split(url)[-1].strip()[1:-1]
                self.Finger.append({
                    "Url": url,
                    "Finger": finger,
                })

    def saveFile(self):
        fileName = f'outPut_{time.strftime("%Y-%m-%d_%H%M%S", time.localtime())}.xlsx'

        def format_file_size(size):
            units = ['B', 'KB', 'MB']
            for unit in units:
                if size < 1024:
                    return f"{size:.2f} {unit}"
                size /= 1024
            return f"{size:.2f} {units[-1]}"

        with pd.ExcelWriter(fileName) as writer:
            for index, s in enumerate(
                    [self.AliveIp, self.OpenPort, self.OsList, self.ExpList, self.PocList, self.TitleList,
                     self.WeakPasswd, self.Finger]):
                if s:
                    df = pd.DataFrame(s)
                    df.to_excel(writer, sheet_name=self.p[index], index=False)
        if os.path.exists(fileName):
            cs.print(f"文件已生成: {fileName} 大小: {format_file_size(os.path.getsize(fileName))}")

    def showInfo(self):
        table = Table(box=box.ASCII2, header_style="yellow", title_style="red")
        table.add_column("项目", justify="center", style="red")
        table.add_column("个数", style="magenta", justify="center")
        for index, s in enumerate([self.AliveIp, self.OpenPort, self.OsList, self.ExpList, self.PocList, self.TitleList,
                                   self.WeakPasswd, self.Finger]):
            if s:
                table.add_row(self.p[index], str(len(s)))
        cs.print(table)

    def run(self):
        self.parserData()
        self.showInfo()
        self.saveFile()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        cs.print('[red]请提供文件[/]: [blue]python3 FscanBeautify.py results.txt')
    elif os.path.exists(sys.argv[1]):
        FscanBeautify(sys.argv[1]).run()
    else:
        cs.print(f"[red]文件 {sys.argv[1]} 不存在")

