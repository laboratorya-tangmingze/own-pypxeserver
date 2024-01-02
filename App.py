# coding: utf-8

import csv
from typing import ClassVar, Dict, Union, List, Tuple, Optional, TypedDict

OPTIONS: Dict[int, Dict[str, Union[str, int]]] = {
    int(line[0]): {
        "name": line[1],
        "len": int(line[2]) if line[2].isdigit() else line[2],
        "description": line[3],
        "rfc": line[4].split("RFC")[-1][:-1],
    }
    for line in csv.reader(open(r"assets\options.csv", encoding='utf-8').readlines())
    if line[0].isdigit()
}

mac_vendor_map: Dict[str, str] = {
    line.split("\t\t")[0].split(" ")[0]: line.split("\t\t")[1]
    for line in [
        line.strip()
        for line in open(r"assets\oui.txt", encoding='utf-8').readlines()
        if "(base 16)" in line
    ]
}

print(mac_vendor_map.get(
            '',
            "Unknown Manufacturer",
        )
)