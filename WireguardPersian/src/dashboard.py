"""
< Wireguard Panel > - Copyright(C) 2021 Donald Zou & Borrowed Codes from Mr Amir & Codes modified and edited BY [https://github.com/Azumi67]
Under Apache-2.0 License
"""
import psutil
import os
import secrets
import subprocess
import time
from datetime import datetime, timedelta
from glob import glob
from operator import itemgetter
from pathlib import Path
from threading import Thread
import sqlite3
import configparser
import hashlib
import ipaddress
import json
import re
import urllib.parse
import urllib.request
import urllib.error
import zipfile
import ifcfg
import pytz
from flask import Flask, request, render_template, redirect, url_for, session, jsonify, g, send_file
from flask_qrcode import QRcode
from icmplib import ping, traceroute

# Import other python files
from util import regex_match, check_DNS, check_Allowed_IPs, check_remote_endpoint, \
    check_IP_with_range, clean_IP_with_range

# Dashboard Version
DASHBOARD_VERSION = 'v3.0.6'

# WireGuard's configuration path
WG_CONF_PATH = '/etc/wireguard'
BLACKLISTED_CONFIGS = {"proxy", "warp", "warp-account"}

# Dashboard Config Name
configuration_path = os.getenv('CONFIGURATION_PATH', '.')
DB_PATH = os.path.join(configuration_path, 'db')

if not os.path.isdir(DB_PATH):
    os.mkdir(DB_PATH)

DB_FILE_PATH = os.path.join(configuration_path, 'db', 'wgdashboard.db')
DASHBOARD_CONF = os.path.join(configuration_path, 'wg-dashboard.ini')

# Upgrade Required
UPDATE = None

# Flask App Configuration
app = Flask("WGDashboard")
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 5206928
app.secret_key = secrets.token_urlsafe(16)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Enable QR Code Generator
QRcode(app)


# TODO: use class and object oriented programming


######### format_bytes-func #########
def format_bytes(bytes):
    if bytes < 1024:
        return f"{bytes} B"
    elif bytes < 1024 ** 2:
        return f"{bytes / 1024:.2f}KB"
    elif bytes < 1024 ** 3:
        return f"{bytes / (1024 ** 2):.2f}MB"
    else:
        return f"{bytes / (1024 ** 3):.2f}GB"


######### total-ram-func #########
def get_total_ram():
    with open('/proc/meminfo') as meminfo_file:
        for line in meminfo_file:
            if line.startswith('MemTotal:'):
                total_ram_kb = int(line.split()[1])
                return total_ram_kb
                
######### used_ram-func #########
def get_used_ram():
    with open('/proc/meminfo') as meminfo_file:
        meminfo = meminfo_file.read()
    lines = meminfo.split('\n')

    for line in lines:
        if line.startswith('MemTotal:'):
            total_ram_kb = int(line.split()[1])
        elif line.startswith('MemFree:'):
            free_ram_kb = int(line.split()[1])
        elif line.startswith('Buffers:'):
            buffers_kb = int(line.split()[1])
        elif line.startswith('Cached:'):
            cached_kb = int(line.split()[1])

    used_ram_kb = total_ram_kb - free_ram_kb - buffers_kb - cached_kb
    return used_ram_kb

######### cpu_capacity-func ######### 
def get_cpu_capacity():
    cpuinfo_path = '/proc/cpuinfo'
    if not os.path.exists(cpuinfo_path):
        return None

    with open(cpuinfo_path, 'r') as cpuinfo_file:
        cpuinfo = cpuinfo_file.read()

    processor_lines = [line for line in cpuinfo.split('\n') if line.startswith('processor')]
    return len(processor_lines)
    
        
######### cpu_usage-func #########    
def get_cpu_usage():
    with open('/proc/stat') as stat_file:
        lines = stat_file.readlines()

    for line in lines:
        if line.startswith("cpu "):
            fields = line.strip().split()
            user, nice, system, idle, iowait, irq, softirq = map(int, fields[1:8])
            total = user + nice + system + idle + iowait + irq + softirq
            usage = 100.0 * (total - idle) / total
            return usage


######### get_hard_info-func #########   
def get_hard_info():
    # Get the disk partitions
    partitions = psutil.disk_partitions()

    for partition in partitions:
        # Get the disk usage statistics
        usage = psutil.disk_usage(partition.mountpoint)

        #print(f"Device: {partition.device}")
        #print(f"Mountpoint: {partition.mountpoint}")
        #print(f"Total Size: {usage.total / (1024 ** 3):.2f} GB")
        #print(f"Free Space: {usage.free / (1024 ** 3):.2f} GB")
        #print(f"Used Space: {usage.used / (1024 ** 3):.2f} GB")
        #print(f"Percentage Used: {usage.percent}%\n")
    
        return f"{format_bytes(usage.used)} / {format_bytes(usage.total)}"
    
    



def connect_db():
    """
    Connect to the database
    @return: sqlite3.Connection
    """
    return sqlite3.connect(DB_FILE_PATH)


def get_dashboard_conf():
    """
    Get dashboard configuration
    @return: configparser.ConfigParser
    """
    r_config = configparser.ConfigParser(strict=False)
    r_config.read(DASHBOARD_CONF)
    return r_config


def set_dashboard_conf(config):
    """
    Write to configuration
    @param config: Input configuration
    """
    with open(DASHBOARD_CONF, "w", encoding='utf-8') as conf_object:
        config.write(conf_object)


# Get all keys from a configuration
def get_conf_peer_key(config_name):
    """
    Get the peers keys of wireguard interface.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return list of peers keys or text if configuration not running
    @rtype: list, str
    """

    try:
        peers_keys = subprocess.check_output(f"wg show {config_name} peers",
                                             shell=True, stderr=subprocess.STDOUT)
        peers_keys = peers_keys.decode("UTF-8").split()
        return peers_keys
    except subprocess.CalledProcessError:
        return config_name + " در حال اجرا نیست. آن را فعال کنید."


def get_conf_running_peer_number(config_name):
    """
    Get number of running peers on wireguard interface.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Number of running peers, or test if configuration not running
    @rtype: int, str
    """

    running = 0
    # Get latest handshakes
    try:
        data_usage = subprocess.check_output(f"wg show {config_name} latest-handshakes",
                                             shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return "stopped"
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    now = datetime.now()
    time_delta = timedelta(minutes=2)
    for _ in range(int(len(data_usage) / 2)):
        minus = now - datetime.fromtimestamp(int(data_usage[count + 1]))
        if minus < time_delta:
            running += 1
        count += 2
    return running


def read_conf_file_interface(config_name):
    """
    Get interface settings.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Dictionary with interface settings
    @rtype: dict
    """

    conf_location = WG_CONF_PATH + "/" + config_name + ".conf"
    with open(conf_location, 'r', encoding='utf-8') as file_object:
        file = file_object.read().split("\n")
        data = {}
        for i in file:
            if not regex_match("#(.*)", i):
                if len(i) > 0:
                    if i != "[Interface]":
                        tmp = re.split(r'\s*=\s*', i, 1)
                        if len(tmp) == 2:
                            data[tmp[0]] = tmp[1]
    return data


def read_conf_file(config_name):
    """
    Get configurations from file of wireguard interface.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Dictionary with interface and peers settings
    @rtype: dict
    """

    conf_location = WG_CONF_PATH + "/" + config_name + ".conf"
    f = open(conf_location, 'r')
    file = f.read().split("\n")
    conf_peer_data = {
        "Interface": {},
        "Peers": []
    }
    peers_start = 0
    for i in range(len(file)):
        if not regex_match("#(.*)", file[i]) and regex_match(";(.*)", file[i]):
            if file[i] == "[Peer]":
                peers_start = i
                break
            else:
                if len(file[i]) > 0:
                    if file[i] != "[Interface]":
                        tmp = re.split(r'\s*=\s*', file[i], 1)
                        if len(tmp) == 2:
                            conf_peer_data['Interface'][tmp[0]] = tmp[1]
    conf_peers = file[peers_start:]
    peer = -1
    for i in conf_peers:
        if not regex_match("#(.*)", i) and not regex_match(";(.*)", i):
            if i == "[Peer]":
                peer += 1
                conf_peer_data["Peers"].append({})
            elif peer > -1:
                if len(i) > 0:
                    tmp = re.split(r'\s*=\s*', i, 1)
                    if len(tmp) == 2:
                        conf_peer_data["Peers"][peer][tmp[0]] = tmp[1]

    f.close()
    # Read Configuration File End
    return conf_peer_data


def get_latest_handshake(config_name):
    """
    Get the latest handshake from all peers of a configuration
    @param config_name: Configuration name
    @return: str
    """
    try:
        data_usage = subprocess.check_output(f"wg show {config_name} latest-handshakes",
                                             shell=True, stderr=subprocess.STDOUT).decode("UTF-8")
    except subprocess.CalledProcessError:
        return "stopped"

    data_usage = list(filter(bool, data_usage.split("\n")))

    now = time.time()
    time_delta = 2 * 60  

    for handshake in data_usage:
        (_id, _time) = handshake.split("\t")
        minus = now - int(_time)
        
        if minus < time_delta:
            status = "running"
        else:
            status = "stopped"

        if int(_time) > 0:
            query = f"UPDATE {config_name} SET latest_handshake = ?, status = ? WHERE id = ?"
            bindings = (str(minus).split(".", maxsplit=1)[0], status, _id)
            g.cur.execute(query, bindings)
        else:
            query = f"UPDATE {config_name} SET latest_handshake = '(None)', status = ? WHERE id = ?"
            bindings = (status, _id)
            g.cur.execute(query, bindings)

    return "done"


def update_transfer(config_name, peer, total_sent, total_receive, cumu_receive, cumu_sent, end_active, status):
    """
    Update transfer information for a specific peer in a configuration
    @param config_name: Configuration name
    @param peer: Peer ID
    @param total_sent: Total sent data for the peer
    @param total_receive: Total received data for the peer
    @param cumu_receive: Cumulative received data for the peer
    @param cumu_sent: Cumulative sent data for the peer
    @param end_active: Boolean indicating if the peer is still active
    @param status: Status of the peer
    """
    query = f"""
        UPDATE {config_name}
        SET total_receive = ?,
            total_sent = ?,
            cumu_receive = ?,
            cumu_sent = ?,
            cumu_data = ?,
            end_active = ?,
            status = ?
        WHERE id = ?
    """
    g.cur.execute(query, (
        round(total_receive, 4),
        round(total_sent, 4),
        round(cumu_receive, 4),
        round(cumu_sent, 4),
        round(cumu_sent + cumu_receive, 4),
        int(end_active),
        status,
        peer
    ))


def get_transfer(config_name):
    """
    Get transfer from all peers of a configuration
    @param config_name: Configuration name
    @return: str
    """
    try:
        data_usage = subprocess.check_output(f"wg show {config_name} transfer", shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return "stopped"

    data_usage = data_usage.decode("UTF-8").split("\n")
    transfers = {}

    for line in filter(bool, data_usage):
        key, down, up = line.split("\t")
        transfers[key] = {
            "id": key,
            "down": down,
            "up": up
        }

    peers = g.cur.execute(f"SELECT total_receive, total_sent, cumu_receive, cumu_sent, status, bandwidth, end_active, ends_at, id FROM {config_name}").fetchall()

    if len(peers) > 0:
        for peer in peers:
            total_receive, total_sent, cumu_receive, cumu_sent, status, bandwidth, end_active, ends_at, key = peer
            ends_at = ends_at or None
            end_active = bool(True or end_active)
            status = peer[4]

            transfer = transfers.get(key, {})
            cur_total_sent = round(int(transfer.get('up', 0)) / pow(1024, 3), 4)
            cur_total_receive = round(int(transfer.get('down', 0)) / pow(1024, 3), 4)

            if status == "running":
                if total_sent <= cur_total_sent and total_receive <= cur_total_receive:
                    total_sent = cur_total_sent
                    total_receive = cur_total_receive
                else:
                    cumulative_receive = cumu_receive + total_receive
                    cumulative_sent = cumu_sent + total_sent
                    update_transfer(config_name, key, 0, 0, cumulative_receive, cumulative_sent, end_active, status)

                if end_active:
                    end_active = (ends_at is None or time.time() < int(ends_at)) and (bandwidth == 0 or bandwidth >= total_sent * pow(1024, 3))

                    if not end_active:
                        subprocess.check_output(f"wg set {config_name} peer {key} remove", shell=True, stderr=subprocess.STDOUT)
                        status = "stopped"

                update_transfer(config_name, key, total_receive, total_sent, cumu_receive, cumu_sent, end_active, status)

    return "completed"


def get_endpoint(config_name):
    """
    Get endpoint from all peers of a configuration
    @param config_name: Configuration name
    @return: str
    """
    # Get endpoint
    try:
        data_usage = subprocess.check_output(f"wg show {config_name} endpoints",
                                             shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return "stopped"
    data_usage = data_usage.decode("UTF-8").split()
    count = 0
    for _ in range(int(len(data_usage) / 2)):
        g.cur.execute("UPDATE " + config_name + " SET endpoint = '%s' WHERE id = '%s'"
                      % (data_usage[count + 1], data_usage[count]))
        count += 2


def get_allowed_ip(conf_peer_data, config_name):
    """
    Get allowed ips from all peers of a configuration
    @param conf_peer_data: Configuration peer data
    @param config_name: Configuration name
    @return: None
    """
    # Get allowed ip
    for i in conf_peer_data["Peers"]:
        g.cur.execute("UPDATE " + config_name + " SET allowed_ip = '%s' WHERE id = '%s'"
                      % (i.get('AllowedIPs', '(None)'), i["PublicKey"]))


def get_all_peers_data(config_name):
    """
    Look for new peers from WireGuard
    @param config_name: Configuration name
    @return: None
    """
    conf_peer_data = read_conf_file(config_name)
    config = get_dashboard_conf()
    failed_index = []
    for i in range(len(conf_peer_data['Peers'])):
        if "PublicKey" in conf_peer_data['Peers'][i].keys():
            result = g.cur.execute(
                "SELECT * FROM %s WHERE id='%s'" % (config_name, conf_peer_data['Peers'][i]["PublicKey"])).fetchall()
            if len(result) == 0:
                new_data = {
                    "id": conf_peer_data['Peers'][i]['PublicKey'],
                    "private_key": "",
                    "DNS": config.get("Peers", "peer_global_DNS"),
                    "endpoint_allowed_ip": config.get("Peers", "peer_endpoint_allowed_ip"),
                    "name": "",
                    "total_receive": 0,
                    "total_sent": 0,
                    "total_data": 0,
                    "endpoint": "N/A",
                    "status": "stopped",
                    "latest_handshake": "N/A",
                    "allowed_ip": "N/A",
                    "cumu_receive": 0,
                    "cumu_sent": 0,
                    "cumu_data": 0,
                    "traffic": [],
                    "mtu": config.get("Peers", "peer_mtu"),
                    "keepalive": config.get("Peers", "peer_keep_alive"),
                    "remote_endpoint": config.get("Peers", "remote_endpoint"),
                    "preshared_key": "",
                    "end_active": 1,
                    "ends_at": None,
                    "bandwidth": 0,
                    "timer_on": 0,
                    "created_at": time.time()
                }
                if "PresharedKey" in conf_peer_data['Peers'][i].keys():
                    new_data["preshared_key"] = conf_peer_data['Peers'][i]["PresharedKey"]
                sql = f"""
                INSERT INTO {config_name} 
                    VALUES (:id, :private_key, :DNS, :endpoint_allowed_ip, :name, :total_receive, :total_sent, 
                    :total_data, :endpoint, :status, :latest_handshake, :allowed_ip, :cumu_receive, :cumu_sent, 
                    :cumu_data, :mtu, :keepalive, :remote_endpoint, :preshared_key, :end_active, :ends_at, :bandwidth, :timer_on, :created_at);
                """
                g.cur.execute(sql, new_data)
        else:
            print("Trying to parse a peer doesn't have public key...")
            failed_index.append(i)
    for i in failed_index:
        conf_peer_data['Peers'].pop(i)

    db_key = list(map(lambda a: a[0], g.cur.execute("SELECT id FROM %s" % config_name)))
    wg_key = list(map(lambda a: a['PublicKey'], conf_peer_data['Peers']))
    for i in db_key:
        if i not in wg_key:
            g.cur.execute("UPDATE %s SET end_active=0 WHERE id='%s'" % (config_name, i))

    get_latest_handshake(config_name)
    get_transfer(config_name)
    get_endpoint(config_name)
    get_allowed_ip(conf_peer_data, config_name)


def get_peers(config_name, search="", sort_t="status"):
    """
    Get all peers.
    @param config_name: Name of WG interface
    @type config_name: str
    @param search: Search string
    @type search: str
    @param sort_t: Sorting tag
    @type sort_t: str
    @return: list
    """
    tic = time.perf_counter()
    col = g.cur.execute("PRAGMA table_info(" + config_name + ")").fetchall()
    col = [a[1] for a in col]
    get_all_peers_data(config_name)
    if len(search) == 0:
        data = g.cur.execute("SELECT * FROM " + config_name).fetchall()
        result = [{col[i]: data[k][i] for i in range(len(col))} for k in range(len(data))]
    else:
        sql = "SELECT * FROM " + config_name + " WHERE name LIKE '%" + search + "%'"
        data = g.cur.execute(sql).fetchall()
        result = [{col[i]: data[k][i] for i in range(len(col))} for k in range(len(data))]
    if sort_t == "allowed_ip":
        result = sorted(result, key=lambda d: ipaddress.ip_network(
            "0.0.0.0/0" if d[sort_t].split(",")[0] == "(None)" else d[sort_t].split(",")[0]))
    else:
        result = sorted(result, key=lambda d: d[sort_t])
    toc = time.perf_counter()
    print(f"Finish fetching peers in {toc - tic:0.4f} seconds")

    def cast_data(item):
        ends_at = item.get('ends_at')
        end_active = item.get('end_active')

        if ends_at is not None:
            item['ends_at'] = datetime.fromtimestamp(ends_at).isoformat()
        else:
            item['ends_at'] = None

        if end_active is not None:
            item['end_active'] = bool(end_active)
        else:
            item['end_active'] = False

        return item

    return list(map(cast_data, result))


def get_conf_pub_key(config_name):
    """
    Get public key for configuration.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return public key or empty string
    @rtype: str
    """
    try:
        file_path = os.path.join(WG_CONF_PATH, f"{config_name}.conf")
        with open(file_path, 'r') as f:
            first_char = f.read(1)
            f.seek(0)
            if first_char == '{':
                conf = json.load(f)
                pri = conf["Interface"]["PrivateKey"]
            else:
                conf = configparser.ConfigParser(strict=False)
                conf.read(file_path)
                pri = conf.get("Interface", "PrivateKey")
        pub = subprocess.check_output(f"echo '{pri}' | wg pubkey", shell=True, stderr=subprocess.STDOUT)
        return pub.decode().strip("\n")
    except (json.JSONDecodeError, configparser.NoSectionError, KeyError):
        return ""


def get_conf_listen_port(config_name):
    """
    Get listen port number.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return number of port or empty string
    @rtype: str
    """

    conf = configparser.ConfigParser(strict=False)
    conf.read(WG_CONF_PATH + "/" + config_name + ".conf")
    port = ""
    try:
        port = conf.get("Interface", "ListenPort")
    except (configparser.NoSectionError, configparser.NoOptionError):
        if get_conf_status(config_name) == "running":
            port = subprocess.check_output(f"wg show {config_name} listen-port",
                                           shell=True, stderr=subprocess.STDOUT)
            port = port.decode("UTF-8")
    conf.clear()
    return port


def get_conf_total_data(config_name):
    """
    Get configuration's total amount of data
    @param config_name: Configuration name
    @return: list
    """
    data = g.cur.execute("SELECT total_sent, total_receive, cumu_sent, cumu_receive FROM " + config_name)
    upload_total = 0
    download_total = 0
    for i in data.fetchall():
        upload_total += i[0]
        download_total += i[1]
        upload_total += i[2]
        download_total += i[3]
    total = round(upload_total + download_total, 4)
    upload_total = round(upload_total, 4)
    download_total = round(download_total, 4)
    return [total, upload_total, download_total]


def get_conf_status(config_name):
    """
    Check if the configuration is running or not
    @param config_name:
    @return: Return a string indicate the running status
    """
    ifconfig = dict(ifcfg.interfaces().items())
    return "running" if config_name in ifconfig.keys() else "stopped"


def get_config_names():
    """
    Get the names of all WireGuard configurations.
    @return: List of configuration names
    @rtype: list[str]
    """
    config_files = glob(os.path.join(WG_CONF_PATH, '*.conf'))
    config_names = [Path(file).stem for file in config_files]
    config_names = [name for name in config_names if name not in BLACKLISTED_CONFIGS]
    return config_names


def get_conf_list():
    """
    Get all WireGuard interfaces with status.
    @return: Return a list of dicts with interfaces and their statuses
    @rtype: list
    """
    
    configs = []
    config_names = get_config_names()

    for conf_name in config_names:
        create_table = f"""CREATE TABLE IF NOT EXISTS "{conf_name}" (
            id VARCHAR NOT NULL,
            private_key VARCHAR NULL,
            DNS VARCHAR NULL,
            endpoint_allowed_ip VARCHAR NULL,
            name VARCHAR NULL,
            total_receive FLOAT NULL,
            total_sent FLOAT NULL,
            total_data FLOAT NULL,
            endpoint VARCHAR NULL,
            status VARCHAR NULL,
            latest_handshake VARCHAR NULL,
            allowed_ip VARCHAR NULL,
            cumu_receive FLOAT NULL,
            cumu_sent FLOAT NULL,
            cumu_data FLOAT NULL,
            mtu INT NULL,
            keepalive INT NULL,
            remote_endpoint VARCHAR NULL,
            preshared_key VARCHAR NULL,
            end_active TINYINT(1) DEFAULT 1,
            timer_on TINYINT(1) DEFAULT 0,
            ends_at BIGINT(15) NULL,
            created_at BIGINT(15) NULL,
            bandwidth BIGINT DEFAULT 0,
            PRIMARY KEY (id)
        )"""

        g.cur.execute(create_table)

        status = get_conf_status(conf_name)
        checked = 'checked' if status == "running" else ""

        temp = {
            "conf": conf_name,
            "status": status,
            "public_key": get_conf_pub_key(conf_name),
            "checked": checked
        }

        configs.append(temp)

    if configs:
        configs = sorted(configs, key=itemgetter('conf'))

    return configs


def gen_public_key(private_key):
    """Generate the public key.

    @param private_key: Private key
    @type private_key: str
    @return: Return dict with public key or error message
    @rtype: dict
    """

    with open('private_key.txt', 'w', encoding='utf-8') as file_object:
        file_object.write(private_key)
    try:
        subprocess.check_output("wg pubkey < private_key.txt > public_key.txt", shell=True)
        with open('public_key.txt', encoding='utf-8') as file_object:
            public_key = file_object.readline().strip()
        os.remove('private_key.txt')
        os.remove('public_key.txt')
        return {"status": 'success', "msg": "", "data": public_key}
    except subprocess.CalledProcessError:
        os.remove('private_key.txt')
        return {"status": 'failed', "msg": "تعداد کلید یا قالب آن صحیح نیست.", "data": ""}


def f_check_key_match(private_key, public_key, config_name):
    """
    Check if private key and public key match
    @param private_key: Private key
    @type private_key: str
    @param public_key: Public key
    @type public_key: str
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return dictionary with status
    @rtype: dict
    """

    result = gen_public_key(private_key)
    if result['status'] == 'failed':
        return result
    else:
        sql = "SELECT * FROM " + config_name + " WHERE id = ?"
        match = g.cur.execute(sql, (result['data'],)).fetchall()
        if len(match) != 1 or result['data'] != public_key:
            return {'status': 'failed', 'msg': 'لطفا کلید خصوصی خود را بررسی کنید، با کلید عمومی مطابقت ندارد.'}
        else:
            return {'status': 'success'}


def check_repeat_allowed_ip(public_key, ip, config_name):
    """
    Check if there are repeated IPs
    @param public_key: Public key of the peer
    @param ip: IP of the peer
    @param config_name: configuration name
    @return: a JSON object
    """
    peer = g.cur.execute("SELECT COUNT(*) FROM " + config_name + " WHERE id = ?", (public_key,)).fetchone()
    if peer[0] != 1:
        return {'status': 'failed', 'msg': 'کاربر وجود ندارد.'}
    else:
        existed_ip = g.cur.execute("SELECT COUNT(*) FROM " +
                                   config_name + " WHERE id != ? AND allowed_ip LIKE '" + ip + "/%'", (public_key,)) \
            .fetchone()
        if existed_ip[0] != 0:
            return {'status': 'failed', 'msg': "Allowed IP قبلاً توسط کاربر دیگری استفاده شده است."}
        else:
            return {'status': 'success'}


def f_available_ips(config_name):
    """
    Get a list of available IPs
    @param config_name: Configuration Name
    @return: list
    """
    config_interface = read_conf_file_interface(config_name)
    if "Address" in config_interface:
        existed = []
        conf_address = config_interface['Address']
        address = conf_address.split(',')
        for i in address:
            add, sub = i.split("/")
            existed.append(ipaddress.ip_address(add))
        peers = g.cur.execute("SELECT allowed_ip FROM " + config_name).fetchall()
        for i in peers:
            add = i[0].split(",")
            for k in add:
                a, s = k.split("/")
                existed.append(ipaddress.ip_address(a.strip()))
        available = list(ipaddress.ip_network(address[0], False).hosts())
        for i in existed:
            try:
                available.remove(i)
            except ValueError:
                pass
        available = [str(i) for i in available]
        return available
    else:
        return []


"""
Flask Functions
"""


@app.teardown_request
def close_DB(exception):
    """
    Commit to the database for every request
    @param exception: Exception
    @return: None
    """
    if hasattr(g, 'db'):
        g.db.commit()
        g.db.close()


@app.before_request
def auth_req():
    """
    Action before every request
    @return: Redirect
    """
    if getattr(g, 'db', None) is None:
        g.db = connect_db()
        g.cur = g.db.cursor()
    conf = get_dashboard_conf()
    req = conf.get("Server", "auth_req")
    session['update'] = UPDATE
    session['dashboard_version'] = DASHBOARD_VERSION
    session['admin_ip'] =     request.remote_addr
    
    
    total_ram_kb = get_total_ram()
    if total_ram_kb >= 1024**2:
        total_ram = total_ram_kb / (1024**2)  # Convert to gigabytes
        t_unit = "GB"
    else:
        total_ram = total_ram_kb / 1024  # Convert to megabytes
        t_unit = "MB"
    session['total_ram'] =  f"{total_ram:.2f}{t_unit}"
 
 
    used_ram_kb = get_used_ram()
    if used_ram_kb >= 1024**2:
        used_ram = used_ram_kb / (1024**2)  # Convert to gigabytes
        u_unit = "GB"
    else:
        used_ram = used_ram_kb / 1024  # Convert to megabytes
        u_unit = "MB"
    session['used_ram'] = f"{used_ram:.2f}{u_unit}"
    
    
    cpu_capacity = get_cpu_capacity()
    if cpu_capacity is not None:
        session['cpu_capacity'] = f"{cpu_capacity}"
    else:
        session['cpu_capacity'] = 0
    

    cpu_usage = get_cpu_usage()
    session['cpu_usage'] = f"{cpu_usage:.2f}%"


    session['hard_info'] = get_hard_info()
    
    
    if req == "true":
        if '/static/' not in request.path and \
                request.endpoint != "signin" and \
                request.endpoint != "signout" and \
                request.endpoint != "auth" and \
                "username" not in session:
            print("کاربر وارد نشده است - تلاش برای دسترسی:" + str(request.endpoint))
            if request.endpoint != "index":
                session['message'] = "لطفا ابتدا وارد شوید."
            else:
                session['message'] = ""
            conf.clear()
            redirectURL = str(request.url)
            redirectURL = redirectURL.replace("http://", "")
            redirectURL = redirectURL.replace("https://", "")
            return redirect("/signin?redirect=" + redirectURL)
    else:
        if request.endpoint in ['signin', 'signout', 'auth', 'settings', 'update_acct', 'update_pwd',
                                'update_app_ip_port', 'update_wg_conf_path']:
            conf.clear()
            return redirect(url_for("index"))
    conf.clear()
    return None


"""
Sign In / Sign Out
"""


@app.route('/signin', methods=['GET'])
def signin():
    """
    Sign in request
    @return: template
    """

    message = ""
    if "message" in session:
        message = session['message']
        session.pop("message")
    return render_template('signin.html', message=message, version=DASHBOARD_VERSION)


# Sign Out
@app.route('/signout', methods=['GET'])
def signout():
    """
    Sign out request
    @return: redirect back to sign in
    """
    if "username" in session:
        session.pop("username")
    return redirect(url_for('signin'))


@app.route('/auth', methods=['POST'])
def auth():
    """
    Authentication request
    @return: json object indicating verifying
    """
    data = request.get_json()
    config = get_dashboard_conf()
    password = hashlib.sha256(data['password'].encode())
    if password.hexdigest() == config["Account"]["password"] \
            and data['username'] == config["Account"]["username"]:
        session['username'] = data['username']
        config.clear()
        return jsonify({"status": True, "msg": ""})
    config.clear()
    return jsonify({"status": False, "msg": "نام کاربری یا کلمه عبور اشتباه است."})


"""
Index Page
"""


@app.route('/', methods=['GET'])
def index():
    """
    Index page related
    @return: Template
    """
    msg = ""
    if "switch_msg" in session:
        msg = session["switch_msg"]
        session.pop("switch_msg")

    return render_template('index.html', conf=get_conf_list(), msg=msg)


# Setting Page
@app.route('/settings', methods=['GET'])
def settings():
    """
    Settings page related
    @return: Template
    """
    message = ""
    status = ""
    config = get_dashboard_conf()
    if "message" in session and "message_status" in session:
        message = session['message']
        status = session['message_status']
        session.pop("message")
        session.pop("message_status")
    required_auth = config.get("Server", "auth_req")
    return render_template('settings.html', conf=get_conf_list(), message=message, status=status,
                           app_ip=config.get("Server", "app_ip"), app_port=config.get("Server", "app_port"),
                           required_auth=required_auth, wg_conf_path=config.get("Server", "wg_conf_path"),
                           peer_global_DNS=config.get("Peers", "peer_global_DNS"),
                           peer_endpoint_allowed_ip=config.get("Peers", "peer_endpoint_allowed_ip"),
                           peer_mtu=config.get("Peers", "peer_mtu"),
                           peer_keepalive=config.get("Peers", "peer_keep_alive"),
                           peer_remote_endpoint=config.get("Peers", "remote_endpoint"))


@app.route('/update_acct', methods=['POST'])
def update_acct():
    """
    Change dashboard username
    @return: Redirect
    """

    if len(request.form['username']) == 0:
        session['message'] = "نام کاربری نمی تواند خالی باشد."
        session['message_status'] = "danger"
        return redirect(url_for("settings"))
    config = get_dashboard_conf()
    config.set("Account", "username", request.form['username'])
    try:
        set_dashboard_conf(config)
        config.clear()
        session['message'] = "نام کاربری با موفقیت به روز شد!"
        session['message_status'] = "success"
        session['username'] = request.form['username']
        return redirect(url_for("settings"))
    except Exception:
        session['message'] = "به روز رسانی نام کاربری ناموفق بود."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))


# Update peer default setting
@app.route('/update_peer_default_config', methods=['POST'])
def update_peer_default_config():
    """
    Update new peers default setting
    @return: None
    """

    config = get_dashboard_conf()
    if len(request.form['peer_endpoint_allowed_ip']) == 0 or \
            len(request.form['peer_global_DNS']) == 0 or \
            len(request.form['peer_remote_endpoint']) == 0:
        session['message'] = "لطفا فیلدهای الزامی را تکمیل نمایید"
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    # Check DNS Format
    dns_addresses = request.form['peer_global_DNS']
    if not check_DNS(dns_addresses):
        session['message'] = "فرمت DNS تنظیمات نادرست است."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    dns_addresses = dns_addresses.replace(" ", "").split(',')
    dns_addresses = ",".join(dns_addresses)
    # Check Endpoint Allowed IPs
    ip = request.form['peer_endpoint_allowed_ip']
    if not check_Allowed_IPs(ip):
        session['message'] = "فرمت Endpoint Allowed IPs نادرست است." \
                             "مثال: 192.168.1.1/32 or 192.168.1.1/32,192.168.1.2/32"
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    # Check MTU Format
    if not len(request.form['peer_mtu']) > 0 or not request.form['peer_mtu'].isdigit():
        session['message'] = "فرمت MTU نادرست است."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    # Check keepalive Format
    if not len(request.form['peer_keep_alive']) > 0 or not request.form['peer_keep_alive'].isdigit():
        session['message'] = "فرمت Persistent keepalive نادرست است."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    # Check peer remote endpoint
    if not check_remote_endpoint(request.form['peer_remote_endpoint']):
        session['message'] = "فرمت Peer Remote Endpoint نادرست است. " \
                             "آدرس IP یا دامنه معتبر (بدون http:// یا https://)."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    config.set("Peers", "remote_endpoint", request.form['peer_remote_endpoint'])
    config.set("Peers", "peer_keep_alive", request.form['peer_keep_alive'])
    config.set("Peers", "peer_mtu", request.form['peer_mtu'])
    config.set("Peers", "peer_endpoint_allowed_ip", ','.join(clean_IP_with_range(ip)))
    config.set("Peers", "peer_global_DNS", dns_addresses)
    try:
        set_dashboard_conf(config)
        session['message'] = "تنظیمات پیش فرض با موفقیت به‌روزرسانی شد!"
        session['message_status'] = "success"
        config.clear()
        return redirect(url_for("settings"))
    except Exception:
        session['message'] = "بروزرسانی تنظیمات پیش فرض ناموفق بود."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))


# Update dashboard password
@app.route('/update_pwd', methods=['POST'])
def update_pwd():
    """
    Update dashboard password
    @return: Redirect
    """

    config = get_dashboard_conf()
    if hashlib.sha256(request.form['currentpass'].encode()).hexdigest() == config.get("Account", "password"):
        if hashlib.sha256(request.form['newpass'].encode()).hexdigest() == hashlib.sha256(
                request.form['repnewpass'].encode()).hexdigest():
            config.set("Account", "password", hashlib.sha256(request.form['repnewpass'].encode()).hexdigest())
            try:
                set_dashboard_conf(config)
                session['message'] = "رمز عبور با موفقیت به روز شد!"
                session['message_status'] = "success"
                config.clear()
                return redirect(url_for("settings"))
            except Exception:
                session['message'] = "به روز رسانی رمز عبور ناموفق بود"
                session['message_status'] = "danger"
                config.clear()
                return redirect(url_for("settings"))
        else:
            session['message'] = "رمز عبور جدید شما مطابقت ندارد."
            session['message_status'] = "danger"
            config.clear()
            return redirect(url_for("settings"))
    else:
        session['message'] = "رمز عبور فعلی شما مطابقت ندارد."
        session['message_status'] = "danger"
        config.clear()
        return redirect(url_for("settings"))


@app.route('/update_app_ip_port', methods=['POST'])
def update_app_ip_port():
    """
    Update dashboard ip and port
    @return: None
    """

    config = get_dashboard_conf()
    config.set("Server", "app_ip", request.form['app_ip'])
    config.set("Server", "app_port", request.form['app_port'])
    set_dashboard_conf(config)
    config.clear()
    subprocess.Popen('bash wgd.sh restart', shell=True)
    return ""


# Update WireGuard configuration file path
@app.route('/update_wg_conf_path', methods=['POST'])
def update_wg_conf_path():
    """
    Update configuration path
    @return: None
    """

    config = get_dashboard_conf()
    config.set("Server", "wg_conf_path", request.form['wg_conf_path'])
    set_dashboard_conf(config)
    config.clear()
    session['message'] = "به روز رسانی مسیر پیکربندی وایرگارد با موفقیت انجام شد!"
    session['message_status'] = "success"
    subprocess.Popen('bash wgd.sh restart', shell=True)


@app.route('/update_dashboard_sort', methods=['POST'])
def update_dashbaord_sort():
    """
    Update configuration sorting
    @return: Boolean
    """

    config = get_dashboard_conf()
    data = request.get_json()
    sort_tag = ['name', 'status', 'allowed_ip']
    if data['sort'] in sort_tag:
        config.set("Server", "dashboard_sort", data['sort'])
    else:
        config.set("Server", "dashboard_sort", 'status')
    set_dashboard_conf(config)
    config.clear()
    return "true"


# Update configuration refresh interval
@app.route('/update_dashboard_refresh_interval', methods=['POST'])
def update_dashboard_refresh_interval():
    """
    Change the refresh time.
    @return: Return text with result
    @rtype: str
    """

    preset_interval = ["5000", "10000", "30000", "60000"]
    if request.form["interval"] in preset_interval:
        config = get_dashboard_conf()
        config.set("Server", "dashboard_refresh_interval", str(request.form['interval']))
        set_dashboard_conf(config)
        config.clear()
        return "true"
    else:
        return "false"


# Configuration Page
@app.route('/configuration/<config_name>', methods=['GET'])
def configuration(config_name):
    """
    Show wireguard interface view.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Template
    """

    config = get_dashboard_conf()
    conf_data = {
        "name": config_name,
        "status": get_conf_status(config_name),
        "checked": ""
    }
    if conf_data['status'] == "stopped":
        conf_data['checked'] = "nope"
    else:
        conf_data['checked'] = "checked"
    config_list = get_conf_list()
    if config_name not in [conf['conf'] for conf in config_list]:
        return render_template('index.html', conf=get_conf_list())

    refresh_interval = int(config.get("Server", "dashboard_refresh_interval"))
    dns_address = config.get("Peers", "peer_global_DNS")
    allowed_ip = config.get("Peers", "peer_endpoint_allowed_ip")
    peer_mtu = config.get("Peers", "peer_MTU")
    peer_keep_alive = config.get("Peers", "peer_keep_alive")
    config.clear()
    return render_template('configuration.html', conf=get_conf_list(), conf_data=conf_data,
                           dashboard_refresh_interval=refresh_interval,
                           DNS=dns_address,
                           endpoint_allowed_ip=allowed_ip,
                           title=config_name,
                           mtu=peer_mtu,
                           keep_alive=peer_keep_alive)


# Get configuration details
@app.route('/get_config/<config_name>', methods=['GET'])
def get_conf(config_name):
    """
    Get configuration setting of wireguard interface.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: TODO
    """

    config_interface = read_conf_file_interface(config_name)
    search = request.args.get('search')
    if len(search) == 0:
        search = ""
    search = urllib.parse.unquote(search)
    config = get_dashboard_conf()
    sort = config.get("Server", "dashboard_sort")
    peer_display_mode = config.get("Peers", "peer_display_mode")
    wg_ip = config.get("Peers", "remote_endpoint")
    if "Address" not in config_interface:
        conf_address = "N/A"
    else:
        conf_address = config_interface['Address']
    conf_data = {
        "peer_data": get_peers(config_name, search, sort),
        "name": config_name,
        "status": get_conf_status(config_name),
        "total_data_usage": get_conf_total_data(config_name),
        "public_key": get_conf_pub_key(config_name),
        "listen_port": get_conf_listen_port(config_name),
        "running_peer": get_conf_running_peer_number(config_name),
        "conf_address": conf_address,
        "wg_ip": wg_ip,
        "sort_tag": sort,
        "dashboard_refresh_interval": int(config.get("Server", "dashboard_refresh_interval")),
        "peer_display_mode": peer_display_mode
    }
    if conf_data['status'] == "stopped":
        conf_data['checked'] = "nope"
    else:
        conf_data['checked'] = "checked"
    config.clear()
    return jsonify(conf_data)


# Turn on / off a configuration
@app.route('/switch/<config_name>', methods=['GET'])
def switch(config_name):
    """
    On/off the wireguard interface.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: redirects
    """

    status = get_conf_status(config_name)
    if status == "running":
        try:
            check = subprocess.check_output("wg-quick down " + config_name,
                                            shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            session["switch_msg"] = exc.output.strip().decode("utf-8")
            return redirect('/')
    elif status == "stopped":
        try:
            subprocess.check_output("wg-quick up " + config_name,
                                    shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            session["switch_msg"] = exc.output.strip().decode("utf-8")
            return redirect('/')
    return redirect(request.referrer)


@app.route('/add_peer_bulk/<config_name>', methods=['POST'])
def add_peer_bulk(config_name):
    """
    Add peers by bulk
    @param config_name: Configuration Name
    @return: String
    """
    data = request.get_json()
    keys = data['keys']
    endpoint_allowed_ip = data['endpoint_allowed_ip']
    dns_addresses = data['DNS']
    enable_preshared_key = data["enable_preshared_key"]
    amount = data['amount']
    config_interface = read_conf_file_interface(config_name)
    
    if "Address" not in config_interface:
        return "Configuration must have an IP address."
    
    if not amount.isdigit() or int(amount) < 1:
        return "Amount must be an integer larger than 0."
    
    amount = int(amount)
    
    if not check_DNS(dns_addresses):
        return "DNS format is incorrect. Example: 1.1.1.1"
    
    if not check_Allowed_IPs(endpoint_allowed_ip):
        return "Endpoint Allowed IPs format is incorrect."
    
    if len(data['MTU']) == 0 or not data['MTU'].isdigit():
        return "MTU format is not correct."
    
    if len(data['keep_alive']) == 0 or not data['keep_alive'].isdigit():
        return "Persistent Keepalive format is not correct."
    
    ips = f_available_ips(config_name)
    num_available_ips = len(ips)
    
    if amount > num_available_ips:
        return f"Cannot create more than {num_available_ips} peers."
    
    wg_command = ["wg", "set", config_name]
    sql_commands = []
    
    for i in range(amount):
        if not ips: 
            break
        
        keys[i]['name'] = f"{config_name}_{datetime.now().strftime('%m%d%Y%H%M%S')}_Peer_#_{(i + 1)}"
        keys[i]['allowed_ips'] = ips.pop(0)
        
        if enable_preshared_key:
            keys[i]['psk_file'] = f"{keys[i]['name']}.txt"
            
            with open(keys[i]['psk_file'], "w") as f:
                f.write(keys[i]['presharedKey'])
            
            wg_command.extend(["peer", keys[i]['publicKey'], "preshared-key", keys[i]['psk_file']])
        else:
            keys[i]['psk_file'] = ""
            wg_command.extend(["peer", keys[i]['publicKey']])
        
        wg_command.extend(["allowed-ips", keys[i]['allowed_ips']])
        
        update = f"UPDATE {config_name} SET name = '{keys[i]['name']}', private_key = '{keys[i]['privateKey']}', " \
                 f"DNS = '{dns_addresses}', created_at = {time.time()}, " \
                 f"endpoint_allowed_ip = '{endpoint_allowed_ip}' WHERE id = '{keys[i]['publicKey']}'"
        
        sql_commands.append(update)
    
    try:
        subprocess.check_output(" ".join(wg_command), shell=True, stderr=subprocess.STDOUT)
        subprocess.check_output("wg-quick save " + config_name, shell=True, stderr=subprocess.STDOUT)
        get_all_peers_data(config_name)
        
        if enable_preshared_key:
            for i in keys:
                os.remove(i['psk_file'])
        
        for command in sql_commands:
            g.cur.execute(command)
        
        return "true"
    
    except subprocess.CalledProcessError as exc:
        return exc.output.strip()

@app.route('/add_peer/<config_name>', methods=['POST'])
def add_peer(config_name):
    """
    Add Peers
    @param config_name: configuration name
    @return: string
    """
    data = request.get_json()
    public_key = data['public_key']
    allowed_ips = data['allowed_ips']
    endpoint_allowed_ip = data['endpoint_allowed_ip']
    dns_addresses = data['DNS']
    enable_preshared_key = data["enable_preshared_key"]
    preshared_key = data['preshared_key']

    ends_at = data.get('ends_at')
    if ends_at is None:
        ends_at = None
    bandwidth = float(data['bandwidth']) * pow(1024, 3) if 'bandwidth' in data else 0
    keys = get_conf_peer_key(config_name)
    if len(public_key) == 0 or len(dns_addresses) == 0 or len(allowed_ips) == 0 or len(endpoint_allowed_ip) == 0:
        return "لطفا فیلدهای الزامی را تکمیل نمایید."
    if not isinstance(keys, list):
        return config_name + " در حال اجرا نیست. آن را فعال کنید."
    if public_key in keys:
        return "کلید عمومی از قبل وجود دارد."
    check_dup_ip = g.cur.execute(
        "SELECT COUNT(*) FROM " + config_name + " WHERE allowed_ip LIKE '" + allowed_ips + "/%'", ) \
        .fetchone()
    if check_dup_ip[0] != 0:
        return "Allowed IPs قبلاً توسط کاربر دیگری استفاده شده است."
    if not check_DNS(dns_addresses):
        return "فرمت DNS نادرست است. مثال: 1.1.1.1"
    if not check_Allowed_IPs(endpoint_allowed_ip):
        return "فرمت Endpoint Allowed IPs نادرست است."
    if len(data['MTU']) == 0 or not data['MTU'].isdigit():
        return "فرمت MTU درست نیست."
    if len(data['keep_alive']) == 0 or not data['keep_alive'].isdigit():
        return "فرمت Persistent Keepalive درست نیست."
    try:
        if enable_preshared_key:
            now = str(datetime.now().strftime("%m%d%Y%H%M%S"))
            f_name = now + "_tmp_psk.txt"
            f = open(f_name, "w+")
            f.write(preshared_key)
            f.close()
            status = subprocess.check_output(
                f"wg set {config_name} peer {public_key} allowed-ips {allowed_ips} preshared-key {f_name}",
                shell=True, stderr=subprocess.STDOUT)
            os.remove(f_name)
        elif not enable_preshared_key:
            status = subprocess.check_output(f"wg set {config_name} peer {public_key} allowed-ips {allowed_ips}",
                                             shell=True, stderr=subprocess.STDOUT)
        status = subprocess.check_output("wg-quick save " + config_name, shell=True, stderr=subprocess.STDOUT)
        get_all_peers_data(config_name)
        sql = "UPDATE " + config_name + " SET name = ?, private_key = ?, DNS = ?, endpoint_allowed_ip = ?, bandwidth = ?, ends_at = ?, timer_on = ?, created_at = ? WHERE id = ?"
        g.cur.execute(sql, (
            data['name'], data['private_key'], data['DNS'], endpoint_allowed_ip, bandwidth, ends_at, 0, time.time(),
            public_key))
        return "true"
    except subprocess.CalledProcessError as exc:
        return exc.output.strip()


@app.route('/remove_peer/<config_name>', methods=['POST'])
def remove_peer(config_name):
    """
    Remove peer.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return result of action or recommendations
    @rtype: str
    """

    if get_conf_status(config_name) == "stopped":
        return "Your need to turn on " + config_name + " first."

    data = request.get_json()
    delete_keys = data['peer_ids']
    keys = get_conf_peer_key(config_name)

    if not isinstance(keys, list):
        return config_name + " در حال اجرا نیست. آن را فعال کنید."

    sql_command = []
    wg_command = ["wg", "set", config_name]

    for delete_key in delete_keys:
        sql_command.append("DELETE FROM " + config_name + " WHERE id = '" + delete_key + "';")
        wg_command.append("peer")
        wg_command.append(delete_key)
        wg_command.append("remove")

    try:
        remove_wg = subprocess.check_output(" ".join(wg_command), shell=True, stderr=subprocess.STDOUT)
        save_wg = subprocess.check_output(f"wg-quick save {config_name}", shell=True, stderr=subprocess.STDOUT)
        g.cur.executescript(' '.join(sql_command))
        g.db.commit()
    except subprocess.CalledProcessError as exc:
        return exc.output.strip()

    return "true"


@app.route('/save_peer_setting/<config_name>', methods=['POST'])
def save_peer_setting(config_name):
    """
    Save peer configuration.

    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return status of action and text with recommendations
    """

    data = request.get_json()
    id = data['id']
    name = data['name']
    bandwidth = float(data['bandwidth']) * pow(1024, 3)
    now = time.time()
    ends_at = data['ends_at'] or None

    private_key = data['private_key']
    dns_addresses = data['DNS']
    allowed_ip = data['allowed_ip']
    endpoint_allowed_ip = data['endpoint_allowed_ip']
    preshared_key = data['preshared_key']
    peer = g.cur.execute(
        "SELECT id, end_active, total_receive, total_sent, total_data FROM " + config_name + " WHERE id = ?",
        (id,)).fetchone()
    if peer:
        (id, end_active, total_receive, total_sent, total_data) = peer

        end_active = (ends_at is None or int(ends_at) > now) and (
                bandwidth == 0 or bandwidth >= float(total_data) * pow(1024, 3))

        check_ip = check_repeat_allowed_ip(id, allowed_ip, config_name)
        if not check_IP_with_range(endpoint_allowed_ip):
            return jsonify({"status": "failed", "msg": "فرمت Endpoint Allowed IPs نادرست است."})
        if not check_DNS(dns_addresses):
            return jsonify({"status": "failed", "msg": "فرمت DNS نادرست است. مثلا: 1.1.1.1"})
        if len(data['MTU']) == 0 or not data['MTU'].isdigit():
            return jsonify({"status": "failed", "msg": "فرمت MTU نادرست است."})
        if len(data['keep_alive']) == 0 or not data['keep_alive'].isdigit():
            return jsonify({"status": "failed", "msg": "فرمت Persistent Keepalive نادرست است."})
        if private_key != "":
            check_key = f_check_key_match(private_key, id, config_name)
            if check_key['status'] == "failed":
                return jsonify(check_key)
        if check_ip['status'] == "failed":
            return jsonify(check_ip)
        try:
            if end_active:
                tmp_file = 'tmp_edit_psk.txt'
                tmp_psk = open(tmp_file, "w+")
                tmp_psk.write(preshared_key)
                tmp_psk.close()

                wg_cmd = ['wg', 'set', config_name, 'peer', id, 'preshared-key', tmp_file]

                change_psk = subprocess.check_output(f"wg set {config_name} peer {id} preshared-key tmp_edit_psk.txt",
                                                     shell=True, stderr=subprocess.STDOUT)
                if change_psk.decode("UTF-8") != "":
                    return jsonify({"status": "failed", "msg": change_psk.decode("UTF-8")})

                if allowed_ip == "":
                    allowed_ip = '""'

                allowed_ip = allowed_ip.replace(" ", "")
                wg_cmd.append('allowed-ips')
                wg_cmd.append(allowed_ip)
                output = subprocess.check_output(" ".join(wg_cmd), shell=True, stderr=subprocess.STDOUT)

                if output.decode("UTF-8") != "":
                    return jsonify({"status": "failed", "msg": output.decode("UTF-8")})
            else:
                output = subprocess.check_output(f"wg set {config_name} peer {id} remove", shell=True,
                                                 stderr=subprocess.STDOUT).decode('UTF-8')

                if output:
                    return jsonify({"status": "failed", "msg": output})

            subprocess.check_output(f'wg-quick save {config_name}', shell=True, stderr=subprocess.STDOUT)

            sql = "UPDATE " + config_name + " SET name = ?, bandwidth = ?, private_key = ?, DNS = ?, endpoint_allowed_ip = ?, mtu = ?, keepalive = ?, preshared_key = ?, end_active = ?, ends_at = ? WHERE id = ?"

            g.cur.execute(sql, (name, bandwidth, private_key, dns_addresses, endpoint_allowed_ip, data["MTU"],
                                data["keep_alive"], preshared_key, int(end_active),
                                ends_at, id))

            return jsonify({"status": "success", "msg": ""})
        except subprocess.CalledProcessError as exc:
            return jsonify({"status": "failed", "msg": str(exc.output.decode("UTF-8").strip())})
    else:
        return jsonify({"status": "failed", "msg": "این کاربر وجود ندارد."})


# Get peer settings
@app.route('/get_peer_data/<config_name>', methods=['POST'])
def get_peer_name(config_name):
    """
    Get peer settings.

    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return settings of peer
    """

    data = request.get_json()
    peer_id = data['id']
    result = g.cur.execute(
        "SELECT name, allowed_ip, DNS, private_key, endpoint_allowed_ip, mtu, keepalive, preshared_key, bandwidth, ends_at, end_active FROM "
        + config_name + " WHERE id = ?", (peer_id,)).fetchall()
    data = {"name": result[0][0], "bandwidth": result[0][8], "end_active": bool(result[0][10]), "allowed_ip": result[0][1],
            "DNS": result[0][2],
            "private_key": result[0][3], "endpoint_allowed_ip": result[0][4],
            "mtu": result[0][5], "keep_alive": result[0][6], "preshared_key": result[0][7],
            "ends_at": datetime.fromtimestamp(result[0][9]).astimezone(pytz.timezone('Asia/Tehran')).isoformat() if
            result[0][9] else None}
    return jsonify(data)


# Return available IPs
@app.route('/available_ips/<config_name>', methods=['GET'])
def available_ips(config_name):
    return jsonify(f_available_ips(config_name))


# Check if both key match
@app.route('/check_key_match/<config_name>', methods=['POST'])
def check_key_match(config_name):
    """
    Check key matches
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return dictionary with status
    """

    data = request.get_json()
    private_key = data['private_key']
    public_key = data['public_key']
    return jsonify(f_check_key_match(private_key, public_key, config_name))


@app.route("/qrcode/<config_name>", methods=['GET'])
def generate_qrcode(config_name):
    """
    Generate QRCode
    @param config_name: Configuration Name
    @return: Template containing QRcode img
    """
    peer_id = request.args.get('id')
    get_peer = g.cur.execute(
        "SELECT private_key, allowed_ip, DNS, mtu, endpoint_allowed_ip, keepalive, preshared_key FROM "
        + config_name + " WHERE id = ?", (peer_id,)).fetchall()
    config = get_dashboard_conf()
    if len(get_peer) == 1:
        peer = get_peer[0]
        if peer[0] != "":
            public_key = get_conf_pub_key(config_name)
            listen_port = get_conf_listen_port(config_name)
            endpoint = config.get("Peers", "remote_endpoint") + ":" + listen_port
            private_key = peer[0]
            allowed_ip = peer[1]
            dns_addresses = peer[2]
            mtu_value = peer[3]
            endpoint_allowed_ip = peer[4]
            keepalive = peer[5]
            preshared_key = peer[6]

            result = "[Interface]\nPrivateKey = " + private_key + "\nAddress = " + allowed_ip + "\nMTU = " \
                     + str(mtu_value) + "\nDNS = " + dns_addresses + "\n\n[Peer]\nPublicKey = " + public_key \
                     + "\nAllowedIPs = " + endpoint_allowed_ip + "\nPersistentKeepalive = " \
                     + str(keepalive) + "\nEndpoint = " + endpoint
            if preshared_key != "":
                result += "\nPresharedKey = " + preshared_key
            return render_template("qrcode.html", i=result)
    else:
        return redirect("/configuration/" + config_name)


@app.route('/download_all/<config_name>', methods=['GET'])
def download_all(config_name):
    """
    Download all configuration
    @param config_name: Configuration Name
    @return: JSON Object
    """
    get_peer = g.cur.execute(
        "SELECT private_key, allowed_ip, DNS, mtu, endpoint_allowed_ip, keepalive, preshared_key, name FROM "
        + config_name + " WHERE private_key != ''").fetchall()
    config = get_dashboard_conf()
    data = []
    public_key = get_conf_pub_key(config_name)
    listen_port = get_conf_listen_port(config_name)
    endpoint = config.get("Peers", "remote_endpoint") + ":" + listen_port
    for peer in get_peer:
        private_key = peer[0]
        allowed_ip = peer[1]
        dns_addresses = peer[2]
        mtu_value = peer[3]
        endpoint_allowed_ip = peer[4]
        keepalive = peer[5]
        preshared_key = peer[6]
        filename = peer[7]
        if len(filename) == 0:
            filename = "Untitled_Peer"
        else:
            filename = peer[7]
            # Clean filename
            illegal_filename = [".", ",", "/", "?", "<", ">", "\\", ":", "*", '|' '\"', "com1", "com2", "com3",
                                "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4",
                                "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "con", "nul", "prn"]
            for i in illegal_filename:
                filename = filename.replace(i, "")
            if len(filename) == 0:
                filename = "Untitled_Peer"
            filename = "".join(filename.split(' '))
        filename = filename + "_" + config_name
        psk = ""
        if preshared_key != "":
            psk = "\nPresharedKey = " + preshared_key

        return_data = "[Interface]\nPrivateKey = " + private_key + "\nAddress = " + allowed_ip + "\nDNS = " + \
                      dns_addresses + "\nMTU = " + str(mtu_value) + "\n\n[Peer]\nPublicKey = " + \
                      public_key + "\nAllowedIPs = " + endpoint_allowed_ip + "\nEndpoint = " + \
                      endpoint + "\nPersistentKeepalive = " + str(keepalive) + psk
        data.append({"filename": f"{filename}.conf", "content": return_data})
    return jsonify({"status": True, "peers": data, "filename": f"{config_name}.zip"})


# Download configuration file
@app.route('/download/<config_name>', methods=['GET'])
def download(config_name):
    """
    Download one configuration
    @param config_name: Configuration name
    @return: JSON object
    """
    peer_id = request.args.get('id')
    get_peer = g.cur.execute(
        "SELECT private_key, allowed_ip, DNS, mtu, endpoint_allowed_ip, keepalive, preshared_key, name FROM "
        + config_name + " WHERE id = ?", (peer_id,)).fetchall()
    config = get_dashboard_conf()
    if len(get_peer) == 1:
        peer = get_peer[0]
        if peer[0] != "":
            public_key = get_conf_pub_key(config_name)
            listen_port = get_conf_listen_port(config_name)
            endpoint = config.get("Peers", "remote_endpoint") + ":" + listen_port
            private_key = peer[0]
            allowed_ip = peer[1]
            dns_addresses = peer[2]
            mtu_value = peer[3]
            endpoint_allowed_ip = peer[4]
            keepalive = peer[5]
            preshared_key = peer[6]
            filename = peer[7]
            if len(filename) == 0:
                filename = "Untitled_Peer"
            else:
                filename = peer[7]
                # Clean filename
                illegal_filename = [".", ",", "/", "?", "<", ">", "\\", ":", "*", '|' '\"', "com1", "com2", "com3",
                                    "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4",
                                    "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "con", "nul", "prn"]
                for i in illegal_filename:
                    filename = filename.replace(i, "")
                if len(filename) == 0:
                    filename = "Untitled_Peer"
                filename = "".join(filename.split(' '))
            filename = filename + "_" + config_name
            psk = ""
            if preshared_key != "":
                psk = "\nPresharedKey = " + preshared_key

            return_data = "[Interface]\nPrivateKey = " + private_key + "\nAddress = " + allowed_ip + "\nDNS = " + \
                          dns_addresses + "\nMTU = " + str(mtu_value) + "\n\n[Peer]\nPublicKey = " + \
                          public_key + "\nAllowedIPs = " + endpoint_allowed_ip + "\nEndpoint = " + \
                          endpoint + "\nPersistentKeepalive = " + str(keepalive) + psk

            return jsonify({"status": True, "filename": f"{filename}.conf", "content": return_data})
    return jsonify({"status": False, "filename": "", "content": ""})


@app.route('/switch_display_mode/<mode>', methods=['GET'])
def switch_display_mode(mode):
    """
    Change display view style.

    @param mode: Mode name
    @type mode: str
    @return: Return text with result
    @rtype: str
    """

    if mode in ['list', 'grid']:
        config = get_dashboard_conf()
        config.set("Peers", "peer_display_mode", mode)
        set_dashboard_conf(config)
        config.clear()
        return "true"
    return "false"


"""
Dashboard Tools Related
"""


# Get all IP for ping
@app.route('/get_ping_ip', methods=['POST'])
def get_ping_ip():
    # TODO: convert return to json object

    """
    Get ips for network testing.
    @return: HTML containing a list of IPs
    """

    config = request.form['config']
    peers = g.cur.execute("SELECT id, name, allowed_ip, endpoint FROM " + config).fetchall()
    html = ""
    for i in peers:
        html += '<optgroup label="' + i[1] + ' - ' + i[0] + '">'
        allowed_ip = str(i[2]).split(",")
        for k in allowed_ip:
            k = k.split("/")
            if len(k) == 2:
                html += "<option value=" + k[0] + ">" + k[0] + "</option>"
        endpoint = str(i[3]).split(":")
        if len(endpoint) == 2:
            html += "<option value=" + endpoint[0] + ">" + endpoint[0] + "</option>"
        html += "</optgroup>"
    return html


# Ping IP
@app.route('/ping_ip', methods=['POST'])
def ping_ip():
    """
    Execute ping command.
    @return: Return text with result
    @rtype: str
    """

    try:
        result = ping('' + request.form['ip'] + '', count=int(request.form['count']), privileged=True, source=None)
        returnjson = {
            "address": result.address,
            "is_alive": result.is_alive,
            "min_rtt": result.min_rtt,
            "avg_rtt": result.avg_rtt,
            "max_rtt": result.max_rtt,
            "package_sent": result.packets_sent,
            "package_received": result.packets_received,
            "package_loss": result.packet_loss
        }
        if returnjson['package_loss'] == 1.0:
            returnjson['package_loss'] = returnjson['package_sent']
        return jsonify(returnjson)
    except Exception:
        return "Error"


# Traceroute IP
@app.route('/traceroute_ip', methods=['POST'])
def traceroute_ip():
    """
    Execute ping traceroute command.

    @return: Return text with result
    @rtype: str
    """

    try:
        result = traceroute('' + request.form['ip'] + '', first_hop=1, max_hops=30, count=1, fast=True)
        returnjson = []
        last_distance = 0
        for hop in result:
            if last_distance + 1 != hop.distance:
                returnjson.append({"hop": "*", "ip": "*", "avg_rtt": "", "min_rtt": "", "max_rtt": ""})
            returnjson.append({"hop": hop.distance, "ip": hop.address, "avg_rtt": hop.avg_rtt, "min_rtt": hop.min_rtt,
                               "max_rtt": hop.max_rtt})
            last_distance = hop.distance
        return jsonify(returnjson)
    except Exception:
        return "Error"


@app.route('/backup', methods=['GET'])
def backup():
    files_to_zip = [os.path.abspath(i) for i in [
        DB_FILE_PATH, DASHBOARD_CONF
    ]]

    conf_files_path = WG_CONF_PATH
    conf_files_to_zip = [os.path.join(conf_files_path, f) for f in os.listdir(conf_files_path) if f.endswith('.conf')]
    files_to_zip.extend(conf_files_to_zip)

    now = datetime.now()
    zip_file_name = now.strftime("%Y-%m-%d%H%M%S") + '.zip'

    with zipfile.ZipFile(zip_file_name, 'w') as myzip:
        for file in files_to_zip:
            myzip.write(file)

    response = send_file(zip_file_name, as_attachment=True)

    os.remove(zip_file_name)

    return response


"""
Dashboard Initialization
"""


def init_dashboard():
    """
    Create dashboard default configuration.
    """

    # Set Default INI File
    if not os.path.isfile(DASHBOARD_CONF):
        open(DASHBOARD_CONF, "w+").close()
    config = get_dashboard_conf()
    # Default dashboard account setting
    if "Account" not in config:
        config['Account'] = {}
    if "username" not in config['Account']:
        config['Account']['username'] = 'admin'
    if "password" not in config['Account']:
        config['Account']['password'] = '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'
    # Default dashboard server setting
    if "Server" not in config:
        config['Server'] = {}
    if 'wg_conf_path' not in config['Server']:
        config['Server']['wg_conf_path'] = '/etc/wireguard'
    if 'app_ip' not in config['Server']:
        config['Server']['app_ip'] = '0.0.0.0'
    if 'app_port' not in config['Server']:
        config['Server']['app_port'] = '10086'
    if 'auth_req' not in config['Server']:
        config['Server']['auth_req'] = 'true'
    if 'version' not in config['Server'] or config['Server']['version'] != DASHBOARD_VERSION:
        config['Server']['version'] = DASHBOARD_VERSION
    if 'dashboard_refresh_interval' not in config['Server']:
        config['Server']['dashboard_refresh_interval'] = '60000'
    if 'dashboard_sort' not in config['Server']:
        config['Server']['dashboard_sort'] = 'status'
    # Default dashboard peers setting
    if "Peers" not in config:
        config['Peers'] = {}
    if 'peer_global_DNS' not in config['Peers']:
        config['Peers']['peer_global_DNS'] = '1.1.1.1'
    if 'peer_endpoint_allowed_ip' not in config['Peers']:
        config['Peers']['peer_endpoint_allowed_ip'] = '0.0.0.0/0'
    if 'peer_display_mode' not in config['Peers']:
        config['Peers']['peer_display_mode'] = 'grid'
    if 'remote_endpoint' not in config['Peers']:
        config['Peers']['remote_endpoint'] = ifcfg.default_interface()['inet']
    if 'peer_MTU' not in config['Peers']:
        config['Peers']['peer_MTU'] = "1420"
    if 'peer_keep_alive' not in config['Peers']:
        config['Peers']['peer_keep_alive'] = "21"
    set_dashboard_conf(config)
    config.clear()


def check_update():
    """
    Dashboard check update

    @return: Return text with result
    @rtype: str
    """
    config = get_dashboard_conf()
    try:
        data = urllib.request.urlopen("https://api.github.com/repos/Azumi67/Wireguard/releases").read()
        output = json.loads(data)
        release = [i for i in output if not i["prerelease"]]

        if release:
            latest_release = release[0]["tag_name"]
            if config.get("Server", "version") == latest_release:
                result = "false"
            else:
                result = "true"
        else:
            result = "false"  # No non-prerelease releases found

        return result
    except urllib.error.HTTPError:
        return "false"

"""
Configure DashBoard before start web-server
"""


def run_dashboard():
    init_dashboard()
    global UPDATE
    UPDATE = check_update()
    config = configparser.ConfigParser(strict=False)
    config.read('wg-dashboard.ini')
    # global app_ip
    app_ip = config.get("Server", "app_ip")
    # global app_port
    app_port = config.get("Server", "app_port")
    global WG_CONF_PATH
    WG_CONF_PATH = config.get("Server", "wg_conf_path")
    config.clear()
    return app


"""
Get host and port for web-server
"""


def get_host_bind():
    init_dashboard()
    config = configparser.ConfigParser(strict=False)
    config.read('wg-dashboard.ini')
    app_ip = config.get("Server", "app_ip")
    app_port = config.get("Server", "app_port")
    return app_ip, app_port


if __name__ == "__main__":
    from apscheduler.schedulers.background import BackgroundScheduler


    def test():
        with app.app_context():
            if getattr(g, 'db', None) is None:
                g.db = connect_db()
                g.cur = g.db.cursor()

            for name in get_config_names():
                get_latest_handshake(name)
                get_transfer(name)


    scheduler = BackgroundScheduler()
    scheduler.add_job(test, seconds=10, trigger='interval')
    scheduler.start()

    init_dashboard()
    UPDATE = check_update()
    config = configparser.ConfigParser(strict=False)
    config.read('wg-dashboard.ini')
    # global app_ip
    app_ip = config.get("Server", "app_ip")
    # global app_port
    app_port = config.get("Server", "app_port")
    WG_CONF_PATH = config.get("Server", "wg_conf_path")
    config.clear()
    app.run(host=app_ip, debug=False, port=app_port)
