#! /usr/bin/python

from . import __version__
import requests, time, json, sys, re, os, multiprocessing, configparser, platform, datetime
import logging
import logging.handlers
import http.server
import socketserver
from os.path import expanduser

HTML = (["<html>", "<head>", "</head>", "<body>", "</body>", "</html>"])
HOSTNAME = platform.uname().node

def webserver_process (port, directory):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", int(port)), Handler) as httpd:
        httpd.serve_forever()

def get_external_ip(urllist):
    ip = None
    url = ""
    for url in urllist:
        try:
            r = requests.get(url)
            ip = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r.text)
            if ip[-1]:
                break
        except (Exception, ):
            pass
    return ip[-1], url

def start():
    userhome = expanduser("~")
    maindir = userhome + "/.whatismyip2/"
    statusfile = maindir + "myipstatus.txt"

    # Init Logger
    logger = logging.getLogger("wip2")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(maindir + "whatismyip2.log", mode="w")
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    cfg_file = maindir + "config"
    # read interval & weburls config
    try:
        cfg = configparser.ConfigParser()
        cfg.read(cfg_file)

        interval = int(cfg["GENERAL"]["interval"])
        logger.info("Set query interval to " + str(interval) + " seconds!")

        port = int(cfg["GENERAL"]["port"])
        logger.info("Set web server port to " + str(port) + "!")

        token = str(cfg["IPINFO"]["token"])
        logger.info("Set ipinfo token to " + str(token) + "!")

        #weburls_values = cfg["WEBURLS"]["interfaces"]
        #interfaces = json.loads(weburls_values)
        #logger.info("Interfaces are:" + str(interfaces))

        i = 1
        interfaces = {}
        while True:
            try:
                if_config = cfg["INTERFACES"]["if" + str(i)]
            except Exception as e:
                break
            if0 = json.loads(if_config)
            try:
                for key in if0:
                    interfaces[key] = if0[key]
            except (Exception, ):
                pass
            i += 1
    except Exception as e:
        logger.error(str(e))
        sys.exit()

    if not interfaces:
        logger.error("Empty interfaces data, exiting ...")
        sys.exit()

    logger.info("Set interfaces dir to: " + str(interfaces))

    motd = ("whatismyip2 " + str(__version__) + " external ip info running on " + str(HOSTNAME) + ", Port " + str(port)
            + " ...")
    logger.info(motd)

    indexhtmlpath = maindir
    indexhtml = indexhtmlpath + "/index.html"
    MP = multiprocessing.Process(target=webserver_process, args=(port, indexhtmlpath,))
    MP.daemon = True
    MP.start()

    ipdir = {}
    for key in interfaces:
        ipdir[key] = {"IP": "0.0.0.0", "IP_old": "1.1.1.1", "org": "-", "country": "-",
                      "urllist": interfaces[key]}

    while True:
        reslist = []
        ip_has_changed = False
        for if_name in ipdir:
            if_ip = str(ipdir[if_name]["IP"])
            ipdir[if_name]["IP_old"] = if_ip
            url = ""
            ip = None
            try:
                ip, url = get_external_ip(ipdir[if_name]["urllist"])
                details = ""
                if not ip:
                    ipdir[if_name]["IP"] = "0.0.0.0"
                    ipdir[if_name]["org"] = "-"
                    ipdir[if_name]["country"] = "-"
                    url = "https://<url-error>"
                elif ip is not None and ip != if_ip:
                    ip_has_changed = True
                    details = requests.get("http://ipinfo.io/" + str(ip) + "?token=" + token).json()
                    try:
                        org = details["org"]
                        country = details["country"]
                    except Exception:
                        org = "-"
                        country = "-"
                    ipdir[if_name]["IP"] = ip
                    ipdir[if_name]["org"] = org
                    ipdir[if_name]["country"] = country
            except Exception as e:
                details = "Error: " + str(e)
            if "Error" not in details:
                res0 = (if_name + " via " + url.split("/")[2] + ": " + str(ipdir[if_name]["IP"]) + ": "
                        + ipdir[if_name]["org"] + ": " + ipdir[if_name]["country"])
                reslist.append(res0)
                logger.info("IP change: " + if_name + " via " + url.split("/")[2] + ": from " +
                            str(ipdir[if_name]["IP_old"]) + " to " + str(ipdir[if_name]["IP"]) + " / " +
                            ipdir[if_name]["org"] + " / " + ipdir[if_name]["country"])
            else:
                reslist.append(if_name + " via " + url.split("/")[2] + ": " + details)

        # if at least 1 ip has changed update index.html / statusfile
        if ip_has_changed:
            try:
                with open(indexhtml, "w") as f:
                    for h in HTML:
                        f.writelines(h)
                        if h == "<body>":
                            for r in reslist:
                                f.writelines(r + "<br />")
                # write to statusfile
                with open(statusfile, "w") as f:
                    for r in reslist:
                        tstr = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S : ")
                        s0 = tstr + r
                        s0 += "\n"
                        f.write(s0)
            except Exception as e:
                logger.error(str(e))

        time.sleep(interval)
