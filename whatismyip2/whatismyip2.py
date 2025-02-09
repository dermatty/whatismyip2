#! /usr/bin/python

from . import __version__
import requests, time, json, sys, os, multiprocessing, configparser, platform, datetime
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

        weburls_values = cfg["WEBURLS"]["interfaces"]
        interfaces = json.loads(weburls_values)
        logger.info("Interfaces are:" + str(interfaces))

    except Exception as e:
        logger.error(str(e))
        sys.exit()

    motd = ("whatismyip2 " + str(__version__) + " external ip info running on " + str(HOSTNAME) + ", Port " + str(port)
            + " ...")
    logger.info(motd)

    indexhtmlpath = maindir
    indexhtml = indexhtmlpath + "/index.html"
    MP = multiprocessing.Process(target=webserver_process, args=(port, indexhtmlpath,))
    MP.daemon = True
    MP.start()

    ipdir = {}
    for url in interfaces:
        ipdir[url] = {"Name": interfaces[url], "IP": "0.0.0.0", "org": "-", "country": "-"}

    while True:
        reslist = []

        for url in ipdir:
            if_name = ipdir[url]["Name"]
            if_ip = str(ipdir[url]["IP"])

            ip_has_changed = False
            try:
                r = requests.get(url)
                if "ip4only" in url:
                    ip = r.text.split(",")[1]
                elif "dyndns" in url:
                    ip = r.text.split(":")[1].split("<")[0].strip()
                else:
                    ip = r.text.strip()
                details = ""
                if ip != if_ip:
                    ip_has_changed = True
                    details = requests.get("http://ipinfo.io/" + str(ip) + "?token=" + token).json()
                    try:
                        org = details["org"]
                        country = details["country"]
                    except Exception:
                        org = "-"
                        country = "-"
                    ipdir[url]["IP"] = ip
                    ipdir[url]["org"] = org
                    ipdir[url]["country"] = country
            except Exception as e:
                details = "Error: " + str(e)

            if ip_has_changed:
                if "Error" not in details:
                    res0 = (if_name + " via " + url.split("/")[2] + ": " + str(ipdir[url]["IP"]) + ": "
                            + ipdir[url]["org"] + ": " + ipdir[url]["country"])

                    reslist.append(res0)
                    logger.info ("Ip change: " + if_name + " via " + url.split("/")[2] + ": from " +
                                 str(if_ip) + " to " + str(ipdir[url]["IP"]) + " / " + ipdir[url]["org"] +
                                 " / " + ipdir[url]["country"])

                else:
                    reslist.append(if_name + " via " + url.split("/")[2] + ": " + details)
                # write index.html
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
