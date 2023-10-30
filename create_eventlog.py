#!/usr/bin/env python
#
# License:
# https://github.com/JPCERTCC/xml2evtx/LICENSE.txt

import os
import random
import logging
import datetime
import argparse

try:
    from lxml import etree
    has_lxml = True
except ImportError:
    has_lxml = False

# Event id: rate
EVENT_ID = {
    4624: 0.71,
    4625: 0.02,
    4662: 0.01,
    4719: 0.01,
    4720: 0.01,
    4726: 0.01,
    4728: 0.01,
    4729: 0.01,
    4732: 0.01,
    4733: 0.01,
    4756: 0.01,
    4757: 0.01,
    4768: 0.05,
    4769: 0.05,
    4776: 0.05,
    5137: 0.01,
    5141: 0.01,
}

# Host name: IP Address
HOSTNAME_IP = {
    "host01": "192.168.0.1",
    "host02": "192.168.0.2",
    "host03": "192.168.0.3",
    "host04": "192.168.0.4",
    "host05": "192.168.0.5",
    "host06": "192.168.0.6",
    "host07": "192.168.0.7",
    "host08": "192.168.0.8",
    "host09": "192.168.0.9",
    "host10": "192.168.0.10",
    "host11": "192.168.0.11",
    "host12": "192.168.0.12",
    "host13": "192.168.0.13",
    "host14": "192.168.0.14",
    "host15": "192.168.0.15",
    "host16": "192.168.0.16",
    "host17": "192.168.0.17",
    "host18": "192.168.0.18",
    "host19": "192.168.0.19",
    "host20": "192.168.0.20",
    "ad": "192.168.0.100",
}

USERNAME = [
    "user01", "user02", "user03", "user04", "user05", "user06", "user07", "user08", "user09", "user10",
    "user11", "user12", "user13", "user14", "user15", "user16", "user17", "user18", "user19", "user20",
]

DOMAINNAME = {
    "CORP.LOCAL": 1,
}

# Logon type: rate
LOGONTYPE = {
    3: 99,
    10: 1,
}

# folder path
FPATH = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(description="Create random XML event logs.")
parser.add_argument("-f", "--file", dest="file", action="store", type=str, metavar="FILE",
                    help="Created event log file name. (Default: sample.xml)")
parser.add_argument("-c", "--count", dest="count", action="store", type=int, metavar="NUMBER",
                    help="Number of event logs to create.")
parser.add_argument("-v", "--verbose", action="store_true", default=False,
                    help="Show debug logs.")
args = parser.parse_args()

def setup_logger(name):
    setlogger = logging.getLogger(name)
    if args.verbose:
        setlogger.setLevel(logging.DEBUG)
    else:
        setlogger.setLevel(logging.INFO)

    # create console handler with a INFO log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')
    ch.setFormatter(ch_formatter)

    # add the handlers to the logger
    setlogger.addHandler(ch)

    return setlogger

logger = setup_logger(__name__)


def get_random_data(data_list, num):
    for i in range(num):
        id = random.choices(list(data_list.keys()), weights=list(data_list.values()))[0]
        yield id


def load_template_data(directory):
    logger.debug("load template data.")
    temlate_data = {}
    LOAD_DIR = os.path.join(FPATH, directory)
    file_list = os.listdir(LOAD_DIR)
    for file in file_list:
        with open(os.path.join(LOAD_DIR, file), "r") as f:
            temlate_data[int(file.split(".")[0])] = f.read()

    count = len(temlate_data)
    logger.debug(f"finished load template data {count}.")
    
    return temlate_data


def create_randum_xml_data(num):
    logger.info(f"create {num} event.")

    template_data = load_template_data("template")

    current_time = datetime.datetime.now()

    events = []
    event_record_id = 0
    for event_id in get_random_data(EVENT_ID, num):
        try:
            load_data = template_data[event_id]
        except:
            logger.error(f"Can't load template data for event id {event_id}.")
            continue

        random_seconds = random.randint(1, 5)
        new_time = current_time + datetime.timedelta(seconds=random_seconds)

        hostname = random.choice(list(HOSTNAME_IP.keys()))
        ip = HOSTNAME_IP[hostname]
        username = random.choice(USERNAME)
        logontype = list(get_random_data(LOGONTYPE, 1))[0]
        domainname = list(get_random_data(DOMAINNAME, 1))[0]
        port = random.randint(1024, 65535)
        processid = random.randint(1000, 10000)
        threadid = random.randint(1, 10000)

        format_event = load_data.format(**{"processid": processid,
                                            "threadid": threadid,
                                            "date": new_time.strftime("%Y-%m-%dT%H:%M:%S.%f"),
                                            "event_record_id": event_record_id,
                                            "hostname": hostname,
                                            "domainname": domainname,
                                            "username": username,
                                            "logontype": logontype,
                                            "ipaddress": ip,
                                            "port": port})
        fin_xml = format_event.encode("utf-8")
        parser = etree.XMLParser(resolve_entities=False)
        try:
            events.append(etree.fromstring(fin_xml, parser))
        except:
            logger.error(f"Can't parse xml data.\n {fin_xml}")
            continue

        event_record_id += 1

    return events


def main():
    logger.info("start create event log.")

    if args.count:
        event_count = args.count
    else:
        event_count = 10

    events = create_randum_xml_data(event_count)
    
    xml_data = b"<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<Events>\n"
    for event in events:
        xml_data += etree.tostring(event, encoding='utf8', method='xml')
        xml_data += b"\n"
    xml_data += b"</Events>"

    if args.file:
        xml_file_name = args.file
    else:
        xml_file_name = "sample.xml"

    # Create XML file
    with open(xml_file_name, "wb") as fe:
        fe.write(xml_data)

    logger.info(f"created {xml_file_name}.")


if __name__ == "__main__":
    main()