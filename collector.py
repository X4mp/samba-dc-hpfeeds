#!/usr/bin/python

import multitail2
import hpfeeds

import sys
import datetime
import json
import hpfeeds
import logging
import re

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

def parse(line):
    regex = r"\s*Kerberos:\s(?P<flag>\w+)-REQ\s(?P<username>\w+)@(\S*)\s+from\s+ipv4:(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<source_port>\d+)\sfor\s(?P<destination>\S+)"
    match = re.match(regex, line)
    if match:
        print(line)
        res = match.groupdict()
        for name in res.keys():
            if not res[name]:
                del res[name]
        return res
    return None

def hpfeeds_connect(host, port, ident, secret):
    try:
	logger.info('{0}, {1}'.format(ident, secret))
        connection = hpfeeds.new(host, port, ident, secret)
    except hpfeeds.FeedException as e:
        logger.error('feed exception: %s'%e)
        sys.exit(1)
    logger.info('connected to %s (%s:%s)'%(connection.brokername, host, port))
    return connection

def main():
    cfg = {
        'host' : '',
        'port' : 10000,
        'channel' : '',
        'ident' : '',
        'secret' : '',
        'tail_file' : '/var/log/samba/samba.log'
    }

    if len(sys.argv) > 1:
        logger.info("Parsing config file: %s"%sys.argv[1])
        cfg.update(json.load(file(sys.argv[1])))

        for name,value in cfg.items():
            if isinstance(value, basestring):
                # hpfeeds protocol has trouble with unicode, hence the utf-8 encoding here
                cfg[name] = value.encode("utf-8")
    else:
        logger.warning("Warning: no config found, using default values for hpfeeds server")
    publisher  = hpfeeds_connect(cfg['host'], cfg['port'], cfg['ident'], cfg['secret'])

    tail = multitail2.MultiTail(cfg['tail_file'])
    for filemeta, line in tail:
        record = parse(line)
        if record:
            publisher.publish(cfg['channel'], json.dumps(record))
            logger.debug(json.dumps(record))
    publisher.stop()
    return 0

if __name__ == '__main__':
    try: 
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)

