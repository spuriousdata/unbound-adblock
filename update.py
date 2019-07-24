#!/usr/bin/env python
import sys
import re
import requests
from collections import namedtuple
from argparse import ArgumentParser
from contextlib import contextmanager

comment = re.compile(r'\s*#')
host = re.compile(r'\d\.\d\.\d\.\d\s+(.*)')
hostonly = re.compile(r'^[\w\.-]+$')
spaceonly = re.compile(r'^\s*$')  # all whitespace or blank

BIGDOMAINS = (
    'cloudfront.net',
    'wordpress.com',
    'blogspot.com',
    'akamaihd.net',
)

MALWARE = (
    "http://www.malwaredomainlist.com/hostslist/hosts.txt",
    "/var/unbound/etc/block/ublock-malwarelist.block",
)

ADS = (
    "https://pgl.yoyo.org/as/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "/var/unbound/etc/block/local.block",
)

SendTo = namedtuple('SendTo', ['four', 'six'])
rdr = {
    'local': SendTo('127.0.0.1', '::1'),
    'invalid': SendTo('0.0.0.0', '::'),
}

malware_domains = set()
adserver_domains = set()


@contextmanager
def get_iterator(f):
    if f.startswith('/') or not f.startswith('http'):
        fp = open(f, 'rb')
        yield iter(fp)
        fp.close()
    else:
        yield requests.get(f).iter_lines()


def process(url, _list):
    with get_iterator(url) as data:
        for line in data:
            if spaceonly.search(line) or comment.search(line):
                continue
            m = host.search(line)
            try:
                _list.add(m.group(1).strip())
            except:
                if hostonly.search(line):
                    _list.add(line.strip())
                else:
                    print "Error parsing line: %s" % line


def distill(_list):
    superdomains = set()
    for d in _list:
        in_bigdomains = False
        for bd in BIGDOMAINS:
            if d.endswith(bd):
                superdomains.add(d)
                in_bigdomains = True
                break
        if in_bigdomains:
            continue
        parts = d.split('.')
        if len(parts) > 2:
            if len(''.join(parts[-2:])) <= 5:
                # try to deal better with *.co.uk and the like
                superdomains.add('.'.join(parts[-3:]))
            else:
                superdomains.add('.'.join(parts[-2:]))
    return superdomains


def unbound_entry(zone, add_ip6=True, rdr_to="invalid"):
    d = {
        'rdr4': rdr[rdr_to].four,
        'rdr6': rdr[rdr_to].six,
        'zone': zone,
    }
    out = [
        'local-zone: "%(zone)s" redirect' % d,
        'local-data: "%(zone)s A %(rdr4)s"' % d,
    ]
    if add_ip6:
        out.append('local-data: "%(zone)s AAAA %(rdr6)s"' % d)

    return out


def main():
    parser = ArgumentParser()
    parser.add_argument('-4', '--no_ip6', action='store_true', default=False)
    parser.add_argument('-m', '--malware_conf_file', default='baddies.conf')
    parser.add_argument('-a', '--adserver_conf_file', default='adservers.conf')
    args = parser.parse_args(sys.argv[1:])

    for url in MALWARE:
        process(url, malware_domains)

    for url in ADS:
        process(url, adserver_domains)

    md = distill(malware_domains)

    with open(args.malware_conf_file, 'wb') as fp:
        for zone in md:
            fp.write('\n'.join(unbound_entry(zone, not args.no_ip6)))
            fp.write('\n\n')

    with open(args.adserver_conf_file, 'wb') as fp:
        # skip domains already blocked by malware blocker
        domains = adserver_domains - md
        for zone in domains:
            fp.write('\n'.join(unbound_entry(zone, not args.no_ip6)))
            fp.write('\n\n')


if __name__ == '__main__':
    main()
