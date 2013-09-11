#!/usr/bin/env python

import os
import re
import cgi
import flask
import socket
import datetime
import apachelog
import pymongo
import hashlib
import json
import gitsh

#from dulwich.repo import Repo
#from dulwich.client import HttpGitClient

#import socket
#import syslog

app = flask.Flask(__name__)
app.config.from_object(__name__)
app.config.from_pyfile('../conf/kickoff.cfg')

# Convert from datetime object to timestamp
def dt_to_timestamp(dt):
    t = dt.strftime("%Y%m%d%H%M%S")
    return t

# Convert from timestamp to datetime object
def timestamp_to_dt(timestamp):
    t = datetime.datetime.strptime(str(timestamp.strip("[").split(" ")[0]), '%d/%b/%Y:%H:%M:%S')
    return t

def dbopen(collection):
    dbhost = app.config['DBHOST']
    dbport = app.config['DBPORT']
    db = app.config['DBNAME']

    # Connect to mongodb
    try:
        connection = pymongo.Connection(dbhost,dbport)

    except:
        print "Unable to connect to database server " \
              "at %s:%s" % (dbhost,dbport)
        return False

    # Select database
    try:
        database = connection[db]

    except:
        print "ERROR: Unable to select to database %s " \
              "at %s:%s" % (db,dbhost,dbport)
        return False

    # Select collection
    try:
        col = database[collection]

    except:
        print "ERROR: Unable to select to collection %s " \
              "in database at %s:%s" % (collection,db,dbhost,dbport)
        return False

    # Return collection handler
    return col

def get_vendor(mac):
    path = '/vagrant/kickoff/conf/oui.txt'
    vendor = False
    if not os.path.isfile(path):
        return False

    needle = mac[0:8].upper()
    r = re.compile('^\s+%s\s+\(hex\)\s+(.*)' % needle)
    with open(path, 'r') as f:
        for line in f:
            m = r.search(line)
            if m:
                vendor = m.group(1)

    return vendor

## Save the data for a spesific MAC address.
#def save_host(mac, data = {}):
#    path = app.config['HOST_DIR'] + '/' + mac
#
#    now = datetime.datetime.now()
#    ts = dt_to_timestamp(now)
#
#    if not os.path.exists(path):
#        os.makedirs(path,0700)
#
#    status = False
#
#    data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
#    data['mac'] = mac
#
#    filepath = '%s/%s.json' % (path, ts)
#    content = json.dumps(data, indent=4, sort_keys=True)
#
#    try:
#        f = open(filepath,'w+')
#        f.write(content)
#        f.close()
#
#    except:
#        print "Unable to write host file (%s)." % (filepath)
#
#    else:
#        status = True
#        print "Host file written (%s)." % (filepath)
#
#    return status
#
## Save the data for a spesific MAC address.
#def save_state(mac, data = {}):
#    path = app.config['STATE_DIR'] + '/' + mac
#
#    now = datetime.datetime.now()
#    ts = dt_to_timestamp(now)
#
#    if not os.path.exists(path):
#        os.makedirs(path,0700)
#
#    status = False
#
#    data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
#    data['mac'] = mac
#    data['id'] = hashlib.sha1(ts + mac).hexdigest()
#    data['ts'] = int(ts)
#
#    filepath = '%s/%s.json' % (path, ts)
#    content = json.dumps(data, indent=4, sort_keys=True)
#
#    try:
#        f = open(filepath,'w+')
#        f.write(content)
#        f.close()
#
#    except:
#        print "Unable to write state file (%s)." % (filepath)
#
#    else:
#        status = True
#        #print "State file created (%s)." % (filepath)
#
#        history = app.config['HISTORY_DIR']
#        if not os.path.exists(history):
#            os.makedirs(history,0700)
#
#        linkpath = '%s/%s-%s' % (history, ts, mac)
#        try:
#            os.symlink(filepath, linkpath)
#        except:
#            print "Unable to create symlink from %s to %s" % \
#                (filepath, linkpath)
#
#    return status

# Input validation for domains
def clean_domain(domain):
    f = re.compile('[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*')
    m = f.match(domain)
    if not m:
       domain = False

    return domain

def verify_mac(mac):
    macfilter = re.compile('^[a-f0-9]{12}$')
    m = macfilter.match(mac)

    if m:
        return True
    else:
        return False

## Give MAC addresses nice formatting.
def clean_mac(mac):
    # Remove all uneccessary characters from the given mac address
    mac = re.sub('[^0-9a-fA-F]', '', mac)
    mac = mac.lower()

    # At this point, the mac address should be 12 characters
    if len(mac) != 12:
        mac = False
    
    return mac

## Give MAC addresses nice formatting.
def pretty_mac(mac):
    # Remove all uneccessary characters from the given mac address
    mac = re.sub('[^0-9a-fA-F]', '', mac)
    mac = mac.lower()

    # At this point, the mac address should be 12 characters
    if len(mac) == 12:
        mac = '%s-%s-%s-%s-%s-%s' % \
              (mac[0:2],mac[2:4],mac[4:6],mac[6:8],mac[8:10],mac[10:12])
    else:
        mac = False
    
    return mac

#def get_ipxe_configuration(mac, permission, host):
#    ipxe = False
#    path = False
#    status = False
#
#    # If not permission, serve some exit-message
#    if not permission:
#        path = app.config['DEFAULT_NO_PERMISSION_IPXE_CONFIGURATION']
#        status = 0
#
#    else:
#        # Check if the directory of this mac address exists to see if we have seen
#        # this host before or not.
#        d = app.config['STATE_DIR'] + '/' + mac
#        if os.path.isdir(d):
#            # Known host
#            # Look for configuration, if none is found:
#            if 'ipxe' in host:
#                ipxe = host['ipxe']
#                status = 3
#            else:
#                path = app.config['DEFAULT_KNOWN_HOST_IPXE_CONFIGURATION']
#                status = 2
#        else:
#            # Unknown host
#            path = app.config['DEFAULT_UNKNOWN_HOST_IPXE_CONFIGURATION']
#            status = 1
#
#    if not ipxe and path:
#        if os.path.exists(path):
#            try:
#                f = open(path, 'r')
#
#            except:
#                print "Unable to open file %s for reading." % (path)
#
#            else:
#                ipxe = f.read()
#                f.close()
#
#    return (status,ipxe)
#
#def get_data(path, ts = False):
#    if not os.path.isdir(path):
#        return False
#
#    if not ts:
#        f = re.compile("^(\d+)\.json$")
#        ts = 0
#        for entry in os.listdir(path):
#            i = path + '/' + entry
#            m = f.match(entry)
#            if os.path.isfile(i) and m:
#                this_ts = int(m.group(1))
#                if this_ts > ts:
#                    ts = this_ts
#
#    filepath = path + '/' + str(ts) + '.json'
#    if not os.path.isfile(filepath):
#        print "File %s does not exist" % filepath
#        return False
#
#    try:
#        f = open(filepath,'r')
#    except:
#        print "Unable to open file %s for reading" % filepath
#    else:
#         try:
#             content = json.loads(f.read())
#
#         except:
#             print "Unable to read and/or decode content in %s" % filepath
#
#         else:
#             return content
#
#    return False
#
## Let's see if this host with mac, uuid and remote_addr is allowed to get configuration
#def get_permission(host, mac, uuid, remote_addr, hostname):
#    if 'mac' in host:
#        if mac != host['mac']:
#            return False
#
#    if 'uuid' in host:
#        if uuid != host['uuid']:
#            return False
#
#    if 'remote_addr' in host:
#        if remote_addr != host['remote_addr']:
#            return False
#
#    if 'hostname' in host:
#        if hostname != host['hostname']:
#            return False
#
#    return True
#
#def get_host_configuration(mac, uuid = False, remote_addr = False, hostname = False):
#    data = {}
#    path = app.config['HOST_DIR'] + '/' + mac
#
#    if os.path.isdir(path):
#        # Known host
#        data = get_data(path)
#
#    else:
#        # Unknown host, create a default here with lockdown
#        data['mac'] = mac
#        data['uuid'] = uuid
#        data['remote_addr'] = remote_addr
#        data['hostname'] = hostname
#
#        vendor = get_vendor(mac)
#        if vendor:
#            data['vendor'] = vendor
#
#        now = datetime.datetime.now()
#        ts = dt_to_timestamp(now)
#
#        data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
#        if not os.path.exists(path):
#            os.makedirs(path,0700)
#
#        status = False
#        filepath = '%s/%s.json' % (path, ts)
#        content = json.dumps(data, indent=4, sort_keys=True)
#
#        try:
#            f = open(filepath,'w+')
#            f.write(content)
#            f.close()
#
#        except:
#            print "Unable to write host file (%s)." % (filepath)
#
#        else:
#            status = True
#            print "Host file written (%s)." % (filepath)
#
#    return data
#
#def get_revisions(path, count = False, reverse = True):
#    f = re.compile("^(\d+)\.json$")
#    revisions = []
#    if os.path.isdir(path):
#        for i in os.listdir(path):
#            filepath = path + "/" + i
#            m = f.match(i)
#            if os.path.isfile(filepath) and m:
#                ts = int(m.group(1))
#                revisions.append(ts)
#    revisions.sort()
#    if reverse:
#        revisions.reverse()
#    if count:
#        return revisions[0:count]
#    else:
#        return revisions
#        
#def get_all_mac_addresses():
#    path = app.config['STATE_DIR']
#    macs = []
#    if os.path.isdir(path):
#        for mac in os.listdir(path):
#            p = path + "/" + mac
#            if os.path.isdir(p):
#                macs.append(mac)
#    return macs

# https://gist.github.com/nzjrs/207624
def humanize_date_difference(now, otherdate=None, offset=None):
    if otherdate:
        dt = otherdate - now
        offset = dt.seconds + (dt.days * 60*60*24)
    if offset:
        delta_s = offset % 60
        offset /= 60
        delta_m = offset % 60
        offset /= 60
        delta_h = offset % 24
        offset /= 24
        delta_d = offset
    else:
        return "now"
 
    if delta_d > 1:
        if delta_d > 6:
            date = now + datetime.timedelta(days=-delta_d, hours=-delta_h, minutes=-delta_m)
            return date.strftime('%A, %Y %B %m, %H:%I')
        else:
            wday = now + datetime.timedelta(days=-delta_d)
            return wday.strftime('%A')
    if delta_d == 1:
        return "Yesterday"
    if delta_h > 0:
        return "%dh %dm" % (delta_h, delta_m)
    if delta_m > 0:
        return "%dm %ds" % (delta_m, delta_s)
    else:
        return "%ds" % delta_s

def is_boot_request(request):
    r = re.compile('^GET\s+\/bootstrap\/([A-Fa-f0-9]{12})\/ipxe\s+HTTP\/[0-9]+\.[0-9]+$')
    m = r.match(request)
    if m:
        mac = m.group(1)
        return mac
    else:
        return False

def log_data_exists(checksum):
    col = dbopen('log')

    q = {}
    q['_id'] = checksum
    try:
        count = col.find(q).count()

    except:
        print "Unable to execute find query %s" % q

    else:
        if count > 0:
            return True

    return False

def process_log_data(data,checksum,host):
    request = data['%r']
    mac = is_boot_request(request)
    if mac:
        if not log_data_exists(checksum):
            l = {}
            l['_id'] = checksum
            l['host'] = host
            l['request'] = request
            l['status'] = data['%>s']
            l['byte'] = data['%b']
            l['client'] = data['%h']

            fqdn = get_reverse_address(l['client'])
            if fqdn:
                l['client_ptr'] = fqdn
                l['domain'] = extract_domain_from_fqdn(fqdn)

            l['timestamp'] = data['%t']
            l['useragent'] = data['%{User-Agent}i']
            l['referer'] = data['%{Referer}i']
            l['mac'] = clean_mac(mac)
            col = dbopen('log')
            try:
                col.insert(l)
            except:
                print "Unable to insert log data"
                return False
            else:
                return True

    return 
    #ref = data['%{Referer}i']
    #byte = data['%b']
    #code = data['%b']
    #code = data['%b']

def get_boot_requests(mac = False, first = 0, limit = False, status = []):
    res = []
    now = datetime.datetime.now()
    col = dbopen('log')
    try:
        q = {}
        if mac:
            q['mac'] = mac

        if limit:
            cursor = col.find(q, limit=limit)
        else:
            cursor = col.find(q)
    except:
        print "Unable to get boot requests %s" % (q)
    else:
        for i in cursor:
            dt = timestamp_to_dt(i['timestamp'])
            i['epoch'] = (dt - datetime.datetime(1970,1,1)).total_seconds()
            i['age'] = humanize_date_difference(dt,now)
            i['pretty_mac'] = pretty_mac(i['mac'])
            i['status'] = int(i['status'])

            vendor = get_vendor(i['mac'])
            if vendor:
                i['vendor'] = vendor

            res.append(i)


    res = sorted(res, key=lambda x: x['epoch'], reverse = True)
    return res

#def get_last_boot_requests(first = 0, limit = False, mac = False, status = []):
#    res = []
#
#    path = app.config['HISTORY_DIR']
#    f = re.compile('^(\d+)-(.*)')
#    if mac:
#        path = app.config['STATE_DIR'] + '/' + mac
#        f = re.compile('^(\d{14}).json$')
#
#    now = datetime.datetime.now()
#
#    if not os.path.isdir(path):
#        print "Directory %s does not exists." % path
#        return []
#    
#    entries = sorted(os.listdir(path), reverse = True)
#
#    matched_counter = 0
#    for entry in entries:
#        matching = False
#        if os.path.islink('%s/%s' % (path, entry)):
#            m = f.match(entry)
#            if m:
#                ts = m.group(1)
#                mac = m.group(2)
#                mac = clean_mac(mac)
#        else:
#            m = f.match(entry)
#            if m:
#                ts = m.group(1)
#
#        if ts and mac:
#            state_path = app.config['STATE_DIR'] + '/' + mac
#            data = get_data(state_path, ts = ts)
#            dt = timestamp_to_dt(ts)
#            data['age'] = humanize_date_difference(dt,now)
#            data['seconds'] = (now-dt).seconds
#
#            # Status filter
#            if len(status) > 0:
#                if data['status'] in status:
#                    matching = True
#            else:
#                matching = True
#
#            if matching:
#                if matched_counter >= first:
#                    res.append(data)
#
#                matched_counter += 1
#
#        if limit:
#            if len(res) >= limit:
#                break
#
#    return res

# Use the DNS PTR to create logical groups of nodes. This method converts fqdn
# to group name.
def extract_domain_from_fqdn(fqdn):
    group = False
    rule = re.compile('^[^\.]+\.(.*)')
    res = rule.search(fqdn)
    if res:
        if res.group(1):
            group = res.group(1)

    return group

def get_reverse_address(ip):
    try:
        reverse = socket.gethostbyaddr(ip)[0]
    except:
        reverse = False
    return reverse


@app.route("/")
def index():
    known = get_boot_requests(limit = 5)

    headings = [
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'pretty_mac',    'pretty': 'MAC'},
        {'id': 'domain',        'pretty': 'Domain'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'status',        'pretty': 'HTTP status'},
    ]
    return flask.render_template("index.html", title = "Overview", \
        active = "overview", unknown = unknown, entries = known, \
        headings = headings)

@app.route("/hosts/")
@app.route("/hosts")
def hosts():
    cfg = get_bootstrap_cfg()
    history = get_boot_requests()
    data = {}
    for i in history:
        mac = i['mac']

        if not mac in data:
            data[mac] = i

    for mac in cfg:
        if mac in data:
            data[mac] = dict(data[mac], **cfg[mac])
        else:
            data[mac] = cfg[mac]
            data[mac]['mac'] = mac

    hosts = []
    for mac in data:
        # To enable sorting
        if not 'epoch' in data[mac]:
            data[mac]['epoch'] = -1

        hosts.append(data[mac])

    hosts = sorted(hosts, key=lambda x: x['epoch'], reverse = True)
    headings = [
        {'id': 'pretty_mac',    'pretty': 'MAC'},
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'timestamp',     'pretty': 'Timestamp'},
        {'id': 'domain',        'pretty': 'Domain'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'HTTP status'},
    ]

    return flask.render_template("hosts.html", \
        entries = hosts, \
        headings = headings, \
        title = "Hosts", \
        active = "hosts")

@app.route("/maintenance/")
@app.route("/maintenance")
def maintenance():
    logdir = app.config['REPLICA_LOG_DIR']
    log_format = app.config['REPLICA_LOG_FORMAT']

    if not os.path.isdir(logdir):
        return flask.make_response("The path %s is not a directory" % logdir, 500)

    p = apachelog.parser(log_format)
    out = {}
    out['errors'] = []
    for h in os.listdir(logdir):
        path = "%s/%s" % (logdir,h)
        if os.path.isdir(path):
            if not h in out:
                out[h] = {}

            for f in os.listdir(path):
                path = "%s/%s/%s" % (logdir,h,f)
                if os.path.isfile(path):
                    meta = {}
                    try:
                        fp = open(path,'r')
                    except:
                        out['errors'].append("Unable to open %s for reading" % path)
                    else:
                        meta['new_entries'] = 0
                        #try:
                        #    stat = os.stat(path)
                        #except:
                        #    out['errors'].append("Unable to stat %s" % path)
                        #else:
                        #    meta['mtime'] = stat.st_mtime
                        #    meta['size'] = stat.st_size

                        for line in fp:
                            try:
                                data = p.parse(line)
                            except:
                                out['errors'].append("Unable to parse line [%s] in file %s" % (line,path))
                            else:
                                checksum = hashlib.sha1()
                                checksum.update(line)

                                s=process_log_data(data,checksum.hexdigest(),h)
                                if s:
                                    meta['new_entries'] += 1

                    out[h][f] = meta

    # Remove the error list if it's empty
    if len(out['errors']) == 0:
        del(out['errors'])
    
    response = flask.make_response(json.dumps(out, indent=2))
    response.headers['cache-control'] = 'max-age=0, must-revalidate'
    return response

@app.route("/domains/")
@app.route("/domains")
def domains():
    history = get_boot_requests()
    data = {}
    for i in history:
        if not i['mac'] in data:
            data[i['mac']] = i

    domains = []
    for mac in data:
        if 'domain' in data[mac]:
            domains.append(data[mac])

    headings = [
        {'id': 'domain',        'pretty': 'Domain'},
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'pretty_mac',    'pretty': 'MAC'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'HTTP status'},
    ]

    domains = sorted(domains, key=lambda x: x['epoch'], reverse = True)
    return flask.render_template("domains.html", title = "Domains", \
        active = "domains", entries = domains, headings = headings)

@app.route("/domain/<domain>")
def domain(domain):
    domain = clean_domain(domain)
    if not domain:
        return flask.make_response("The given domain is not valid", 400)

    history = get_boot_requests()
    data = {}
    for i in history:
        if not i['mac'] in data:
            data[i['mac']] = i

    hosts = []
    for mac in data:
        if 'domain' in data[mac]:
            if data[mac]['domain'] == domain:
                hosts.append(data[mac])

    headings = [
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'pretty_mac',    'pretty': 'MAC'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'HTTP status'},
        {'id': 'ipxe',          'pretty': 'iPXE'},
    ]

    hosts = sorted(hosts, key=lambda x: x['epoch'], reverse = True)
    return flask.render_template("domain.html", title = "Domain %s" % domain, \
        active = "domain", entries = hosts, headings = headings, \
        domain = domain)

#@app.route("/boot-history/")
#@app.route("/boot-history")
#def boot_history():
#    per_page = int(app.config['ELEMENTS_PER_PAGE'])
#    page = int(flask.request.args.get('page', 1))
#
#    # Status filter
#    s = flask.request.args.get('status', False)
#    status = []
#    if s:
#        for i in list(s):
#            status.append(int(i))
#
#    boot = False
#    mac = flask.request.args.get('mac', False)
#    if mac:
#        mac = clean_mac(mac)
#        boot = get_last_boot_requests(limit = 1, mac = mac)
#
#        title = "%s boot history" % mac
#    else:
#        if int(s) == 1:
#            title = "Discovered hosts"
#        else:
#            title = "Boot history"
#
#    entries = get_last_boot_requests(first = per_page*(page-1), limit = per_page, mac = mac, status = status)
#
#    previous_page = False
#    next_page = False
#
#    if page > 1:
#        previous_page = page - 1
#
#    if len(entries) == per_page:
#        next_page = page + 1
#
#    return flask.render_template("boot-history.html", title = title, \
#        active = "history", entries = entries, mac = mac, status = int(s), \
#        boot = boot, \
#        page = page, previous_page = previous_page, next_page = next_page)
#
#@app.route("/mac/<mac>")
#@app.route("/mac/<mac>/")
#def mac(mac):
#    return flask.redirect('/mac/%s/history' % mac)
#
@app.route("/mac/<mac>/security", methods = ['GET', 'POST'])
def mac_security(mac):
    mac = clean_mac(mac)

    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    #boot = get_last_boot_requests(limit = 1, mac = mac)
    boot = {}
    cfg = get_bootstrap_cfg(mac)

    return flask.render_template("mac_security.html", \
        title = "%s security" % mac, mac = mac, \
        active = "security", cfg = cfg, boot = boot)
    mac = clean_mac(mac)
    
@app.route("/mac/<mac>/configuration")
def mac_configuration(mac):
    mac = clean_mac(mac)

    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    #boot = get_last_boot_requests(limit = 1, mac = mac)
    boot = {}
    cfg = get_bootstrap_cfg(mac)

    return flask.render_template("mac_configuration.html", \
        title = "%s configuration" % mac, mac = mac, \
        active = "configuration", cfg = cfg, boot = boot)

@app.route("/mac/<mac>/history")
def mac_history(mac):
    mac = clean_mac(mac)
    history = get_boot_requests(mac)
    headings = [
        {'id': 'age',           'pretty': 'Last active'},
        {'id': 'timestamp',     'pretty': 'Timestamp'},
        {'id': 'domain',        'pretty': 'Domain'},
        {'id': 'client_ptr',    'pretty': 'DNS PTR'},
        {'id': 'client',        'pretty': 'IP'},
        {'id': 'host',          'pretty': 'Served by'},
        {'id': 'status',        'pretty': 'HTTP status'},
    ]
    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    return flask.render_template("mac_history.html", \
        title = "%s boot history" % mac, mac = mac, \
        active = "history", entries = history, headings = headings)

@app.route("/about/")
@app.route("/about")
def about():
    return flask.render_template("about.html", title = "About", \
       active = "about")

#@app.route("/bootstrap/mac-<mac>.ipxe")
#def bootstrap(mac):
#    mac = clean_mac(mac)
#    h = {'content-type' : 'text/plain'}
#
#    if not mac:
#        return flask.make_response("The given mac address is not valid", 400, h)
#
#    # Store the UUID if sent by the client
#    uuid = flask.request.args.get('uuid', None)
#    hostname = flask.request.args.get('hostname', None)
#
#    # Read the source IP address of the request
#    remote_addr = flask.request.environ.get('REMOTE_ADDR', None)
#
#    # Get host configuration
#    host = get_host_configuration(mac, uuid, remote_addr, hostname)
#
#    # Let's see if this host with mac, uuid and remote_addr is allowed to get configuration
#    permission = get_permission(host, mac, uuid, remote_addr, hostname)
#
#    # If permission is granted, get configuration:
#    (status, ipxe) = get_ipxe_configuration(mac, permission, host)
#
#    data = {}
#    data['ipxe']        = ipxe
#    data['uuid']        = uuid
#    data['remote_addr'] = remote_addr
#    data['status']      = status
#    data['hostname']    = hostname
#
#    if 'vendor' in host:
#        data['vendor']  = host['vendor']
#
#    reverse = get_reverse_address(remote_addr)
#    if reverse:
#        data['reverse'] = reverse
#        data['domain'] = extract_domain_from_fqdn(reverse)
#
#    if not save_state(mac, data):
#        print "Unable to write state for MAC " + mac
#        return flask.make_response("Unable to write state for MAC %s" % (mac), 500, h)
#
#    return flask.make_response(ipxe, 200, h)

def save_host_boot_configuration(mac, ipxe, htaccess):
    status = False
    return status

def read_file(path):
    contents = False
    try:
        fp = open(path, 'r')
    except:
        pass
    else:
        contents = fp.read()

    return contents

def get_bootstrap_cfg(mac = False):
    repository = app.config['REPOSITORY']
    cache = app.config['CACHE']

    if mac:
        if not verify_mac(mac):
            mac = False

    repo = gitsh.gitsh(repository, cache, True)
    if os.path.isdir(cache):
        #repo.pull()
        pass
    else:
        repo.clone()

    data = {}
    for m in os.listdir(cache):
        path = cache + "/" + m
        if os.path.isdir(path):
            if verify_mac(m):
                if mac:
                    if mac != m:
                        continue

                if not m in data:
                    data[m] = {}
                    data[m]['pretty_mac'] = pretty_mac(m)
    
                for f in os.listdir(cache + "/" + m):
                    path = cache + "/" + m + "/" + f
                    if os.path.isfile(path):
                        if f == 'ipxe':
                            data[m]['ipxe'] = read_file(path)
            
                        elif f == '.htaccess':
                            data[m]['htaccess'] = read_file(path)
        
    return data

@app.route("/api/configuration/", methods = ['GET', 'POST'])
@app.route("/api/configuration", methods = ['GET', 'POST'])
def api_configuration():
    out = {}
    if flask.request.method == 'GET':
        out = get_bootstrap_cfg()

    if flask.request.method == 'POST':
        try:
            mac = clean_mac(flask.request.form['mac'])
            ipxe = flask.request.form['ipxe']
            htaccess = flask.request.form['htaccess']

        except:
            out['error'] = 'The input data was invalid'

        else:
            if save_host_boot_configuration(mac, ipxe, htaccess):
                out['status'] = 'OK'

    response = flask.make_response(json.dumps(out, indent=2))
    response.headers['cache-control'] = 'max-age=0, must-revalidate'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0')

