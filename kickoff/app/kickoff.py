#!/usr/bin/env python

import os
import re
import cgi
import flask
import datetime
import json
#import socket
#import syslog

app = flask.Flask(__name__)
app.config.from_object(__name__)
app.config.from_pyfile('../conf/kickoff.cfg')

## Return an array of the images available.
#def get_images():
#    images = []
#    basepath = app.config['IMAGEDIR']
#    if os.path.isdir(basepath):
#        for image in os.listdir(basepath):
#            if os.path.isdir('%s/%s' % (basepath,image)):
#                 if len(get_image_releases(image)) > 0:
#                     images.append(image)
#            
#    return images
#
## Return an array of the releases available for a spesific image.
#def get_image_releases(image):
#    releases = []
#    basepath = '%s/%s' % (app.config['IMAGEDIR'],image)
#    if os.path.isdir(basepath):
#        for release in os.listdir(basepath):
#            if os.path.isdir('%s/%s' % (basepath,release)):
#                 if os.path.isfile('%s/%s/boot.pxe' % (basepath,release)):
#                     releases.append(release)
#
#    return releases
#
## Return a dict containing the releases (with files) of a spesific image.
#def get_image_release(image,release):
#    files = {}
#    basepath = '%s/%s/%s' % (app.config['IMAGEDIR'],image,release)
#    if os.path.isdir(basepath):
#        for filename in os.listdir(basepath):
#            files[filename] = {}
#
#            filepath = '%s/%s' % (basepath,filename)
#            if os.path.isfile(filepath):
#                 stat=os.stat(filepath)
#
#                 i={}
#                 i['path'] = filepath
#                 i['size'] = stat.st_size
#                 i['mtime'] = stat.st_mtime
#                 i['mtime_iso'] = datetime.datetime.fromtimestamp( \
#                     stat.st_mtime).strftime("%Y-%m-%d %H:%S:%M")
#
#                 files[filename]=i
#
#    return files
#
## Return a default boot script.
#def boot_script_on_error(mac):
#    text="""#!ipxe
#echo Unable to deliver the boot configuration for %s.
#echo Will reboot in 60 seconds.
#sleep 60
#reboot
#""" % (mac)
#    return text

# Convert from datetime object to timestamp
def dt_to_timestamp(dt):
    t = dt.strftime("%Y%m%d%H%M%S")
    return t

# Convert from timestamp to datetime object
def timestamp_to_dt(timestamp):
    t = datetime.datetime.strptime(str(timestamp), '%Y%m%d%H%M%S')
    return t

# Save the data for a spesific MAC address.
def save_host(mac, data = {}):
    path = app.config['HOST_DIR'] + '/' + mac

    now = datetime.datetime.now()
    ts = dt_to_timestamp(now)

    if not os.path.exists(path):
        os.makedirs(path,0700)

    status = False

    data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
    data['mac'] = mac

    filepath = '%s/%s.json' % (path, ts)
    content = json.dumps(data, indent=4, sort_keys=True)

    try:
        f = open(filepath,'w+')
        f.write(content)
        f.close()

    except:
        print "Unable to write host file (%s)." % (filepath)

    else:
        status = True
        print "Host file written (%s)." % (filepath)

    return status

# Save the data for a spesific MAC address.
def save_state(mac, data = {}):
    path = app.config['STATE_DIR'] + '/' + mac

    now = datetime.datetime.now()
    ts = dt_to_timestamp(now)

    if not os.path.exists(path):
        os.makedirs(path,0700)

    status = False

    data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
    data['mac'] = mac
    data['ts'] = int(ts)

    filepath = '%s/%s.json' % (path, ts)
    content = json.dumps(data, indent=4, sort_keys=True)

    try:
        f = open(filepath,'w+')
        f.write(content)
        f.close()

    except:
        print "Unable to write state file (%s)." % (filepath)

    else:
        status = True
        print "State file created (%s)." % (filepath)

    return status

## Read the data for a spesific MAC address. Return a dict with the data.
#def read_data(mac):
#    data = {}
#    basepath = app.config['VARDIR']
#    if os.path.isdir(basepath):
#        filepath = '%s/%s.json' % (basepath,mac)
#        if os.path.isfile(filepath):
#            f = open(filepath,'r')
#            if f:
#                 try:
#                     content = json.loads(f.read())
#
#                 except:
#                     syslog.syslog(syslog.LOG_ERR,"%s: Unable to decode json " \
#                         "in %s." % (mac,filepath))
#
#                 else:
#                     if mac in content:
#                         data = content[mac]
#
#                     else:
#                         syslog.syslog(syslog.LOG_ERR,"%s: Something " \
#                             "uncool happened." % (mac))
#
#        else:
#            do_log("INFO","Discovered a new node with MAC %s" % (mac))
#            syslog.syslog(syslog.LOG_ERR,"%s: Configuration not found " \
#                "(%s)." % (mac,filepath))
#    
#    return data
#
## Return a dict containing all images and releases available.
#def get_images_and_releases():
#    ret = {}
#
#    images = get_images()
#    for image in images:
#        ret[image] = {}
#        releases = get_image_releases(image)
#
#        for release in releases:
#            ret[image][release] = get_image_release(image,release)
#
#    return ret
#
## Return an array of all MAC addresses known by the strapper.
#def get_all_known_macs():
#    macs = []
#    basepath = '%s' % (app.config['VARDIR'])
#
#    if os.path.isdir(basepath):
#        for m in os.listdir(basepath):
#            filepath = '%s/%s' % (app.config['VARDIR'],m)
#            if os.path.isfile(filepath):
#                try:
#                    f = open(filepath,'r')
#                    content = json.loads(f.read())
#
#                except:
#                    syslog.syslog(syslog.LOG_ERR,"Unable to read " \
#                        "configuration file (%s)." % (filepath))
#
#                else:
#                    if len(content) == 1:
#                        # Add the MAC address to the array
#                        macs.append(content.keys()[0])
#
#    return macs
#
## Return the active boot script for a spesific MAC address.
#def get_boot_script(mac):
#
#    # Serve some default script
#    script = boot_script_on_error(mac)
#
#    data = read_data(mac)
#
#    success = False
#
#    try:
#        image = data['image']
#        release = data['release']
#
#    except:
#        syslog.syslog(syslog.LOG_ERR,"%s: Unable to read image and release from the database. MAC is not configured." % (mac))
#
#    else:
#        syslog.syslog(syslog.LOG_INFO,"%s: Will serve image %s, release %s." % (mac,image,release))
#
#        basepath = '%s/%s/%s' % (app.config['IMAGEDIR'],image,release)
#        bootfile = '%s/boot.pxe' % (basepath)
#
#        if os.path.isfile(bootfile):
#            try:
#                f = open(bootfile,'r')
#
#            except:
#                syslog.syslog(syslog.LOG_ERR,"%s: Unable to read boot " \
#                    "configuration file (%s)." % (mac,bootfile))
#
#            else:
#                script = f.read()
#                f.close()
#                success = True
#                do_log("INFO","Boot configuration (%s, %s) served to %s" \
#                    % (image, release, mac))
#
#        else:
#            syslog.syslog(syslog.LOG_ERR,"%s: Boot configuration file " \
#                "(%s) was not found." % (mac,bootfile))
#
#    # Boot counter
#    try:
#        count = data['bootcount']
#
#    except:
#        data['bootcount'] = 1
#
#    else:
#        data['bootcount'] = int(count) + 1
#
#    data['lastbootscript'] = script
#    data['success'] = success
#
#    now = datetime.datetime.now()
#    data['lastboot'] = now.strftime("%Y%m%d%H%M%S")
#    data['lastboot_iso'] = now.strftime("%Y-%m-%d %H:%M:%S")
#
#    data['remote_addr'] = cgi.escape(os.environ['REMOTE_ADDR'])
#
#    if not save_data(mac,data):
#        syslog.syslog(syslog.LOG_ERR,"%s: Unable to save data." % (mac))
#
#    return script
#
## Use the DNS PTR to create logical groups of nodes. This method converts fqdn
## to group name.
#def extract_nodegroup_from_fqdn(fqdn):
#    group = False
#    rule = re.compile('^[^\.]+\.(.*)')
#    res = rule.search(fqdn)
#    if res:
#        if res.group(1):
#            group = res.group(1)
#
#    return group
#
#def get_nodegroup(group):
#    macs = get_all_known_macs()
#
#    ret = {}
#
#    for mac in macs:
#        data = read_data(mac)
#        try:
#            remote_addr = data['remote_addr']
# 
#        except:
#            pass
#
#        else:
#            try:
#                reverse = socket.gethostbyaddr(remote_addr)[0]
#
#            except:
#                syslog.syslog(syslog.LOG_ERR,"%s: Unable to reverse lookup %s" \
#                    % (mac,remote_addr))
#
#            else:
#                data['reverse'] = reverse
#                this_group = extract_nodegroup_from_fqdn(reverse)
#                if group == this_group:
#                    ret[mac] = data
#
#    return ret
#
#def get_nodegroups():
#    macs = get_all_known_macs()
#
#    data = {}
#    nodegroups = {}
#
#    rule = re.compile('^[^\.]+\.(.*)')
#
#    for mac in macs:
#        data[mac] = read_data(mac)
#        try:
#            remote_addr = data[mac]['remote_addr']
# 
#        except:
#            pass
#
#        else:
#            try:
#                reverse = socket.gethostbyaddr(remote_addr)[0]
#
#            except:
#                syslog.syslog(syslog.LOG_ERR,"%s: Unable to reverse lookup %s" \
#                    % (mac,remote_addr))
#
#            else:
#                res = rule.search(reverse)
#                if res:
#                    group = res.group(1)
#
#                    if group in nodegroups:
#                        nodegroups[group] += 1
#
#                    else:
#                        nodegroups[group] = 1
#
#    return nodegroups
#
## Return an array containing the dates in which there are log entries.
#def get_logs():
#    logs = []
#
#    basepath = app.config['LOGDIR']
#
#    rule = re.compile('^strapper-(\d\d\d\d-\d\d-\d\d).log$')
#
#    if os.path.isdir(basepath):
#        for filename in os.listdir(basepath):
#            res = rule.match(filename)
#            if res.group(1):
#                day = res.group(1)
#                logs.insert(0,day)
#            
#    return logs
#
## Return an array containing the log entries of a given date.
#def read_log(day):
#    log = []
#
#    # Input validation
#    if re.match("^\d\d\d\d-\d\d-\d\d$",day):
#
#        logfile = '%s/strapper-%s.log' \
#            % (app.config['LOGDIR'],day)
#
#        try:
#            f = open(logfile,"r")
#            for line in f:
#                log.insert(0,line)
#
#        except:
#            pass
#
#    return log
#
## Write a log entry. Levels should be DEBUG, INFO, WARNING or ERROR.
#def do_log(level,text):
#    now = datetime.datetime.now()
#    logfile = '%s/strapper-%s.log' \
#        % (app.config['LOGDIR'],now.strftime("%Y-%m-%d"))
#    remote_addr = cgi.escape(os.environ['REMOTE_ADDR'])
#
#    try:
#        f = open(logfile,"a+")
#        line = '%s %s %s %s\n' % (remote_addr, \
#            now.strftime("%Y-%m-%d %H:%M:%S"),level,text)
#        f.write(line)
#        f.close()
#
#    except:
#        return False
#
#    else:
#        return True
#
## Give MAC addresses nice formatting.
def clean_mac(mac):
    # Remove all uneccessary characters from the given mac address
    mac = re.sub('[^0-9a-fA-F]', '', mac)
    mac = mac.lower()

    # At this point, the mac address should be 12 characters
    if len(mac) == 12:
        mac = '%s-%s-%s-%s-%s-%s' % \
              (mac[0:2],mac[2:4],mac[4:6],mac[6:8],mac[8:10],mac[10:12])
        # At this point, the mac address should be 12+5 characters
    else:
        #syslog.syslog(syslog.LOG_ERR,"%s: The MAC address is not valid." % (mac))
        mac = False
    
    return mac

def get_ipxe_configuration(mac, permission, host):
    ipxe = False
    path = False
    status = False

    # If not permission, serve some exit-message
    if not permission:
        path = app.config['DEFAULT_NO_PERMISSION_IPXE_CONFIGURATION']
        status = 0

    else:
        # Check if the directory of this mac address exists to see if we have seen
        # this host before or not.
        d = app.config['STATE_DIR'] + '/' + mac
        if os.path.isdir(d):
            # Known host
            # Look for configuration, if none is found:
            if 'ipxe' in host:
                ipxe = host['ipxe']
                status = 3
            else:
                path = app.config['DEFAULT_KNOWN_HOST_IPXE_CONFIGURATION']
                status = 2
        else:
            # Unknown host
            path = app.config['DEFAULT_UNKNOWN_HOST_IPXE_CONFIGURATION']
            status = 1

    if not ipxe and path:
        if os.path.exists(path):
            try:
                f = open(path, 'r')

            except:
                print "Unable to open file %s for reading." % (path)

            else:
                ipxe = f.read()
                f.close()

    return (status,ipxe)

def get_data(path, ts = False):
    if not os.path.isdir(path):
        return False

    f = re.compile("^(\d+)\.json$")

    if not ts:
        ts = 0
        for entry in os.listdir(path):
            i = path + '/' + entry
            m = f.match(entry)
            if os.path.isfile(i) and m:
                this_ts = int(m.group(1))
                if this_ts > ts:
                    ts = this_ts

    filepath = path + '/' + str(ts) + '.json'
    if not os.path.isfile(filepath):
        print "File %s does not exist" % filepath
        return False

    try:
        f = open(filepath,'r')
    except:
        print "Unable to open file %s for reading" % filepath
    else:
         try:
             content = json.loads(f.read())

         except:
             print "Unable to read and/or decode content in %s" % filepath

         else:
             return content

    return False

# Let's see if this host with mac, uuid and remote_addr is allowed to get configuration
def get_permission(host, mac, uuid, remote_addr):
    if 'mac' in host:
        if mac != host['mac']:
            return False

    if 'uuid' in host:
        if uuid != host['uuid']:
            return False

    if 'remote_addr' in host:
        if remote_addr != host['remote_addr']:
            return False

    return True

def get_host_configuration(mac, uuid = False, remote_addr = False):
    data = {}
    path = app.config['HOST_DIR'] + '/' + mac

    if os.path.isdir(path):
        # Known host
        data = get_data(path)

    else:
        # Unknown host, create a default here with lockdown
        data['mac'] = mac
        data['uuid'] = uuid
        data['remote_addr'] = remote_addr

        now = datetime.datetime.now()
        ts = dt_to_timestamp(now)

        data['registered'] = now.strftime("%Y-%m-%d %H:%M:%S")
        if not os.path.exists(path):
            os.makedirs(path,0700)

        status = False
        filepath = '%s/%s.json' % (path, ts)
        content = json.dumps(data, indent=4, sort_keys=True)

        try:
            f = open(filepath,'w+')
            f.write(content)
            f.close()

        except:
            print "Unable to write host file (%s)." % (filepath)

        else:
            status = True
            print "Host file written (%s)." % (filepath)

    return data

def get_revisions(path):
    f = re.compile("^(\d+)\.json$")
    revisions = []
    if os.path.isdir(path):
        for i in os.listdir(path):
            filepath = path + "/" + i
            m = f.match(i)
            if os.path.isfile(filepath) and m:
                ts = int(m.group(1))
                revisions.append(ts)
    revisions.sort()
    revisions.reverse()
    return revisions
        
def get_all_mac_addresses():
    path = app.config['STATE_DIR']
    macs = []
    if os.path.isdir(path):
        for mac in os.listdir(path):
            p = path + "/" + mac
            if os.path.isdir(p):
                macs.append(mac)
    return macs

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

def get_boot_history(mac):
    history = []
    path = app.config['STATE_DIR'] + '/' + mac
    revisions = get_revisions(path)
    now = datetime.datetime.now()
    for ts in revisions:
        data = get_data(path, ts=ts)
        dt = timestamp_to_dt(ts)
        data['age'] = humanize_date_difference(dt,now)
        history.append(data)

    return history

def get_last_boot_requests(count, mac = False, status = False):
    entries = []
    macs = []
    if mac:
        macs.append(mac)
    else:
        macs = get_all_mac_addresses()

    for mac in macs:
        history = get_boot_history(mac)
        for i in history:
            if status == False:
                entries.append(i)
            else:
                if i['status'] == int(status):
                    entries.append(i)

    ret = sorted(entries, key=lambda k: (-k['ts']))
 
    if count:
        return ret[0:count]
    else:
        return ret

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
    known = get_last_boot_requests(5)
    unknown = get_last_boot_requests(5, status = 1)
    return flask.render_template("index.html", title = "Overview", \
        active = "overview", unknown = unknown, known = known)

@app.route("/boot-history/")
@app.route("/boot-history")
def boot_history():
    status = flask.request.args.get('status', False)
    mac = flask.request.args.get('mac', False)
    entries = get_last_boot_requests(False, mac = mac, status = status)

    return flask.render_template("boot-history.html", title = "Boot history", \
        active = "history", entries = entries, mac = mac, status = status)

@app.route("/mac/<mac>")
@app.route("/mac/<mac>/")
def mac(mac):
    return flask.redirect('/mac/%s/history' % mac)

@app.route("/mac/<mac>/configuration")
def mac_configuration(mac):
    mac = clean_mac(mac)
    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    host = get_host_configuration(mac)
    host['reverse'] = get_reverse_address(host['remote_addr'])

    return flask.render_template("mac_configuration.html", \
        title = "%s configuration" % mac, mac = mac, \
        active = "configuration", host = host)

@app.route("/mac/<mac>/history")
def mac_history(mac):
    mac = clean_mac(mac)
    if not mac:
        return flask.make_response("The given mac address is not valid", 400)

    status = flask.request.args.get('status', False)
    entries = get_last_boot_requests(False, mac = mac, status = status)

    if mac:
        title = "%s boot history" % mac
    else:
        title = "Boot history"

    return flask.render_template("boot-history.html", title = title, \
        active = "history", entries = entries, mac = mac, status = status)

@app.route("/about/")
@app.route("/about")
def about():
    return flask.render_template("about.html", title = "About", \
       active = "about")

@app.route("/bootstrap/mac-<mac>.ipxe")
def bootstrap(mac):
    mac = clean_mac(mac)
    h = {'content-type' : 'text/plain'}

    if not mac:
        return flask.make_response("The given mac address is not valid", 400, h)

    # Store the UUID if sent by the client
    uuid = flask.request.args.get('uuid', False)

    # Read the source IP address of the request
    remote_addr = flask.request.environ.get('REMOTE_ADDR', False)

    # Get host configuration
    host = get_host_configuration(mac, uuid, remote_addr)

    # Let's see if this host with mac, uuid and remote_addr is allowed to get configuration
    permission = get_permission(host, mac, uuid, remote_addr)

    # If permission is granted, get configuration:
    (status, ipxe) = get_ipxe_configuration(mac, permission, host)

    data = {}
    data['ipxe']        = ipxe
    data['uuid']        = uuid
    data['remote_addr'] = remote_addr
    data['status']      = status

    reverse = get_reverse_address(remote_addr)
    if reverse:
        data['reverse'] = reverse
        data['domain'] = extract_domain_from_fqdn(reverse)

    if not save_state(mac, data):
        print "Unable to write state for MAC " + mac
        return flask.make_response("Unable to write state for MAC %s" % (mac), 500, h)

    return flask.make_response(ipxe, 200, h)

#@app.route("/group/<group>")
#def group(group):
#    nodegroup = get_nodegroup(group)
#    return render_template("group.html", nodegroup = nodegroup, group = group)
#
#@app.route("/images")
#def images():
#    images = get_images_and_releases()
#    return render_template("images.html", images = images)
#
#@app.route("/log/<day>")
#def log(day):
#    log = read_log(day)
#    return render_template('log.html', log = log, day = day)
#
#@app.route("/logs")
#def logs():
#    logs = get_logs()
#    return render_template('logs.html', logs = logs)
#
## Print the boot scripts to the nodes
#@app.route("/boot/<mac>")
#def boot(mac):
#    script = False
#
#    # Make sure the specified mac address is clean
#    mac = clean_mac(mac)
#
#    if mac:
#        syslog.syslog(syslog.LOG_ERR,"Boot request from %s received." % (mac))
#
#    if mac:
#        # Fetch the active boot script for this mac address
#        script = get_boot_script(mac)
#
#    response = make_response(render_template('boot.html', script = script))
#    response.headers['content-type'] = 'text/plain'
#    return response
#
#@app.route("/setrelease/<mac>", methods = ['POST','GET'])
#def setrelease(mac):
#    data = False
#    success = False
#    releases = False
#    mac = clean_mac(mac)
#    data = read_data(mac)
#
#    if request.method == 'POST':
#        try:
#            release = request.form['release']
#
#            # Input validation
#            re.match("^[0-9a-zA-z-_\.]+$",release)
#
#        except:
#            release = False
#
#        else:
#            try:
#                image = data['image']
#
#            except:
#                pass
#
#            else:
#                releases = get_image_releases(image)
#                if release in releases:
#                    data['release'] = release
#                    if save_data(mac,data):
#                        do_log("INFO","Release changed to %s for MAC %s" \
#                            % (release,mac))
#                        success = True
#
#    else:
#        try:
#            data['image']
#
#        except:
#            pass
#
#        else:
#            releases = get_image_releases(data['image'])
#
#    try:
#        reverse = socket.gethostbyaddr(data['remote_addr'])[0]
#        group = extract_nodegroup_from_fqdn(reverse)
#
#    except:
#        pass
#
#    else:
#        data['reverse'] = reverse
#        data['group'] = group
#
#    return render_template('setrelease.html', data = data, mac = mac, \
#       releases = releases, method = request.method, success = success)
#
#@app.route("/setimage/<mac>", methods = ['POST','GET'])
#def setimage(mac):
#    data = False
#    images = False
#    success = False
#    mac = clean_mac(mac)
#    data = read_data(mac)
#    images = get_images()
#
#    if request.method == 'POST':
#        try:
#            image = request.form['image']
#
#            # Input validation
#            re.match("^[0-9a-zA-z-_\.]+$",image)
#
#        except:
#            image = False
#
#        else:
#            if image in images:
#                data['image'] = image
#                data['release'] = False
#
#                if save_data(mac,data):
#                    do_log("INFO","Image changed to %s for MAC %s" \
#                        % (image,mac))
#                    success = True
#
#    try:
#        reverse = socket.gethostbyaddr(data['remote_addr'])[0]
#        group = extract_nodegroup_from_fqdn(reverse)
#
#    except:
#        pass
#
#    else:
#        data['reverse'] = reverse
#        data['group'] = group
#
#    return render_template('setimage.html', data = data, mac = mac, \
#       images = images, method = request.method, success = success)
#
#@app.route("/node/<mac>")
#def node(mac):
#    script = False
#    data = False
#
#    # Make sure the specified mac address is clean
#    mac = clean_mac(mac)
#
#    if mac:
#        # Fetch the active boot script for this mac address
#        data = read_data(mac)
#        try:
#            reverse = socket.gethostbyaddr(data['remote_addr'])[0]
#            group = extract_nodegroup_from_fqdn(reverse)
#
#        except:
#            pass
#
#        else:
#            data['reverse'] = reverse
#            data['group'] = group
#            images = get_images()
#
#            try:
#                data['image']
#
#            except:
#                releases = False
#
#            else:
#                releases = get_image_releases(data['image'])
#
#    return render_template('node.html', data = data, mac = mac, \
#       images = images, releases = releases)
    
if __name__ == '__main__':
    app.run(host='0.0.0.0')

