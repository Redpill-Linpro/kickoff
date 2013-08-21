#!/usr/bin/env python

import os
import cgi
import re
import syslog
import json
import socket
import datetime
from flask import Flask, g, render_template, Response, make_response, request

IMAGEDIR = '/var/www/pxeboot/'
VARDIR = '/var/lib/strapper/'
LOGDIR = '/var/log/strapper/'
DEBUG = True

app = Flask(__name__)
app.config.from_object(__name__)

# Return an array of the images available.
def get_images():
    images = []
    basepath = app.config['IMAGEDIR']
    if os.path.isdir(basepath):
        for image in os.listdir(basepath):
            if os.path.isdir('%s/%s' % (basepath,image)):
                 if len(get_image_releases(image)) > 0:
                     images.append(image)
            
    return images

# Return an array of the releases available for a spesific image.
def get_image_releases(image):
    releases = []
    basepath = '%s/%s' % (app.config['IMAGEDIR'],image)
    if os.path.isdir(basepath):
        for release in os.listdir(basepath):
            if os.path.isdir('%s/%s' % (basepath,release)):
                 if os.path.isfile('%s/%s/boot.pxe' % (basepath,release)):
                     releases.append(release)

    return releases

# Return a dict containing the releases (with files) of a spesific image.
def get_image_release(image,release):
    files = {}
    basepath = '%s/%s/%s' % (app.config['IMAGEDIR'],image,release)
    if os.path.isdir(basepath):
        for filename in os.listdir(basepath):
            files[filename] = {}

            filepath = '%s/%s' % (basepath,filename)
            if os.path.isfile(filepath):
                 stat=os.stat(filepath)

                 i={}
                 i['path'] = filepath
                 i['size'] = stat.st_size
                 i['mtime'] = stat.st_mtime
                 i['mtime_iso'] = datetime.datetime.fromtimestamp( \
                     stat.st_mtime).strftime("%Y-%m-%d %H:%S:%M")

                 files[filename]=i

    return files

# Return a default boot script.
def boot_script_on_error(mac):
    text="""#!ipxe
echo Unable to deliver the boot configuration for %s.
echo Will reboot in 60 seconds.
sleep 60
reboot
""" % (mac)
    return text

# Save the data for a spesific MAC address.
def save_data(mac,data):
    basepath = app.config['VARDIR']

    status = False

    now = datetime.datetime.now()
    data['saved'] = now.strftime("%Y%m%d%H%M%S")
    data['saved_iso'] = now.strftime("%Y-%m-%d %H:%M:%S")

    # Fix the structure
    i = {} 
    i[mac] = data

    if os.path.isdir(basepath):
        filepath = '%s/%s.json' % (basepath,mac)
        content = json.dumps(i, indent=2, sort_keys=False)

        if os.path.isfile(filepath):
            # The database entry file exists, which means this is a known MAC 
            # address.
            try:
                f = open(filepath,'w+')
                f.write(content)
                f.close()

            except:
                syslog.syslog(syslog.LOG_ERR,"%s: Unable to update the " \
                    "configuration file (%s). " % (mac,filepath))

            else:
                status = True
                syslog.syslog(syslog.LOG_INFO,"%s: Configuration updated. " % \
                    (mac))

        else:
            # The database entry file does not exist, which means that this
            # is the first time this strapper receives a boot request from
            # this MAC address.
            try:
                f = open(filepath,'w')
                f.write(content)
                f.close()

            except:
                syslog.syslog(syslog.LOG_ERR,"%s: Unable to create the " \
                    "configuration file (%s). " % (mac,filepath))

            else:
                status = True
                syslog.syslog(syslog.LOG_INFO,"%s: Configuration created. " % \
                    (mac))

    else:
        syslog.syslog(syslog.LOG_ERR,"%s: Unable to update configuration. " \
            "The var directory (%s) does not exist." % (mac,basepath))

    return status

# Read the data for a spesific MAC address. Return a dict with the data.
def read_data(mac):
    data = {}
    basepath = app.config['VARDIR']
    if os.path.isdir(basepath):
        filepath = '%s/%s.json' % (basepath,mac)
        if os.path.isfile(filepath):
            f = open(filepath,'r')
            if f:
                 try:
                     content = json.loads(f.read())

                 except:
                     syslog.syslog(syslog.LOG_ERR,"%s: Unable to decode json " \
                         "in %s." % (mac,filepath))

                 else:
                     if mac in content:
                         data = content[mac]

                     else:
                         syslog.syslog(syslog.LOG_ERR,"%s: Something " \
                             "uncool happened." % (mac))

        else:
            do_log("INFO","Discovered a new node with MAC %s" % (mac))
            syslog.syslog(syslog.LOG_ERR,"%s: Configuration not found " \
                "(%s)." % (mac,filepath))
    
    return data

# Return a dict containing all images and releases available.
def get_images_and_releases():
    ret = {}

    images = get_images()
    for image in images:
        ret[image] = {}
        releases = get_image_releases(image)

        for release in releases:
            ret[image][release] = get_image_release(image,release)

    return ret

# Return an array of all MAC addresses known by the strapper.
def get_all_known_macs():
    macs = []
    basepath = '%s' % (app.config['VARDIR'])

    if os.path.isdir(basepath):
        for m in os.listdir(basepath):
            filepath = '%s/%s' % (app.config['VARDIR'],m)
            if os.path.isfile(filepath):
                try:
                    f = open(filepath,'r')
                    content = json.loads(f.read())

                except:
                    syslog.syslog(syslog.LOG_ERR,"Unable to read " \
                        "configuration file (%s)." % (filepath))

                else:
                    if len(content) == 1:
                        # Add the MAC address to the array
                        macs.append(content.keys()[0])

    return macs

# Return the active boot script for a spesific MAC address.
def get_boot_script(mac):

    # Serve some default script
    script = boot_script_on_error(mac)

    data = read_data(mac)

    success = False

    try:
        image = data['image']
        release = data['release']

    except:
        syslog.syslog(syslog.LOG_ERR,"%s: Unable to read image and release from the database. MAC is not configured." % (mac))

    else:
        syslog.syslog(syslog.LOG_INFO,"%s: Will serve image %s, release %s." % (mac,image,release))

        basepath = '%s/%s/%s' % (app.config['IMAGEDIR'],image,release)
        bootfile = '%s/boot.pxe' % (basepath)

        if os.path.isfile(bootfile):
            try:
                f = open(bootfile,'r')

            except:
                syslog.syslog(syslog.LOG_ERR,"%s: Unable to read boot " \
                    "configuration file (%s)." % (mac,bootfile))

            else:
                script = f.read()
                f.close()
                success = True
                do_log("INFO","Boot configuration (%s, %s) served to %s" \
                    % (image, release, mac))

        else:
            syslog.syslog(syslog.LOG_ERR,"%s: Boot configuration file " \
                "(%s) was not found." % (mac,bootfile))

    # Boot counter
    try:
        count = data['bootcount']

    except:
        data['bootcount'] = 1

    else:
        data['bootcount'] = int(count) + 1

    data['lastbootscript'] = script
    data['success'] = success

    now = datetime.datetime.now()
    data['lastboot'] = now.strftime("%Y%m%d%H%M%S")
    data['lastboot_iso'] = now.strftime("%Y-%m-%d %H:%M:%S")

    data['remote_addr'] = cgi.escape(os.environ['REMOTE_ADDR'])

    if not save_data(mac,data):
        syslog.syslog(syslog.LOG_ERR,"%s: Unable to save data." % (mac))

    return script

# Use the DNS PTR to create logical groups of nodes. This method converts fqdn
# to group name.
def extract_nodegroup_from_fqdn(fqdn):
    group = False
    rule = re.compile('^[^\.]+\.(.*)')
    res = rule.search(fqdn)
    if res:
        if res.group(1):
            group = res.group(1)

    return group

def get_nodegroup(group):
    macs = get_all_known_macs()

    ret = {}

    for mac in macs:
        data = read_data(mac)
        try:
            remote_addr = data['remote_addr']
 
        except:
            pass

        else:
            try:
                reverse = socket.gethostbyaddr(remote_addr)[0]

            except:
                syslog.syslog(syslog.LOG_ERR,"%s: Unable to reverse lookup %s" \
                    % (mac,remote_addr))

            else:
                data['reverse'] = reverse
                this_group = extract_nodegroup_from_fqdn(reverse)
                if group == this_group:
                    ret[mac] = data

    return ret

def get_nodegroups():
    macs = get_all_known_macs()

    data = {}
    nodegroups = {}

    rule = re.compile('^[^\.]+\.(.*)')

    for mac in macs:
        data[mac] = read_data(mac)
        try:
            remote_addr = data[mac]['remote_addr']
 
        except:
            pass

        else:
            try:
                reverse = socket.gethostbyaddr(remote_addr)[0]

            except:
                syslog.syslog(syslog.LOG_ERR,"%s: Unable to reverse lookup %s" \
                    % (mac,remote_addr))

            else:
                res = rule.search(reverse)
                if res:
                    group = res.group(1)

                    if group in nodegroups:
                        nodegroups[group] += 1

                    else:
                        nodegroups[group] = 1

    return nodegroups

# Return an array containing the dates in which there are log entries.
def get_logs():
    logs = []

    basepath = app.config['LOGDIR']

    rule = re.compile('^strapper-(\d\d\d\d-\d\d-\d\d).log$')

    if os.path.isdir(basepath):
        for filename in os.listdir(basepath):
            res = rule.match(filename)
            if res.group(1):
                day = res.group(1)
                logs.insert(0,day)
            
    return logs

# Return an array containing the log entries of a given date.
def read_log(day):
    log = []

    # Input validation
    if re.match("^\d\d\d\d-\d\d-\d\d$",day):

        logfile = '%s/strapper-%s.log' \
            % (app.config['LOGDIR'],day)

        try:
            f = open(logfile,"r")
            for line in f:
                log.insert(0,line)

        except:
            pass

    return log

# Write a log entry. Levels should be DEBUG, INFO, WARNING or ERROR.
def do_log(level,text):
    now = datetime.datetime.now()
    logfile = '%s/strapper-%s.log' \
        % (app.config['LOGDIR'],now.strftime("%Y-%m-%d"))
    remote_addr = cgi.escape(os.environ['REMOTE_ADDR'])

    try:
        f = open(logfile,"a+")
        line = '%s %s %s %s\n' % (remote_addr, \
            now.strftime("%Y-%m-%d %H:%M:%S"),level,text)
        f.write(line)
        f.close()

    except:
        return False

    else:
        return True

# Give MAC addresses nice formatting.
def clean_mac(mac):
    # Remove all uneccessary characters from the given mac address
    mac = re.sub('[^\d\w]', '', mac)

    # At this point, the mac address should be 12 characters
    if len(mac) == 12:
        mac = '%s-%s-%s-%s-%s-%s' % \
              (mac[0:2],mac[2:4],mac[4:6],mac[6:8],mac[8:10],mac[10:12])
        # At this point, the mac address should be 12+5 characters
    else:
        syslog.syslog(syslog.LOG_ERR,"%s: The MAC address is not valid." % (mac))
        mac = False
    
    return mac

@app.route("/")
def index():
    nodegroups = get_nodegroups()
    return render_template("index.html", nodegroups = nodegroups)

@app.route("/group/<group>")
def group(group):
    nodegroup = get_nodegroup(group)
    return render_template("group.html", nodegroup = nodegroup, group = group)

@app.route("/images")
def images():
    images = get_images_and_releases()
    return render_template("images.html", images = images)

@app.route("/log/<day>")
def log(day):
    log = read_log(day)
    return render_template('log.html', log = log, day = day)

@app.route("/logs")
def logs():
    logs = get_logs()
    return render_template('logs.html', logs = logs)

# Print the boot scripts to the nodes
@app.route("/boot/<mac>")
def boot(mac):
    script = False

    # Make sure the specified mac address is clean
    mac = clean_mac(mac)

    if mac:
        syslog.syslog(syslog.LOG_ERR,"Boot request from %s received." % (mac))

    if mac:
        # Fetch the active boot script for this mac address
        script = get_boot_script(mac)

    response = make_response(render_template('boot.html', script = script))
    response.headers['content-type'] = 'text/plain'
    return response

@app.route("/setrelease/<mac>", methods = ['POST','GET'])
def setrelease(mac):
    data = False
    success = False
    releases = False
    mac = clean_mac(mac)
    data = read_data(mac)

    if request.method == 'POST':
        try:
            release = request.form['release']

            # Input validation
            re.match("^[0-9a-zA-z-_\.]+$",release)

        except:
            release = False

        else:
            try:
                image = data['image']

            except:
                pass

            else:
                releases = get_image_releases(image)
                if release in releases:
                    data['release'] = release
                    if save_data(mac,data):
                        do_log("INFO","Release changed to %s for MAC %s" \
                            % (release,mac))
                        success = True

    else:
        try:
            data['image']

        except:
            pass

        else:
            releases = get_image_releases(data['image'])

    try:
        reverse = socket.gethostbyaddr(data['remote_addr'])[0]
        group = extract_nodegroup_from_fqdn(reverse)

    except:
        pass

    else:
        data['reverse'] = reverse
        data['group'] = group

    return render_template('setrelease.html', data = data, mac = mac, \
       releases = releases, method = request.method, success = success)

@app.route("/setimage/<mac>", methods = ['POST','GET'])
def setimage(mac):
    data = False
    images = False
    success = False
    mac = clean_mac(mac)
    data = read_data(mac)
    images = get_images()

    if request.method == 'POST':
        try:
            image = request.form['image']

            # Input validation
            re.match("^[0-9a-zA-z-_\.]+$",image)

        except:
            image = False

        else:
            if image in images:
                data['image'] = image
                data['release'] = False

                if save_data(mac,data):
                    do_log("INFO","Image changed to %s for MAC %s" \
                        % (image,mac))
                    success = True

    try:
        reverse = socket.gethostbyaddr(data['remote_addr'])[0]
        group = extract_nodegroup_from_fqdn(reverse)

    except:
        pass

    else:
        data['reverse'] = reverse
        data['group'] = group

    return render_template('setimage.html', data = data, mac = mac, \
       images = images, method = request.method, success = success)

@app.route("/node/<mac>")
def node(mac):
    script = False
    data = False

    # Make sure the specified mac address is clean
    mac = clean_mac(mac)

    if mac:
        # Fetch the active boot script for this mac address
        data = read_data(mac)
        try:
            reverse = socket.gethostbyaddr(data['remote_addr'])[0]
            group = extract_nodegroup_from_fqdn(reverse)

        except:
            pass

        else:
            data['reverse'] = reverse
            data['group'] = group
            images = get_images()

            try:
                data['image']

            except:
                releases = False

            else:
                releases = get_image_releases(data['image'])

    return render_template('node.html', data = data, mac = mac, \
       images = images, releases = releases)
    
if __name__ == '__main__':
    app.run(host='0.0.0.0')

