#!/usr/bin/python

import json
import os
import sys
import subprocess

###############################################################################
# Constants
###############################################################################
MSG_CRITICAL = "CRITICAL"
MSG_DEBUG = "DEBUG"
MSG_INFO = "INFO"
MSG_ERROR = "ERROR"
MSG_WARNING = "WARNING"
TMP_DIR = "/tmp"
#resource files
OPENDJ_FILE = "gluu-opendj-2.6.0.zip"
SCHEMA_100 = '100-user.ldif'
SCHEMA_101 = '101-ox.ldif'
SCHEMA_96 = '96-eduPerson.ldif'
DEFAULT_LDAP_DATA = 'generated-data.ldif'
PORT = '1389'
ADMIN_PORT = '4444'
LOCALHOST = 'localhost'
BASEDN = 'o=gluu'

APT_PACKAGES = ["openjdk-7-jre-headless", "unzip"]

###############################################################################
# Functions
###############################################################################
#log function
def juju_log(level, msg):
    subprocess.call(['juju-log', '-l', level, msg])

#update apt
def apt_get_update():
    cmd_line = ['apt-get', 'update']
    return subprocess.call(cmd_line)

#oepn a port
def open_port(port=None, protocol="TCP"):
    if port is None:
        return None
    return subprocess.call(['open-port', "%d/%s" % (int(port), protocol)])

#close port
def close_port(port=None, protocol="TCP"):
    if port is None:
        return None
    return subprocess.call(['close-port', "%d/%s" % (int(port), protocol)])

#get config
def config_get(scope=None):
    try:
        config_cmd_line = ['config-get']
        if scope is not None:
            config_cmd_line.append(scope)
        config_cmd_line.append('--format=json')
        data = json.loads(subprocess.check_output(config_cmd_line))
    except:
        data = None
    finally:
        return data

#run any command
def run(command, exit_on_error=True, cwd=None):
    try:
        juju_log(MSG_DEBUG, command)
        return subprocess.check_output(
            command, stderr=subprocess.STDOUT, shell=True, cwd=cwd)
    except subprocess.CalledProcessError, e:
        juju_log(MSG_ERROR, "status=%d, output=%s" % (e.returncode, e.output))
        if exit_on_error:
            sys.exit(e.returncode)
        else:
            raise

#install apt packages
def apt_get_install(packages=None):
    if packages is None:
        return False
    cmd_line = ['apt-get', '-y', 'install', '-qq']
    if isinstance(packages, list):
        cmd_line.extend(packages)
    else:
        cmd_line.append(packages)
    return subprocess.call(cmd_line)

#render a file using template and writes it
def process_template(template_name, template_vars, destination):
    tmpl_file_path = get_template(template_name)
    with open(tmpl_file_path, 'r') as fp:
        tmpl = fp.read()
    with open(destination, 'w') as inject_tmpl:
        inject_tmpl.write(tmpl.format(**template_vars))

def get_resource(resource_name):
    return os.path.join(charm_root_dir, "resources", resource_name)

def get_template(template_name):
    return os.path.join(charm_root_dir, "templates", template_name)

def get_unit_host():
    this_host = run("unit-get private-address")
    return this_host.strip()

def relation_set(keyvalues, relation_id=None):
    args = []
    if relation_id:
        args.extend(['-r', relation_id])
    args.extend(["{}='{}'".format(k, v or '') for k, v in keyvalues.items()])
    run("relation-set {}".format(' '.join(args)))

def relation_get(scope=None, unit_name=None, relation_id=None):
    j = relation_json(scope, unit_name, relation_id)
    if j:
        return json.loads(j)
    else:
        return None

def relation_json(scope=None, unit_name=None, relation_id=None):
    command = ['relation-get', '--format=json']
    if relation_id is not None:
        command.extend(('-r', relation_id))
    if scope is not None:
        command.append(scope)
    else:
        command.append('-')
    if unit_name is not None:
        command.append(unit_name)
    output = subprocess.check_output(command, stderr=subprocess.STDOUT)
    return output or None

# oprndj functions
def restart():
    run(opendj_home + "/bin/stop-ds --restart --quiet")

def setup(config):
    juju_log(MSG_DEBUG, "start config of opendj")
    run(opendj_home + '/setup --cli --doNotStart --baseDN {0} \
        --hostname {3} --ldapPort {2} --ldapsPort {5} --adminConnectorPort {4} \
        --rootUserDN "cn=Directory Manager" --rootUserPassword {1} \
        --no-prompt --noPropertiesFile --generateSelfSignedCertificate'.
        format(BASEDN, config['password'],
            config['ldap-port'], LOCALHOST, ADMIN_PORT, config['ldaps-port']))

def desconfig(config):
    run(opendj_home +
        '/bin/dsconfig set-global-configuration-prop \
        -h {0} -p {1} --trustAll --no-prompt \
        -D "cn=Directory Manager" -w {2} \
        --set single-structural-objectclass-behavior:accept'.
        format(LOCALHOST, ADMIN_PORT, config['password']))
    run(opendj_home +
        '/bin/dsconfig -h {0} -p {1} --trustAll --no-prompt \
        -D "cn=Directory Manager" -w {2} set-password-policy-prop \
        --policy-name "Default Password Policy" \
        --set allow-pre-encoded-passwords:true'.
        format(LOCALHOST, ADMIN_PORT, config['password']))
    run(opendj_home +
        '/bin/dsconfig set-backend-prop --backend-name userRoot \
        --add base-dn:{0} -h {1} -p {2} -D "cn=Directory Manager" \
        -w {3} --trustAll --noPropertiesFile --no-prompt'.
        format(BASEDN, LOCALHOST, ADMIN_PORT, config['password']))

def load_data(config, data_file):
    run(opendj_home +
        '/bin/ldapmodify -h {0} -D "cn=Directory Manager" \
        -w {2} -p {1} -a -f {3}'.
        format(LOCALHOST, config['ldap-port'],
                    config['password'], data_file))

def delete_all_entry(config):
    run(opendj_home + '/bin/ldapdelete -h {0} -D "cn=Directory Manager" \
        -p {1} -w {2} -x "{3}"'.format(LOCALHOST,
            config['ldap-port'], config['password'], BASEDN))

###############################################################################
# Hook functions
###############################################################################
def install():
    juju_log(MSG_DEBUG, "start apt-get install packages")
    apt_get_update()
    apt_get_install(APT_PACKAGES)
    juju_log(MSG_DEBUG, "unzip opendj to /opt")
    run('rm -rf ' + opendj_home)
    run("unzip -qq {0} -d /opt".format(get_resource(OPENDJ_FILE)))
    setup(config_data)
    #putting schemas
    run("cp {0} {1}".format(get_resource(SCHEMA_100), schema_path))
    run("cp {0} {1}".format(get_resource(SCHEMA_101), schema_path))
    run("cp {0} {1}".format(get_resource(SCHEMA_96), schema_path))
    #install init.d script
    run("cp {0} /etc/init.d/opendj".format(get_template("opendj.tmpl")))
    run("chmod 755 /etc/init.d/opendj")
    run("update-rc.d opendj defaults")
    #save password
    run("mkdir -p /opt/etc")
    with open("/opt/etc/password", 'w') as fp:
        fp.write(config_data['password'])
    #load default data
    run(opendj_home + "/bin/start-ds --quiet")
    desconfig(config_data)
    data = get_resource(DEFAULT_LDAP_DATA)
    load_data(config_data, data)
    run(opendj_home + "/bin/stop-ds --quiet")

def config_changed():
    if config_data['ldap-data'] != "":
        run("echo " + config_data['ldap-data'] +
            " | base64 -d > " + "/tmp/ldap-data.ldif")
        data = '/tmp/ldap-data.ldif'
        load_data(config_data, data)
        run("rm -f /tmp/ldap-data.ldif")
    #change password
    with open("/opt/etc/password",'r') as fp:
        old_password = fp.read()
    if config_data['password'] != old_password:
        #TODO change opendjpass
        run(opendj_home + '/bin/ldappasswordmodify -h {} -p {} \
            --authzID "dn:cn=Directory Manager" --currentPassword {} \
            --newPassword {}'.format(LOCALHOST, config_data['ldap-port'],
                old_password, config_data['password']))
        with open("/opt/etc/password", 'w') as wfp:
            wfp.write(config_data['password'])
    #TODO: change port (maybe)

def start():
    open_port(config_data['ldaps-port'])
    run(opendj_home + "/bin/start-ds --quiet")
    #desconfig(config_data)

def stop():
    run(opendj_home + "/bin/stop-ds --quiet")
    close_port(config_data['ldaps-port'])
    run("rm -rf " + opendj_home)
    run("update-rc.d -f opendj remove")
    run("rm -f /etc/init.d/opendj")

def upgrade():
    pass

def opendjserver_relation_joined():
    juju_log(MSG_INFO, "#opendjserver relation joined called in gluuldap")
    juju_log(MSG_INFO, "serverhost : " + get_unit_host())
    juju_log(MSG_INFO, "serverport : " + str(config_data["ldaps-port"]))
    relation_set({
                    'ldapserver' : 'gluuldap',
                    'hostname'   : get_unit_host(),
                    'port'       : config_data["ldaps-port"],
                    'port1389'   : config_data["ldap-port"],
                    'basedn'     : BASEDN,
                    'password'   : config_data["password"],
    })
    #insert default data
    #data = get_resource(DEFAULT_LDAP_DATA)
    #load_data(config_data, data)

def opendjserver_relation_changed():
    juju_log(MSG_INFO, "#opendjserver relation changed called in gluuldap")

def opendjserver_relation_broken():
    juju_log(MSG_INFO, "#opendjserver relation broken called in gluuldap")

def opendjserver_relation_departed():
    juju_log(MSG_INFO, "#opendjserver relation departed called in gluuldap")
    #delete_all_entry(config_data)
    run(opendj_home + "/bin/ldapdelete -h {} -D \"cn=Directory Manager\" -p {} -w {} -x 'inum=@!1111!0008!1234!1234,ou=clients,o=@!1111,o=gluu'".format(LOCALHOST, config_data['ldap-port'], config_data['password']))
    run(opendj_home + "/bin/ldapdelete -h {} -D \"cn=Directory Manager\" -p {} -w {} -x 'ou=oxTrust,ou=configuration,o=@!1111,o=gluu'".format(LOCALHOST, config_data['ldap-port'], config_data['password']))
    run(opendj_home + "/bin/ldapdelete -h {} -D \"cn=Directory Manager\" -p {} -w {} -x 'ou=oxAuth,ou=configuration,o=@!1111,o=gluu'".format(LOCALHOST, config_data['ldap-port'], config_data['password']))



###############################################################################
# Global variables
###############################################################################
hook_name = os.path.basename(sys.argv[0])
charm_root_dir = os.environ['CHARM_DIR']
opendj_home = '/opt/opendj'
schema_path = opendj_home + '/config/schema'

config_data = config_get()

###############################################################################
# Main section
###############################################################################
def main():
    juju_log(MSG_INFO, "Running {} hook".format(hook_name))
    fnmap = {
        'install' : install,
        'start' : start,
        'stop' : stop,
        'config-changed' : config_changed,
        'upgrade-charm' : upgrade,
        'opendjserver-relation-joined' : opendjserver_relation_joined,
        'opendjserver-relation-changed' : opendjserver_relation_changed,
        'opendjserver-relation-broken' : opendjserver_relation_broken,
        'opendjserver-relation-departed' : opendjserver_relation_departed,
    }
    if hook_name in fnmap:
        fnmap[hook_name]()
    else:
        print "Unknown hook {}".format(hook_name)
        juju_log(MSG_WARNING, "Unknown hook {}".format(hook_name))
        raise SystemExit(1)


if __name__ == '__main__':
    raise SystemExit(main())

