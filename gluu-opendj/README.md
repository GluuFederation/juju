# Overview

This charm will deploy gluu-opendj LDAP server.

# Usage

    juju deploy gluu-opendj

# Configuration

ldap-data : this configuration variable can be used to inserd custome data into
gluu-opendj server. the data must be a base64 encoded string.
    example: juju set gluu-opendj "ldap-data=$(base64 < ldap-data.ldif)”

password : this configuration variable is for setting/changing gluu-opendj
password. 
    example: juju set gluu-opendj password=mysecret
note: if gluu-opendj in a relation with other charm you must remove the
relation first, than change password, then add relation again.

ldap-port: gluu-opendj default port
ldaps-port: gluu-opendj default secure port
for now (will update soon) if you want to change default port you must do it
before deployment. you can change this two variables using custome myconfig.yaml
file.
    example: juju deploy --config myconfig.yaml gluu-opendj

# Relation

The opendjserver relation with gluuldap interface sets this relation variables
when it joins a relation.

    hostname   : sets unit ip/dns address
    port       : sets gluu-opendj sucure port
    port1389   : sets gluu-opendj port
    basedn     : sets gluu-opendj server basedn
    password   : sets gluu-opendj server password

Note : genarally you do not need to expose this charm.
 
# Contact Information

shouro@gluu.org

