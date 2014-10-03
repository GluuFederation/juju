# Overview

This is a combination for apache mod modox and oxd server which connects to idps
and can protect a web app.

# Usage

To deploy:
        juju deploy gluu-apache

# Configuration

Set a log location of oxd server:
        juju set gluu-apache oxdlog='/var/log/oxd-server.log'

To protect a directory in apache2 server: 
        juju set gluu-apache addrel='{"dir":"app1","idp":"seed.gluu.org"}'

#Relation
it can make a relation to gluu-server
    juju add-relation gluu-server gluu-apache

# Contact Information

shouro@gluu.org
