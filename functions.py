#!/usr/bin/python3
# -*- coding: utf-8 -*-


# MODULES

from vars import *

import requests
import socket
import logging
import platform
from ftplib import FTP
from io import BytesIO


# gettext multilang
_ = translate.gettext
translate.install()


# get client app IP
def clientIpGet():
    global clientIp
    try:
        clientIp = socket.gethostbyname(socket.gethostname())
    except Exception as e:
        print("Fail to get PC IP")
        logging.error('Error at %s', 'division', exc_info=e)
        pass

    return clientIp


# get client app HOSTNAME
def clientHostnameGet():
    global clientHostname
    try:
        clientHostname = platform.node()
    except Exception as e:
        print("Fail to get PC hostname")
        logging.error('Error at %s', 'division', exc_info=e)
        pass

    return clientHostname


# get actual version of glpiclient
def appVersionCheck():
    global appVersionActual

    try:
        # ftp connect
        ftp = FTP()
        ftp.connect(ftpServerHost, int(ftpServerPort))
        ftp.login(ftpServerUser, ftpServerPass)
        rAppVersion = BytesIO()

        # get remote app version - content of file
        ftp.retrbinary('RETR /data/app.version', rAppVersion.write)

        # convert app version - Bytes to Str
        appVersionActual = str(rAppVersion.getvalue(), 'utf-8')

        # debug
        print("Local app version: " + appVersion)
        print("Remote actual app version: " + appVersionActual)

        if (float(appVersion)) < (float(appVersionActual)):
            print("NEW Version ready!")
        else:
            print("There's no new version...")

        ftp.close()

    except Exception as e:
        print("Fail to connect to update server")
        logging.error('Error at %s', 'division', exc_info=e)
        appVersionActual = 0
        pass

    return appVersionActual


# get actual version of glpiclient
def remoteUpdateMarkerCheck():
    global remoteUpdateMarker

    try:
        # ftp connect
        ftp = FTP()
        ftp.connect(ftpServerHost, int(ftpServerPort))
        ftp.login(ftpServerUser, ftpServerPass)
        rUpdateMarker = BytesIO()

        # get remote UpdateMarker - content of file
        ftp.retrbinary('RETR /data/app.update-marker', rUpdateMarker.write)

        # convert UpdateMarker - Bytes to Str
        remoteUpdateMarker = str(rUpdateMarker.getvalue(), 'utf-8')

        # debug
        print("Remote update marker: " + remoteUpdateMarker)

        ftp.close()

    except Exception as e:
        print("Fail to connect to update server")
        logging.error('Error at %s', 'division', exc_info=e)
        remoteUpdateMarker = 0
        pass

    return remoteUpdateMarker


# KILL SESSION COMMON FUNC
def sessionKillCommon():

    # session kill for USER
    headersSessionKill = {'Content-Type': 'application/json',
                          'App-Token': appToken,
                          'Session-Token': sessionToken,
                          }

    # trying kill session on server
    try:
        responseSessionKill = requests.get(glpiApiBaseUrl + '/killSession', headers=headersSessionKill)

        # debug
        print("LOGOUT USER")

        # debug
        print(headersSessionKill)
        print(responseSessionKill.content.decode())

    # pass through if no connect to server
    except:
        pass

    return
