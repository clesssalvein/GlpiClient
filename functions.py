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


# detect already running app

from win32event import CreateMutex
from win32api import CloseHandle, GetLastError
from winerror import ERROR_ALREADY_EXISTS

class singleinstance:
    """ Limits application to single instance """

    def __init__(self):
        self.mutexname = "testmutex_{D0E858DF-985E-4907-B7FB-8D732C3FC3B9}"
        self.mutex = CreateMutex(None, False, self.mutexname)
        self.lasterror = GetLastError()

    def alreadyrunning(self):
        return (self.lasterror == ERROR_ALREADY_EXISTS)

    def __del__(self):
        if self.mutex:
            CloseHandle(self.mutex)


# unwrap already opened app's window

import win32gui
import re


# maximize app window,
# if you run new app and another app already run

class WindowMgr:
    #Encapsulates some calls to the winapi for window management

    def __init__ (self):
        # Constructor
        self._handle = None

    def find_window(self, class_name, window_name=None):
        # find a window by its class_name
        self._handle = win32gui.FindWindow(class_name, window_name)

    def _window_enum_callback(self, hwnd, wildcard):
        # Pass to win32gui.EnumWindows() to check all the opened windows
        if re.match(wildcard, str(win32gui.GetWindowText(hwnd))) is not None:
            self._handle = hwnd

    def find_window_wildcard(self, wildcard):
        # find a window whose title matches the wildcard regex
        self._handle = None
        win32gui.EnumWindows(self._window_enum_callback, wildcard)

    def set_foreground(self):
        # put the window in the foreground
        win32gui.SetForegroundWindow(self._handle)
        win32gui.ShowWindow(self._handle, 4)
