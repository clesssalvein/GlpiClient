#!/usr/bin/python3
# -*- coding: utf-8 -*-


# MODULES

import configparser
import gettext


# VARS

appName = "GlpiClient"
appExeFile = "GlpiClient.exe"
appDirName = "GlpiClient"
appVersion = "0.304"
authorEmail = "clesssalvein@gmail.com"
appHomepage = "https://github.com/clesssalvein/GlpiClient"
sessionToken = None

# userPass enc, NOT FOR WinXP
# encKey = "SCfeRgVZprA9IEgnA8UnilYVhnSV_HW2hW0tspwAVDI="

# config.ini read
config = configparser.ConfigParser()
configFileName = "config.ini"
configPath = "config/config.ini"
config.read(configPath, encoding="utf8")
glpiApiBaseUrl = config.get("main", "glpiApiBaseUrl")
appToken = config.get("main", "appToken")
appLang = config.get("main", "lang")
hideAppWindowToTrayAtStartup = config.get("main", "hideappwindowtotrayatstartup")

# gettext multilang
langDirsPath = "lang/i18n"
translate = gettext.translation('glpiClient', langDirsPath, languages=[appLang])

# auth.ini create, if doesn't exist
configAuthPath = "config/auth.ini"

# create dir "update", if not exist
updateDirPath = "./update"

# ftp server data
ftpServerHost = config.get("ftp", "ftpserverhost")
ftpServerPort = config.get("ftp", "ftpserverport")
ftpServerUser = config.get("ftp", "ftpserveruser")
ftpServerPass = config.get("ftp", "ftpserverpass")

# update options
updaterExeFile = "Updater.exe"
appAutoUpdate = config.get("main", "autoupdate")
updateDirPath = "./update/"
updateAppDirPath = "./update/GlpiClient/"
updateConfigDirPath = "./update/GlpiClient/config/"
ftpPath = "/data/"
appNameZip = "GlpiClient.zip"
