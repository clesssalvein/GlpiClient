#!/usr/bin/python3
# -*- coding: utf-8 -*-


# MODULES

from vars import *
from functions import *
import requests
import json
import base64
import os
from os import listdir
from os.path import isfile,join
import glob
import sys
import shutil
from distutils.dir_util import copy_tree
import logging
import random
import string
import ntpath
from time import strftime
import wget
import markdownify

#PIC ATTACH CODE
#doesn't work on winXP
from PIL import ImageGrab

from PyQt5.QtWidgets import QWidget, QSystemTrayIcon, QAction, QMenu, QLabel, QLineEdit, QCheckBox, QPushButton, \
    QGridLayout, QMainWindow, QDesktopWidget, QTableWidget, QDateTimeEdit, QAbstractItemView, QTableWidgetItem, \
    QAbstractScrollArea, QHeaderView, QMessageBox, QPlainTextEdit, QApplication, QFileDialog, QComboBox, QVBoxLayout
from PyQt5.QtCore import Qt, QCoreApplication, QTimer, QDate
from PyQt5.QtGui import QIcon, QFont, QPixmap

# spinner module (from file "waitingspinnerwidget.py")
from waitingspinnerwidget import QtWaitingSpinner

# check if app already running (from file "singleinstance.py")
from singleinstance import singleinstance
from sys import exit


# APP START

# gettext multilang init
_ = translate.gettext
translate.install()

# get client app ip and hostname
clientIp = clientIpGet()
clientHostname = clientHostnameGet()

# singleinstance var (for single app run check)
myAppAlreadyRunning = singleinstance()

# NOT FOR WinXP
# # enc
# def encrypt(message: bytes, key: bytes) -> bytes:
#     return Fernet(key).encrypt(message)
#
# # decr
# def decrypt(token: bytes, key: bytes) -> bytes:
#     return Fernet(key).decrypt(token)

# debug
print("Client IP: " + str(clientIp))
print("Client Hostname: " + str(clientHostname))

# check if auth.ini exists
if os.path.exists(configAuthPath):
    print(_("auth.ini exists!"))

    # if auth.ini exists
    if os.path.isfile(configAuthPath):
        print(_("auth.ini is a file!"))
    else:
        print(_("auth.ini is a directory! delete directory auth.ini"))
        shutil.rmtree(configAuthPath)

        print(_("Create auth.ini"))

        # create auth.ini
        content = ["[auth]", "checkboxrememberloginchecked = 1"]
        file = open(configAuthPath, "w")
        for index in content:
            file.write(index + '\n')
        file.close()

# if auth.ini DOESN'T exist
else:
    print("auth.ini doesn't exist! create auth.ini")

    # create auth.ini
    content = ["[auth]", "checkboxrememberloginchecked = 1"]
    file = open(configAuthPath, "w")
    for index in content:
        file.write(index + '\n')
    file.close()

# auth.ini read
configAuth = configparser.ConfigParser()
configAuth.read(configAuthPath, encoding="utf8")

# # debug show sessionToken
# def show(event):
#     print(sessionToken)


# AUTH WIN
class AuthWin(QWidget):
    def __init__(self):
        super().__init__()
        self.AuthWinInitUI()

    def onTrayIconActivated(self, reason):
        self.activateWindow()
        self.show()
        self.setWindowState(Qt.WindowNoState)
        # if reason == 1:
        #     print("onTrayIconActivated:", reason)
        #     self.activateWindow()
        #     self.show()
        #
        # if reason == 2 or 3:
        #     print("onTrayIconActivated:", reason)
        #     self.activateWindow()
        #     self.show()

    # def disambiguateTimerTimeout(self):
    #    print("Tray icon single clicked")

    # method initUI create GUI
    def AuthWinInitUI(self):
        super().__init__()

        # create authwin
        self.setFixedSize(450, 250)
        self.center()
        self.setWindowTitle(appName)
        self.setWindowIcon(QIcon('img/ico.png'))

        # check if another instance of the same program running
        if myAppAlreadyRunning.alreadyrunning():
            print("Another instance of this program is already running")
            QMessageBox.about(self, appName, _("The program is already running"))
            exit(0)
        # no app running, safe to continue...
        print("No another instance is running, can continue here")

        self.activateWindow()

        # init QSystemTrayIcon
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("img\ico.png"))
        self.tray_icon.setToolTip(appName)

        settings_action = QAction(_("Settings"), self)
        settings_action.triggered.connect(self.settingsWinShow)

        about_action = QAction(_("About..."), self)
        about_action.triggered.connect(self.aboutWinShow)

        quit_action = QAction(_("Quit"), self)
        quit_action.triggered.connect(self.appClose)

        tray_menu = QMenu()

        tray_menu.addAction(settings_action)
        tray_menu.addAction(about_action)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

        self.tray_icon.activated.connect(self.onTrayIconActivated)

        # head label
        authHeadLabel = QLabel(self)
        authHeadLabel.setText(_("Authorization"))

        # head font
        authHeadLabelFont = QFont("Arial", 16, QFont.Bold)
        authHeadLabel.setFont(authHeadLabelFont)

        # get checkbox REMEMBER LOGIN status
        checkboxRememberLoginChecked = configAuth.get("auth", "checkboxrememberloginchecked")

        # login label create
        loginLabel = QLabel(self)
        loginLabel.setText(_("Login"))

        # login entry create
        self.loginEntry = QLineEdit(self)

        try:
            # read login from config file
            self.loginEntry.setText(configAuth.get("auth", "login"))

        except Exception:
            print(_("Login doesn't exist in auth.ini"))
            self.loginEntry.setText("")
            pass

        # pass label create
        passLabel = QLabel(self)
        passLabel.setText(_("Password"))

        # pass entry create
        self.passEntry = QLineEdit(self)
        self.passEntry.setEchoMode(QLineEdit.Password)

        try:
            # NOT FOR WinXP
            # # get ENC PASS from config & decr it
            # userPassDecr = decrypt((bytes(configAuth.get("auth", "password"), "utf-8")), encKey).decode()
            #
            # # set decr pass to pass entry
            # self.passEntry.setText(userPassDecr)

            # get pass from config
            userPass = configAuth.get("auth", "password")

            # put password to window filled
            self.passEntry.setText(userPass)

        except Exception:
            print(_("Password doesn't exist in auth.ini"))
            self.passEntry.setText("")
            pass

        # add checkbox REMEMBER LOGIN
        self.checkboxRememberLogin = QCheckBox(_("Remember Login and Password"), self)

        # if checked checkbox REMEMBER LOGIN IS TRUE(1) in config file
        if checkboxRememberLoginChecked == "1":
            # check checkboxRememberLogin
            self.checkboxRememberLogin.setChecked(True)
        if checkboxRememberLoginChecked == "0":
            # UNcheck checkboxRememberLogin
            self.checkboxRememberLogin.setChecked(False)

        # auth error label
        self.authErrorLabel = QLabel(self)
        self.authErrorLabel.setText('')
        self.authErrorLabel.setStyleSheet('color: red')

        # login button create
        self.loginButton = QPushButton(_("Sign in"), self)
        self.loginButton.setFixedSize(150, 30)
        self.loginButton.clicked.connect(self.auth)

        # create grid of widgets
        grid = QGridLayout()
        grid.setSpacing(10)

        # auth label
        grid.addWidget(authHeadLabel, 0, 0, 1, 4)
        authHeadLabel.setAlignment(Qt.AlignCenter)
        authHeadLabel.setMinimumHeight(80)

        grid.addWidget(loginLabel, 1, 1)
        loginLabel.setAlignment(Qt.AlignCenter)

        grid.addWidget(self.loginEntry, 1, 2)
        self.loginEntry.setMaximumWidth(150)

        grid.addWidget(passLabel, 2, 1)
        passLabel.setAlignment(Qt.AlignCenter)

        grid.addWidget(self.passEntry, 2, 2)
        self.passEntry.setMaximumWidth(150)

        grid.addWidget(self.checkboxRememberLogin, 3, 0, 1, 4, alignment=Qt.AlignCenter)

        grid.addWidget(self.authErrorLabel, 4, 0, 1, 4)
        self.authErrorLabel.setAlignment(Qt.AlignCenter)

        grid.addWidget(self.loginButton, 5, 1, 2, 2, alignment=Qt.AlignCenter)

        self.setLayout(grid)

        # show mainwin
        self.show()

        # HIDE APP TO TRAY AT STARTUP
        self.hide()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    # auth
    def auth(self):
        # global vars are visible in all parts of code
        global sessionToken
        global userName
        global userFirstname
        global userRealname
        global userId

        # gui auth - get vars from entries
        userLogin = self.loginEntry.text()
        userPass = self.passEntry.text()

        # debug
        print(userLogin)
        print(userPass)

        # create crypt phrase of logg+pass for Basic Auth
        loginPassPairString = (userLogin + ':' + userPass)
        loginPassPairBytes = loginPassPairString.encode("utf-8")
        encLoginPassPair = base64.b64encode(loginPassPairBytes)

        # convert loginPassPairBytes to Str
        encLoginPassPair = encLoginPassPair.decode("utf-8")

        # debug
        # print(encLoginPassPair)


        #####
        ## INIT SESSION, GET sessionToken
        #####

        # request headers sessionInit over crypt log/pass
        headersSession = {'Content-Type': 'application/json',
                          'Authorization': 'Basic ' + encLoginPassPair,
                          'App-Token': appToken,
                          }

        # request headers sessionInit over crypt userToken
        # headersSession = {'Content-Type': 'application/json',
        #    'Authorization': 'user_token ' + userToken,
        #    'App-Token': appToken,
        # }

        # try login to server
        try:
            # request session init
            responseSessionInit = requests.get(glpiApiBaseUrl + '/initSession', headers=headersSession)

            # write to var all json with sessionToken

            # pycharm 2018 x32 python 3.4
            sessionTokenJson = responseSessionInit.json()

            # pycharm 2019 x64 python 3.7
            #sessionTokenJson = json.loads(responseSessionInit.content)

            # debug
            print(type(sessionTokenJson).__name__)

            # check if sessionTokenJson correct type DICT or not
            if not (type(sessionTokenJson).__name__ == 'dict'):
                print(_("sessionTokenJson is NOT correct"))
                self.authErrorLabel.setText(_("Auth error"))

                # if json not DICT - exit func
                return

            # if json is DICT - go on auth
            else:
                print(_("sessionTokenJson is correct"))

                # debug
                print(sessionTokenJson)

                # get sessionToken from json with sessionToken
                sessionToken = sessionTokenJson['session_token']

                # check if sessionTokenJson empty or not
                if not sessionToken:
                    print(_("Auth error. 'session_token' not found"))
                else:
                    print(_("Auth success. 'session_token' found"))

                    # debug
                    print(sessionToken)

                    # if checkbox REMEMBER LOGIN is checked - write login to config file
                    if self.checkboxRememberLogin.isChecked():

                        # enc pass
                        #userPassEnc = encrypt(userPass.encode(), encKey)

                        # remember user login & enc pass in config file
                        configAuth.set("auth", "login", userLogin)
                        configAuth.set("auth", "password", userPass)
                        configAuth.set("auth", "checkboxrememberloginchecked", "1")

                        # NOT FOR WinXP
                        #configAuth.set("auth", "password", str(userPass, "utf-8"))

                        # write configAuth file
                        with open(configAuthPath, "w", encoding="utf-8") as config_file:
                            configAuth.write(config_file)

                    # if checkbox REMEMBER LOGIN is UNchecked - remove login from config file
                    else:
                        # REMOVE user login from config file
                        configAuth.set("auth", "login", "")
                        configAuth.set("auth", "password", "")
                        configAuth.set("auth", "checkboxrememberloginchecked", "0")

                        # write configAuth file
                        with open(configAuthPath, "w", encoding="utf-8") as config_file:
                            configAuth.write(config_file)

                    # get user data

                    # get userName from gui entry
                    userName = userLogin

                    print(userName)

                    # request headers
                    headersGet = {'Content-Type': 'application/json',
                                  'Session-Token': sessionToken,
                                  'App-Token': appToken,
                                  }

                    # GET FULLSESSION (all auth user's vars)

                    # request fullsession
                    responseFullsessionGet = requests.get(glpiApiBaseUrl + '/getFullSession', headers=headersGet)

                    # write to var all json-fullsession

                    # pycharm 2018 x32 python 3.4
                    fullsessionJson = responseFullsessionGet.json()

                    # pycharm 2019 x64 python 3.7
                    #fullsessionJson = json.loads(responseFullsessionGet.content)

                    # debug
                    print(fullsessionJson)

                    # get user's firstname and secondname
                    userFirstname = fullsessionJson['session']['glpifirstname']
                    userRealname = fullsessionJson['session']['glpirealname']
                    userId = fullsessionJson['session']['glpiID']
                    print('\r')
                    print(userFirstname, userRealname)

                    # hide autwin, show mainwin
                    self.destroy()
                    self.exec_ = MainWin()
                    self.tray_icon.hide()

        # pass if no connection to server
        except Exception as e:
            self.authErrorLabel.setText(_("Connection error"))
            logging.error('Error at %s', 'division', exc_info=e)
            pass

        # exit with filled vars
        return sessionToken, headersSession, userName, userFirstname, userRealname  # authStatusLabel

    # press Enter to auth
    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key_Enter or key == Qt.Key_Return:
            self.auth()

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            appName,
            appName + " " + "is minimized to the system tray",
            #QSystemTrayIcon.Information,
            2000
        )

    # about button
    def aboutWinShow(self):
        self.exec_ = AboutWin()

    # settings button
    def settingsWinShow(self):
        self.exec_ = SettingsWin()

    # app close func
    def appClose(self):

        self.tray_icon.hide()
        QCoreApplication.instance().quit()

        # debug
        print(sessionToken)

        # if session token EXISTS
        #if not sessionToken or adminSessionToken is None:
        #    sessionKillCommon()

        # kill session common func
        sessionKillCommon()


# main win
class MainWin(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    # update app
    def appUpdate(self):

        # spinner = QtWaitingSpinner(self, True, True, Qt.ApplicationModal)
        # spinner.start()  # starts spinning
        # self.statusbar.showMessage('Программа обновляется. Это займет несколько секунд...')
        #
        # transport = paramiko.Transport((sftpServerHost, int(sftpServerPort)))
        # transport.connect(username=sftpServerUser, password=sftpServerPass)
        #
        # sftp = paramiko.SFTPClient.from_transport(transport)
        # sftp.get(sftpServerRootPath + "glpiClient/glpiClient.exe", "update/glpiClient.exe")
        #
        # sftp.close()
        #
        # self.statusbar.showMessage('')
        # spinner.stop()
        #
        # # close app after update
        # sessionKillCommon()
        # subprocess.call([r'updater.cmd'])

        if os.path.exists(updateDirPath):
            # print("Update exists!")

            if os.path.isfile(updateDirPath):
                # print("Update is not a directory! Remove file Update")
                os.remove(updateDirPath, dir_fd=None)
            else:
                # print("Update is a directory! Remove directory Update")
                shutil.rmtree(updateDirPath)

            # print("Create directory Update")
            os.mkdir(updateDirPath, mode=0o777, dir_fd=None)
        else:
            # print("Update DOESN'T exist! Create directory Update")
            os.mkdir(updateDirPath, mode=0o777, dir_fd=None)


        if os.path.exists(updateAppDirPath):
            # print("./update/HelpdeskClient exists!")

            if os.path.isfile(updateAppDirPath):
                # print("./update/HelpdeskClient is not a directory! Remove file ./update/HelpdeskClient")
                os.remove(updateAppDirPath, dir_fd=None)
            else:
                # print("./update/HelpdeskClient is a directory! Remove directory ./update/HelpdeskClient")
                shutil.rmtree(updateAppDirPath)

            # print("Create directory ./update/HelpdeskClient")
            os.mkdir(updateAppDirPath, mode=0o777, dir_fd=None)
        else:
            # print("./update/HelpdeskClient DOESN'T exist! Create directory ./update/HelpdeskClient")
            os.mkdir(updateAppDirPath, mode=0o777, dir_fd=None)


        if os.path.exists(updateConfigDirPath):
            # print("config exists!")

            if os.path.isfile(updateConfigDirPath):
                # print("config is not a directory! Remove file config")
                os.remove(updateConfigDirPath, dir_fd=None)
            else:
                # print("config is a directory! Remove directory config")
                shutil.rmtree(updateConfigDirPath)

            # print("Create directory config")
            os.mkdir(updateConfigDirPath, mode=0o777, dir_fd=None)
        else:
            # print("config DOESN'T exist! Create directory config")
            os.mkdir(updateConfigDirPath, mode=0o777, dir_fd=None)

        try:
            # update updater from ftp
            wget.download(
                "ftp://" + ftpServerUser + ":" + ftpServerPass + "@" + ftpServerHost + ":" + ftpServerPort + ftpPath + appDirName + "/" + updaterExeFile,
                out=updateAppDirPath)

            # update config from ftp
            wget.download(
                "ftp://" + ftpServerUser + ":" + ftpServerPass + "@" + ftpServerHost + ":" + ftpServerPort + ftpPath + appDirName + "/config/" + configFileName,
                out=updateConfigDirPath)

            # kill session
            sessionKillCommon()

            try:
                copy_tree(updateAppDirPath, "")
            except Exception as e:
                print(_("Failed to download an update"))
                QMessageBox.about(self, appName, _("Failed to download an update"))
                logging.error('Error at %s', 'division', exc_info=e)

            # start updater
            os.startfile(updaterExeFile)

            # close main app
            self.appClose()

        except Exception as e:
            print(_("Failed to download an update"))
            QMessageBox.about(self, appName, _("Failed to download an update"))
            logging.error('Error at %s', 'division', exc_info=e)
            # close main app
            self.appClose()

    # TIMER RUNNING IN BACKGROUND
    def Time(self):

        # debug TICKS OUTPUT IN CONSOLE EVERY SECONDS - IT'S ANNOYING
        #print(strftime("%H" + ":" + "%M" + ":" + "%S"))

        # # check update every hour & update if there's new version
        # if strftime("%M" + ":" + "%S") == "00:00":
        #     print("HOUR!")
        #     appVersionCheck()
        #     if updateMode == 1:
        #         self.appUpdate()

        # LOGOUT at 00:00:00
        if strftime("%H" + ":" + "%M" + ":" + "%S") == "00:00:00" or \
            strftime("%H" + ":" + "%M" + ":" + "%S") == "00:00:01" or \
            strftime("%H" + ":" + "%M" + ":" + "%S") == "00:00:02":
            print("MIDNIGHT!")
            self.sessionKill()

    def onTrayIconActivated(self, reason):
        self.activateWindow()
        self.show()
        self.setWindowState(Qt.WindowNoState)
        # if reason == 1:
        #     print("onTrayIconActivated:", reason)
        #     self.activateWindow()
        #     self.show()
        #
        # if reason == 2 or 3:
        #     print("onTrayIconActivated:", reason)
        #     self.activateWindow()
        #     self.show()

    def initUI(self):
        QMainWindow.__init__(self)

        # check actual app version
        appVersionActual = appVersionCheck()

        # remoteUpdateMarkerCheck
        remoteUpdateMarker = remoteUpdateMarkerCheck()

        global updateMode

        # if there's new version and remoteUpdateMarker = 1 - enter updateMode
        if (float(appVersionActual) > float(appVersion)) and int(remoteUpdateMarker) == 1:
            updateMode = 1
        else:
            updateMode = 0

        # debug
        print("updateMode: " + str(updateMode))
        print("appAutoUpdate: " + str(appAutoUpdate))

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.Time)
        self.timer.start(1000)

        # init QSystemTrayIcon
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("img\ico.png"))

        # popup on trayicon hover
        self.tray_icon.setToolTip(appName)

        settings_action = QAction(_("Settings"), self)
        settings_action.triggered.connect(self.settingsWinShow)

        about_action = QAction(_("About..."), self)
        about_action.triggered.connect(self.aboutWinShow)

        quit_action = QAction(_("Quit"), self)
        quit_action.triggered.connect(self.appClose)

        tray_menu = QMenu()

        tray_menu.addAction(settings_action)
        tray_menu.addAction(about_action)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.onTrayIconActivated)

        # create mainwin

        # disable resize win
        #self.setFixedSize(900, 700)

        # enable resize win
        self.setMinimumSize(700, 450)
        self.center()
        self.setWindowTitle(appName)
        self.setWindowIcon(QIcon('img\ico.png'))

        # status bar
        self.statusbar = self.statusBar()
        self.statusbar.setStyleSheet("QStatusBar{padding:8px;background:rgba(0,0,0,0);color:black;font-weight:bold;}")
        self.statusbar.showMessage('')

        # CENTRAL WIDGET

        # self.setMinimumSize(QSize(480, 80))  # set window ышяу - disable windows expand
        # self.setWindowTitle("Работа с QTableWidget")  # set window header
        central_widget = QWidget(self)  # create central widget
        self.setCentralWidget(central_widget)  # set central widget

        # create QGridLayout
        grid_layout = QGridLayout()
        grid_layout.setSpacing(10)
        central_widget.setLayout(grid_layout)

        # login label create
        userNameLabel = QLabel(self)
        userNameLabel.setText(
            userFirstname + ' ' + userRealname + ' ' + '(' + userName + ')')

        # logout button create
        self.logoutButton = QPushButton(_("Sign out"), self)
        self.logoutButton.setFixedSize(80, 30)
        self.logoutButton.clicked.connect(self.sessionKill)

        # add ticket button
        self.ticketAddButton = QPushButton(_("Create new ticket"), self)
        self.ticketAddButton.setFixedSize(250, 30)
        self.ticketAddButton.clicked.connect(self.addTicketWinShow)

        # mytickets head label
        myticketsHeadLabel = QLabel(self)
        myticketsHeadLabel.setText(_("My tickets"))
        # head font
        myticketsHeadLabelFont = QFont("Arial", 16, QFont.Bold)
        myticketsHeadLabel.setFont(myticketsHeadLabelFont)

        # add checkbox OPENTICKETS
        self.checkboxTicketsOpen = QCheckBox(_("Open tickets only"), self)
        self.checkboxTicketsOpen.setChecked(True)

        # label FROM
        self.myticketsDateFromLabel = QLabel(self)
        self.myticketsDateFromLabel.setText(_("From"))

        # DATEFROM widget
        self.dateFromWidget = QDateTimeEdit(QDate.currentDate().addMonths(-3), self)
        self.dateFromWidget.setCalendarPopup(True)
        self.dateFromWidget.setMinimumDate(QDate(1970, 1, 1))
        self.dateFromWidget.setMaximumDate(QDate(2099, 12, 31))
        self.dateFromWidget.setDisplayFormat("yyyy-MM-dd")

        def getDateFrom():
            global dateFromStr
            dateFrom = self.dateFromWidget.date()
            dateFromStr = str(dateFrom.toPyDate())
            print(type(dateFromStr))
            print(dateFromStr)

        # debug
        # # A push button
        # btn_get = QPushButton("Get Date From", self)
        # btn_get.move(100, 250)
        # btn_get.clicked.connect(getDateFrom)

        # label TO
        self.myticketsDateToLabel = QLabel(self)
        self.myticketsDateToLabel.setText(_("To"))

        # DATETO widget
        self.dateToWidget = QDateTimeEdit(QDate.currentDate(), self)
        self.dateToWidget.setCalendarPopup(True)
        self.dateToWidget.setMinimumDate(QDate(1970, 1, 1))
        self.dateToWidget.setMaximumDate(QDate(2099, 12, 31))
        self.dateToWidget.setDisplayFormat("yyyy-MM-dd")

        # DATETO func
        def getDateTo():
            global dateToStr
            dateTo = self.dateToWidget.date()
            dateToStr = str(dateTo.toPyDate())
            print(type(dateToStr))
            print(dateToStr)

        # debug
        # # A push button
        # btn_get = QPushButton("Get Date To", self)
        # btn_get.move(100, 450)
        # btn_get.clicked.connect(getDateTo)

        # # add DATEFROM button
        # self.ticketDateFromButton = QPushButton('...', self)
        # self.ticketDateFromButton.setFixedSize(30, 30)
        # self.ticketDateFromButton.clicked.connect(self.calendarShow)

        ################


        # GET tickets list
        def getTicketsList():

            # if update mode ON - update app on ticket list renew
            if updateMode == 1 and appAutoUpdate == "1":
                self.appUpdate()

            spinner = QtWaitingSpinner(self, True, True, Qt.ApplicationModal)
            spinner.start()  # starts spinning

            #self.exec_ = SpinnerWin()

            self.statusbar.showMessage(_("Loading..."))

            # get date from & to
            getDateFrom()
            getDateTo()

            # debug
            print("dateFrom: " + dateFromStr)
            print("dateTo: " + dateToStr)

            # if checked checkbox OPENTICKETS show only UNRESOLVED tickets
            if self.checkboxTicketsOpen.isChecked():
                ticketSearchStatus = "notold"

            # if UNchecked checkbox OPENTICKETS show ALL tickets
            else:
                ticketSearchStatus = "all"

            # request headers
            headersGet = {'Content-Type': 'application/json',
                          'Session-Token': sessionToken,
                          'App-Token': appToken,
                          }

            # request
            responseMyTicketsGet = requests.get(
                glpiApiBaseUrl + '/search/Ticket?'
                                 'is_deleted=0&'
                                 'as_map=0&'
                                 'range=0-999999&'
                                 'criteria[0][field]=12&criteria[0][searchtype]=equals&criteria[0][value]=' + ticketSearchStatus + '&'
                                 'criteria[6][link]=AND&'
                                 #'criteria[2][field]=15&criteria[2][searchtype]=morethan&_select_criteria[2][value]=0&_criteria[2][value]=2019-06-06+00%3A00&criteria[2][value]=2019-06-06+00%3A00&'
                                 'criteria[2][field]=15&criteria[2][searchtype]=morethan&_select_criteria[2][value]=0&_criteria[2][value]=' + dateFromStr + '+00%3A00&criteria[2][value]=' + dateFromStr + '+00%3A00&'
                                 'criteria[6][link]=AND&'
                                 'criteria[7][field]=15&criteria[7][searchtype]=lessthan&_select_criteria[7][value]=0&_criteria[7][value]=' + dateToStr + '+23%3A59&criteria[7][value]=' + dateToStr + '+23%3A59&'
                                 'criteria[6][link]=AND&'
                                 'criteria[6][field]=22&criteria[6][searchtype]=equals&criteria[6][value]=' + str(userId),
                headers=headersGet)

            # debug
            # print(responseMyTicketsGet)

            # pycharm 2018 x32 python 3.4
            myTicketsListJson = responseMyTicketsGet.json()

            # debug
            print(myTicketsListJson)
            print(type(myTicketsListJson))

            # if success getting json dict with user's tickets
            if type(myTicketsListJson).__name__ == 'dict':

                # if user have 0 tickets
                if myTicketsListJson['totalcount'] == 0:
                    print(_("You have no tickets"))

                    # TABLE WITH NO TICKETS

                    table = QTableWidget(self)
                    table.setColumnCount(1)

                    header = table.horizontalHeader()
                    header.setStretchLastSection(True)

                    # set table's headers
                    table.setHorizontalHeaderLabels([_("Tickets not found")])

                    # set header's alignment
                    table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignHCenter)

                # if a user has >0 tickets
                if myTicketsListJson['totalcount'] > 0:

                    myTicketsList = myTicketsListJson['data']
                    myTicketsCount = len(myTicketsList)

                    # debug
                    print(userId)

                    ################

                    ################

                    # TABLE OF TICKETS

                    table = QTableWidget(self)  # create table
                    table.setColumnCount(4)  # set quantity of columns
                    table.setRowCount(myTicketsCount)  # and one string in table
                    table.setEditTriggers(QTableWidget.NoEditTriggers)  # disable edit cells
                    table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)  # smooth scroll
                    table.setSelectionBehavior(QTableWidget.SelectRows)  # select full row instead of one cell
                    table.verticalHeader().setVisible(False)  # hide vertical headers (number of row)

                    # headers of table style
                    table.horizontalHeader().setStyleSheet("""
                        QHeaderView::section {padding: 8px; background-color: lightgrey; border: 1px; }
                        """)

                    header = table.horizontalHeader()

                    # SORT BY TABLE HEADER CLICK
                    table.setSortingEnabled(True)

                    # stretch last column
                    #header.setStretchLastSection(True)

                    # resize width of ALL columns to content
                    #header.setSectionResizeMode(QHeaderView.ResizeToContents)

                    # headers of table
                    itemTableHeaderId = QTableWidgetItem('ID')
                    #itemTableHeaderId.setBackground(QColor(255, 255, 0))
                    itemTableHeaderId.setToolTip(_("Ticket ID"))
                    itemTableHeaderId.setFont(QFont("Arial", 10, QFont.Bold))
                    table.setHorizontalHeaderItem(0, itemTableHeaderId)
                    header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # resize column to contents

                    itemTableHeaderCreateDate = QTableWidgetItem(_("Creation date"))
                    itemTableHeaderCreateDate.setToolTip(_("Ticket creation date and time"))
                    table.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
                    itemTableHeaderCreateDate.setFont(QFont("Arial", 10, QFont.Bold))
                    table.setHorizontalHeaderItem(1, itemTableHeaderCreateDate)
                    header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # resize column to contents

                    itemTableHeaderName = QTableWidgetItem(_("Name"))
                    #itemTableHeaderName.ResizeToContents
                    itemTableHeaderName.setToolTip(_("Ticket name"))
                    itemTableHeaderName.setFont(QFont("Arial", 10, QFont.Bold))
                    table.setHorizontalHeaderItem(2, itemTableHeaderName)
                    header.setSectionResizeMode(2, QHeaderView.Stretch)  # stretch column

                    itemTableHeaderStatus = QTableWidgetItem(_("Status"))
                    itemTableHeaderStatus.setToolTip(_("Ticket status"))
                    itemTableHeaderStatus.setFont(QFont("Arial", 10, QFont.Bold))
                    table.setHorizontalHeaderItem(3, itemTableHeaderStatus)
                    header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # resize column to contents

                    # fill table with mytickets
                    for myTicketJson in range(myTicketsCount):
                        myTicket = (myTicketsList[myTicketJson])

                        # ticket id
                        myTicketId = myTicket['2']

                        # ticket name
                        myTicketName = myTicket['1']

                        # ticket create date
                        myTicketCreateDate = myTicket['15']

                        # ticket status
                        myTicketStatusId = myTicket['12']

                        # debug
                        print(myTicketJson)
                        print(myTicketId)
                        print(myTicketName)
                        print(myTicketCreateDate)
                        print(myTicketStatusId)
                        print('\r')

                        # convert ticket status from ID to HUMAN READABLE
                        if myTicketStatusId == 1:
                            myTicketStatus = _("New")
                        elif myTicketStatusId == 2:
                            myTicketStatus = _("In progress (assigned)")
                        elif myTicketStatusId == 3:
                            myTicketStatus = _("In progress (planned)")
                        elif myTicketStatusId == 4:
                            myTicketStatus = _("Awaiting decision")
                        elif myTicketStatusId == 5:
                            myTicketStatus = _("Solved")
                        elif myTicketStatusId == 6:
                            myTicketStatus = _("Closed")

                        # fill table
                        table.setItem(myTicketJson, 0, QTableWidgetItem(str(myTicketId)))
                        table.setItem(myTicketJson, 1, QTableWidgetItem(str(myTicketCreateDate)))
                        table.setItem(myTicketJson, 2, QTableWidgetItem(str(myTicketName)))
                        table.setItem(myTicketJson, 3, QTableWidgetItem(str(myTicketStatus)))
                        # table.setItem(myTicketJson, 3, QTableWidgetItem(''))

                    # sort auto by date
                    table.sortItems(1, Qt.AscendingOrder)

                    ################


                # show ticket win func
                def showTicketWin():

                    spinner = QtWaitingSpinner(self, True, True, Qt.ApplicationModal)
                    spinner.start()  # starts spinning

                    # show status in statusbar
                    self.statusbar.showMessage(_("Loading..."))

                    global myTicketIdInTableOfTickets
                    index = table.selectedIndexes()[0]
                    myTicketIdInTableOfTickets = table.model().data(index)
                    #print("TicketID: " + str(myTicketIdInTableOfTickets))

                    # open show ticket win
                    self.exec_ = ShowTicketWin()

                    spinner.stop()

                    # hide status in statusbar
                    self.statusbar.showMessage('')

                # # get and print ID of ticket
                # def doubleClicked_table(self):
                #     index = table.selectedIndexes()[0]
                #     myTicketIdInTableOfTickets = table.model().data(index)
                #     print("TicketID: " + str(myTicketIdInTableOfTickets))

                # create a connection to the double click on table event
                table.doubleClicked.connect(showTicketWin)

                # username label show
                grid_layout.addWidget(userNameLabel, 0, 1, alignment=Qt.AlignRight)

                # logout btn
                grid_layout.addWidget(self.logoutButton, 1, 1, alignment=Qt.AlignRight)

                # mytickets label show
                grid_layout.addWidget(myticketsHeadLabel, 2, 0, 1, 2, alignment=Qt.AlignCenter)


                ### DATE WIDGET WITH DATE GRID IN GENERAL GRID

                date_widget = QWidget(self)  # create widget date

                grid_date = QGridLayout()
                grid_date.setSpacing(10)
                date_widget.setLayout(grid_date)  # place grid in widget

                # LABEL DATEFROM in grid
                grid_date.addWidget(self.myticketsDateFromLabel, 0, 0, 1, 1, alignment=Qt.AlignLeft)

                # DATEFROM in grid
                grid_date.addWidget(self.dateFromWidget, 0, 1, 1, 1, alignment=Qt.AlignLeft)

                # LABEL DATETO in grid
                grid_date.addWidget(self.myticketsDateToLabel, 0, 2, 1, 1, alignment=Qt.AlignLeft)

                # DATETO in grid
                grid_date.addWidget(self.dateToWidget, 0, 3, 1, 1, alignment=Qt.AlignLeft)

                ### DATE GRID END


                # place windget GRID_DATE into cell of general grid
                grid_layout.addWidget(date_widget, 4, 0, 1, 1, alignment=Qt.AlignLeft)

                # checkbox OPENTICKETS in grid
                grid_layout.addWidget(self.checkboxTicketsOpen, 5, 0, 1, 1, alignment=Qt.AlignLeft)

                # table of tickets show in grid
                grid_layout.addWidget(table, 6, 0, 1, 2)

                # refresh btn
                grid_layout.addWidget(self.refreshButton, 7, 0, 1, 1, alignment=Qt.AlignCenter)

                # add ticket button grid
                grid_layout.addWidget(self.ticketAddButton, 7, 1, 1, 1, alignment=Qt.AlignCenter)

                # # app update button
                # if updateMode == 1:
                #     # self.appUpdateButton = QPushButton('App update', self)
                #     # self.appUpdateButton.setFixedSize(250, 30)
                #     # self.appUpdateButton.clicked.connect(self.appUpdate)
                #     # grid_layout.addWidget(self.appUpdateButton, 8, 0, 1, 2, alignment=Qt.AlignCenter)
                #
                #     # auto update
                #     self.appUpdate()

                spinner.stop()

                self.statusbar.showMessage('')

        # refresh tickets button create
        self.refreshButton = QPushButton(_("Update a list of tickets"), self)
        self.refreshButton.setFixedSize(250, 30)
        self.refreshButton.clicked.connect(getTicketsList)

        # show & also refresh by button ticketsList
        getTicketsList()

        # clear tmp dir at login
        try:
            files = glob.glob('./tmp/*')
            for f in files:
                os.remove(f)
        except Exception as e:
            print("Failed to delete all files")
            logging.error('Error at %s', 'division', exc_info=e)

        self.show()

    ## KILL SESSION
    def sessionKill(self):
        # запрос на session kill
        headersSessionKill = {'Content-Type': 'application/json',
                              'App-Token': appToken,
                              'Session-Token': sessionToken,
                              }
        responseSessionKill = requests.get(glpiApiBaseUrl + '/killSession', headers=headersSessionKill)

        # del sessionToken

        # debug
        print("LOGOUT")

        # debug
        print(headersSessionKill)
        print(responseSessionKill.content)
        # print(sessionToken)

        # NULL sessiontoken, close mainwin, show authwin
        self.sessionTokenNull()
        self.destroy()
        self.tray_icon.hide()
        self.timer.stop()
        self.exec_ = AuthWin()

    # sessiontoken null
    def sessionTokenNull(self):
        global sessionToken
        sessionToken = None
        return sessionToken

        # center window
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    # add ticket button
    def addTicketWinShow(self):
        self.exec_ = AddTicketWin()

    # # DATEFROM button
    # def calendarShow(self):
    #    self.exec_ = calendar()

    # about button
    def aboutWinShow(self):
        self.exec_ = AboutWin()

    # settings button
    def settingsWinShow(self):
        self.exec_ = SettingsWin()

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            appName,
            appName + " " + _("is minimized to the system tray"),
            #QSystemTrayIcon.Information,
            2000
        )

    # app close func
    def appClose(self):

        self.tray_icon.hide()
        QCoreApplication.instance().quit()

        # debug
        print(sessionToken)

        # if session token EXIST
        #if not sessionToken or adminSessionToken is None:
        #    sessionKillCommon()

        # kill session common func
        sessionKillCommon()


# ABOUT WIN
class AboutWin(QWidget):
    def __init__(self):
        super().__init__()

        # block parent window while open this window
        self.setWindowModality(Qt.ApplicationModal)
        self.initUI()

    def initUI(self):
        # create About win
        self.setFixedSize(300, 240)
        self.center()
        self.setWindowTitle(_("About..."))
        self.setWindowIcon(QIcon('img\ico.png'))

        # hide MINIMIZE & EXPAND buttons
        self.setWindowFlags(Qt.CustomizeWindowHint | Qt.WindowCloseButtonHint )

        self.glpiPic = QLabel(self)
        glpiPicPixmap = QPixmap('img\ico.png')
        self.glpiPic.setPixmap(glpiPicPixmap)

        # label app
        self.aboutAppHeadLabel = QLabel(self)
        self.aboutAppHeadLabel.setFont(QFont("Decorative", 11))
        self.aboutAppHeadLabel.setText(appName + " " + appVersion)

        # OK-exit button create
        self.aboutOkButton = QPushButton(_("OK"), self)
        self.aboutOkButton.setFixedSize(80, 30)
        self.aboutOkButton.clicked.connect(self.aboutClose)

        # grid ABOUT

        gridAbout = QGridLayout()
        gridAbout.addWidget(self.glpiPic, 0, 0, 1, 1, alignment=Qt.AlignCenter)
        gridAbout.addWidget(self.aboutAppHeadLabel, 1, 0, 1, 1, alignment=Qt.AlignCenter)
        gridAbout.addWidget(self.aboutOkButton, 2, 0, 1, 1, alignment=Qt.AlignCenter)
        self.setLayout(gridAbout)

        self.show()

    # center window
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def aboutClose(self):
        self.close()


# SETTINGS WIN
class SettingsWin(QWidget):
    def __init__(self):
        super().__init__()

        # block parent window while open this window
        self.setWindowModality(Qt.ApplicationModal)
        self.initUI()

    def initUI(self):
        # create Settings win
        self.setFixedSize(300, 240)
        self.center()
        self.setWindowTitle(_("Settings"))
        self.setWindowIcon(QIcon('img\ico.png'))

        # hide MINIMIZE & EXPAND buttons
        self.setWindowFlags(Qt.CustomizeWindowHint | Qt.WindowCloseButtonHint)

        # lang option
        self.settingsAppLangOption = QLabel(self)
        self.settingsAppLangOption.setFont(QFont("Decorative", 9))
        self.settingsAppLangOption.setText(_("Language") + ':')

        # lang select option
        self.settingsAppLangSelect = QComboBox()
        self.settingsAppLangSelect.setFont(QFont("Decorative", 9))

        # get lang dirs list
        langDirs = [f for f in listdir(langDirsPath) if not isfile(join(langDirsPath, f))]
        # print(type(langDirs))
        # print(langDirs)
        # print(len(langDirs))

        # put langs to dropdown menu
        for x in range(len(langDirs)):
            lang = langDirs[x]
            # print(type(lang))
            # print(lang)
            self.settingsAppLangSelect.addItem(lang)
            self.settingsAppLangSelect.setCurrentText(appLang)

        # autoupdate option
        self.settingsAutoUpdateOption = QLabel(self)
        self.settingsAutoUpdateOption.setFont(QFont("Decorative", 9))
        self.settingsAutoUpdateOption.setText(_("App autoupdate") + ':')

        # add checkbox autoupdate
        self.settingsCheckboxAutoUpdate = QCheckBox(self)

        # if checked checkbox REMEMBER LOGIN IS TRUE(1) in config file
        if appAutoUpdate == "1":
            # check checkboxRememberLogin
            self.settingsCheckboxAutoUpdate.setChecked(True)
        if appAutoUpdate == "0":
            # UNcheck checkboxRememberLogin
            self.settingsCheckboxAutoUpdate.setChecked(False)

        # OK button create
        self.settingsOkButton = QPushButton(_("OK"), self)
        self.settingsOkButton.setFixedSize(80, 30)
        self.settingsOkButton.clicked.connect(self.settingsSave)

        # Cancel button create
        self.settingsExitButton = QPushButton(_("Cancel"), self)
        self.settingsExitButton.setFixedSize(80, 30)
        self.settingsExitButton.clicked.connect(self.settingsClose)

        # grid
        gridSettings = QGridLayout()
        gridSettings.addWidget(self.settingsAppLangOption, 1, 0, 1, 1, alignment=Qt.AlignCenter)
        gridSettings.addWidget(self.settingsAppLangSelect, 1, 1, 1, 1, alignment=Qt.AlignCenter)
        gridSettings.addWidget(self.settingsAutoUpdateOption, 2, 0, 1, 1, alignment=Qt.AlignCenter)
        gridSettings.addWidget(self.settingsCheckboxAutoUpdate, 2, 1, 1, 1, alignment=Qt.AlignCenter)
        gridSettings.addWidget(self.settingsOkButton, 3, 0, 1, 1, alignment=Qt.AlignCenter)
        gridSettings.addWidget(self.settingsExitButton, 3, 1, 1, 1, alignment=Qt.AlignCenter)
        self.setLayout(gridSettings)

        self.show()

    # center window
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    # save settings func
    def settingsSave(self):
        global appLang

        # get new appLang value
        appLangNewValue = self.settingsAppLangSelect.currentText()

        # debug
        print(appLangNewValue)

        # init config string for new appLang
        config.set("main", "lang", appLangNewValue)

        # if checkbox AUTOUPDATE is checked - write to config file
        if self.settingsCheckboxAutoUpdate.isChecked():
            # remember in config file
            config.set("main", "autoupdate", "1")

        # if checkbox AUTOUPDATE is UNchecked - write to config file
        else:
            config.set("main", "autoupdate", "0")

        # write settings to config file
        with open(configPath, "w", encoding="utf-8") as config_file:
            config.write(config_file)

        # set new appLang var
        appLang = config.get("main", "lang")

        # popup win
        QMessageBox.about(self, _("Info"), _("Restart application to apply settings"))

        # close settings win
        self.close()

    def settingsClose(self):
        self.close()


# ADD TICKET WIN
class AddTicketWin(QWidget):

    # assign global var
    global arrayOfAttachedFiles
    arrayOfAttachedFiles = []
    global arrayOfAttachedScreenshots
    arrayOfAttachedScreenshots = []

    def __init__(self):
        super().__init__()

        # block parent window while open this window
        self.setWindowModality(Qt.ApplicationModal)
        self.initUI()

    def initUI(self):

        # null screenshotAddMarker
        # screenshotAddMarker = "no"

        # create addticket win
        self.setFixedSize(700, 510)
        self.center()
        self.setWindowTitle(appName)
        self.setWindowIcon(QIcon('img\ico.png'))

        # head label create
        self.addTicketLabelHead = QLabel(self)
        self.addTicketLabelHead.setText(_("Create new ticket"))

        # head font
        self.addTicketHeadLabelFont = QFont("Arial", 16, QFont.Bold)
        self.addTicketLabelHead.setFont(self.addTicketHeadLabelFont)
        # loginLabel.move(20, 20)

        # label customer phone create
        self.addTicketPhoneLabel = QLabel(self)
        self.addTicketPhoneLabel.setFont(QFont("Decorative", 11))
        self.addTicketPhoneLabel.setText(_("Contact phone") + '*')

        # customer's phone entry
        self.ticketPhoneEntry = QLineEdit(placeholderText="+7-(XXX)-XXX-XX-XX")
        self.ticketPhoneEntry.setFont(QFont("Decorative", 11))
        self.ticketPhoneEntry.setFixedSize(180, 30)
        #self.ticketPhoneEntry.setFocusPolicy(Qt.StrongFocus)

        # label customer RM number
        self.addTicketCompNumberLabel = QLabel(self)
        self.addTicketCompNumberLabel.setFont(QFont("Decorative", 11))
        self.addTicketCompNumberLabel.setText(_("Problem computer number"))

        # problem RM number
        self.ticketCompNumberEntry = QLineEdit(placeholderText="XXX")
        self.ticketCompNumberEntry.setFont(QFont("Decorative", 11))
        self.ticketCompNumberEntry.setFixedSize(50, 30)

        # ticket body entry create
        self.ticketBodyEntry = QPlainTextEdit(placeholderText=_("Describe your problem..."))
        self.ticketBodyEntry.setFont(QFont("Decorative", 11))
        self.ticketBodyEntry.setFixedSize(650, 250)

        ####
        ####

        # SCREENSHOT AND PIC ADD ELEMENTS

        # add screenshot button
        self.screenshotAddButton = QPushButton(_("Attach a screenshot"), self)
        self.screenshotAddButton.setFixedSize(200, 30)
        self.screenshotAddButton.setToolTip(_("To attach a screenshot,\npress the 'PrintScreen' key on your keyboard,\nand then the 'Attach a screenshot' button"))
        self.screenshotAddButton.clicked.connect(self.screenshotAdd)

        # label screenshot status
        self.screenshotStatusLabel = QLabel(self)
        self.screenshotStatusLabel.setFont(QFont("Decorative", 8))
        self.screenshotStatusLabel.setText(_("Press the 'PrintScreen' key on your keyboard\n and then the 'Attach a screenshot' button"))

        # add pic button
        self.picAddButton = QPushButton(_("Attach an Image"), self)
        self.picAddButton.setFixedSize(200, 30)
        self.picAddButton.clicked.connect(self.picAdd)

        # label pic status
        self.picPathEntry = QLineEdit(self)
        self.picPathEntry.setFixedSize(300, 30)
        self.picPathEntry.setDisabled(True)
        self.picPathEntry.setText(_("Click the 'Attach an Image' button"))

        ####
        ####

        # add ticket button
        self.ticketAddButton = QPushButton(_("Create Ticket"), self)
        self.ticketAddButton.setFixedSize(250, 50)
        self.ticketAddButton.clicked.connect(self.addTicket)

        grid = QGridLayout()
        grid.addWidget(self.addTicketLabelHead, 0, 0, 1, 2, alignment=Qt.AlignTop | Qt.AlignCenter)

        grid.addWidget(self.addTicketPhoneLabel, 2, 0, 1, 1, alignment=Qt.AlignRight)
        grid.addWidget(self.ticketPhoneEntry, 2, 1, 1, 1, alignment=Qt.AlignLeft)

        grid.addWidget(self.addTicketCompNumberLabel, 3, 0, 1, 1, alignment=Qt.AlignRight)
        grid.addWidget(self.ticketCompNumberEntry, 3, 1, 1, 1, alignment=Qt.AlignLeft)

        grid.addWidget(self.ticketBodyEntry, 4, 0, 1, 2, alignment=Qt.AlignCenter)

        ###
        ###

        # SCREENSHOT AND PIC ADD ELEMENTS LOCATION

        grid.addWidget(self.screenshotAddButton, 5, 0, 1, 1, alignment=Qt.AlignCenter)
        grid.addWidget(self.screenshotStatusLabel, 5, 1, 1, 1, alignment=Qt.AlignCenter)

        grid.addWidget(self.picAddButton, 6, 0, 1, 1, alignment=Qt.AlignCenter)
        grid.addWidget(self.picPathEntry, 6, 1, 1, 1, alignment=Qt.AlignLeft)

        ###
        ###

        grid.addWidget(self.ticketAddButton, 7, 0, 1, 2, alignment=Qt.AlignCenter)

        self.setLayout(grid)

        # set focus at phone text entry
        self.ticketPhoneEntry.setFocus()

        self.show()

    # centering window
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    ####
    ####

    # SCREENSHOT AND PIC ADD ELEMENTS

    # add screenshot to ticket
    def screenshotAdd(self):

        global screenshotPath

        # null array before add screenshot to it
        del arrayOfAttachedScreenshots[:]

        # create dir "tmp", if not exist
        tmpDirPath = "./tmp"

        if os.path.exists(tmpDirPath):
            # print("tmpDirPath существует!")

            if os.path.isfile(tmpDirPath):
                # print("tmpDirPath is NOT a directory! Remove file tmpDirPath")
                os.remove(tmpDirPath, dir_fd=None)

                # print("Создаем директорию tmpDirPath")
                os.mkdir(tmpDirPath, mode=0o777, dir_fd=None)
        else:
            # print("tmpDirPath DOESN'T exist! Create directory tmpDirPath")
            os.mkdir(tmpDirPath, mode=0o777, dir_fd=None)

        # generating random suffix for screenshot name
        screenshotRandomSuffix = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(8)])

        # assign screenshotPath
        screenshotPath = tmpDirPath + "/screenshot-" + screenshotRandomSuffix + ".png"

        # save screenshot to disk
        try:
            # assign screenshot
            screenshot = ImageGrab.grabclipboard()

            # screenshot save to disk
            screenshot.save(screenshotPath, 'PNG')

            # set color to label
            self.screenshotStatusLabel.setStyleSheet('color: green')

            arrayOfAttachedScreenshots.append(screenshotPath)

            # set label text
            self.screenshotStatusLabel.setText(_("Screenshot attached to the ticket!"))

        except Exception as e:
            print("Error attaching a screenshot")
            QMessageBox.about(self, _("Error"), _("Error attaching a screenshot.\nTo attach a screenshot, press the 'PrintScreen' key on your keyboard and then the 'Attach a screenshot' button'"))
            logging.error('Error at %s', 'division', exc_info=e)
            pass

    # add screenshot to ticket func
    def picAdd(self):

        global picPath

        # null array before add file to it
        del arrayOfAttachedFiles[:]

        # assign picPath
        picPath = QFileDialog.getOpenFileName()[0]

        # debug
        #print(picPath)

        arrayOfAttachedFiles.append(picPath)

        # set label picPathEntry
        self.picPathEntry.setText(picPath)

    ####
    ####

    # add ticket func
    def addTicket(self):

        # text of ticket body entry - get vars from entrys
        ticketBody = self.ticketBodyEntry.toPlainText()
        ticketTopic = (ticketBody[:40] + '...') if len(ticketBody) > 40 else ticketBody
        ticketPhone = self.ticketPhoneEntry.text()
        ticketCompNumber = self.ticketCompNumberEntry.text()

        # if ticketCompNumber is null
        if not ticketCompNumber:
            ticketCompNumber = "---"

        # ticketPhone = self.ticketPhoneEntry.toPlainText()
        # ticketCompNumber = self.ticketCompNumberEntry.toPlainText()

        # debug
        print(ticketPhone)
        print(ticketCompNumber)

        # if ticket body is empty
        #if (ticketBody == "") or (ticketPhone == "") or (ticketCompNumber == ""):
        if (ticketBody == "") or (ticketPhone == ""):
            QMessageBox.about(self, _("Error"), _("Please fill in all required fields"))
        else:

            # debug
            print("arrayOfAttachedScreenshots:")
            for x in range(len(arrayOfAttachedScreenshots)):
                print(arrayOfAttachedScreenshots[x])
                print(ntpath.basename(arrayOfAttachedScreenshots[x]))

            print(len(arrayOfAttachedScreenshots))

            # debug
            print("arrayOfAttachedFiles:")

            #debug
            print(len(arrayOfAttachedFiles))
            for x in range(len(arrayOfAttachedFiles)):
                print(arrayOfAttachedFiles[x])
                print(ntpath.basename(arrayOfAttachedFiles[x]))

            # post headers
            headersPost = {'Content-Type': 'application/json',
                'Session-Token': sessionToken,
                'App-Token': appToken,
            }

            # post json data - ticket body
            data = {"input": {"name": ticketTopic, "content": ticketBody + "\n\n" + "---" +
                                                              "\n" + "IP: " + clientIp +
                                                              "\n" + _("Computer name") + ": " + clientHostname +
                                                              "\n" + _("Problem computer number") + ": " + ticketCompNumber +
                                                              "\n" + _("Customer phone") + ": " + ticketPhone}}
            ###data = {"input": {"entities_id": "'"${entityId}"'","name": "'"${ticketName}"'","content": "'"${ticketMessage}"'","status": "2","priority": "'"${eventSeverity}"'"}}

            # create ticket
            requestAddTicket = requests.post(glpiApiBaseUrl + '/Ticket/', data=json.dumps(data), headers=headersPost)

            # get response on request of add ticket
            responseAddTicket = requestAddTicket.json()

            # debug
            print("responseAddTicket:")
            print(responseAddTicket)

            # if response is correct json
            if type(responseAddTicket).__name__ == 'dict':
                print("responseAddTicket is correct. Get ticket ID")

                # get id of new ticket
                ticketNewId = str(responseAddTicket['id'])

                # debug
                print(ticketNewId)


                ###
                # ADD REQUESTER TO NEW TICKET (GLPI 10)

                # хидеры запроса POST тикета
                headersPost = {'Content-Type': 'application/json',
                               'Session-Token': sessionToken,
                               'App-Token': appToken,
                               }

                data = {"input": {"tickets_id": ticketNewId, "users_id": userId}}

                requestTicketNewRequesterAdd = requests.post(glpiApiBaseUrl + '/Ticket/' + ticketNewId +
                                                             '/Ticket_User/', data=json.dumps(data), headers=headersPost)

                # debug
                print(requestTicketNewRequesterAdd)

                #
                ###


                #####
                #####
                # ADD CLIENT'S COMP FROM GLPI INV TO TICKET

                try:
                    # request headers
                    headersGet = {'Content-Type': 'application/json',
                                  'Session-Token': sessionToken,
                                  'App-Token': appToken,
                                  }

                    # search client's comp id from inv by name (client's hostname)
                    responseCompsGet = requests.get(
                        glpiApiBaseUrl + '/search/Computer?is_deleted=0&as_map=0&criteria[0][field]=1&criteria[0][searchtype]=contains&criteria[0][value]=' + clientHostname + '&search=Search&itemtype=Computer&start=0',
                        headers=headersGet)

                    # debug
                    print("responseCompsGet: " + str(responseCompsGet))

                    # comp inv json
                    compsListJson = responseCompsGet.json()

                    # debug
                    print("compsListJson: " + str(compsListJson))

                    # debug
                    print("type(compsListJson): " + str(type(compsListJson)))

                    # if response is correct json and key 'data' in dict exists
                    if type(compsListJson).__name__ == 'dict' and "data" in compsListJson:
                        print("compsListJson is correct. Get computer ID")

                        compsList = compsListJson['data']

                        # # comp properties
                        for compsJson in range(len(compsList)):
                            comp = (compsList[compsJson])

                            compInvId = comp['2']

                            # debug
                            print('compInvId: ' + str(compInvId))


                        # add comp (by its id in inv) to ticket

                        # post headers
                        headersPost = {'Content-Type': 'application/json',
                                       'Session-Token': sessionToken,
                                       'App-Token': appToken,
                                       }

                        # post json data - add comp to ticket
                        data = {"input": {"items_id": compInvId,"itemtype": "Computer", "tickets_id": ticketNewId}}

                        # add comp to ticket
                        requestAddCompToTicket = requests.post(glpiApiBaseUrl + '/Ticket/' + ticketNewId + '/Item_ticket/',
                                                               data=json.dumps(data), headers=headersPost)

                        # get response on request of add comp to ticket
                        responseAddCompToTicket = requestAddCompToTicket.json()

                        # debug
                        print(responseAddCompToTicket)

                # pass if error
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
                    pass

                #####
                #####


                # UPLOAD ATTACHED FILE

                # if array of attached files is not empty, then upload files
                if len(arrayOfAttachedFiles) > 0:

                    for fileForAttach in range(len(arrayOfAttachedFiles)):

                        # file name
                        fileBaseName = ntpath.basename(arrayOfAttachedFiles[fileForAttach])

                        if fileBaseName:

                            # debug
                            print('fileBaseName: ' + fileBaseName)

                            # file name with path
                            fileNameWithPath = arrayOfAttachedFiles[fileForAttach]

                            # debug
                            print('fileNameWithPath: ' + fileNameWithPath)

                            headersPost = {
                                'Session-Token': sessionToken,
                                'App-Token': appToken,
                            }

                            multipart_form_data = {
                                'uploadManifest': (None, '{"input": {"name": "fileAttached.png", "_filename": ["fileAttached.png"]}}'),
                                'filename[0]': (fileBaseName, open(fileNameWithPath, 'rb')),
                            }

                            # screenshot add request
                            responseDocumentUpload = requests.post(glpiApiBaseUrl + '/Document/', headers=headersPost,
                                                                   files=multipart_form_data)



                            # get upload result
                            documentUploadJson = responseDocumentUpload.json()

                            # debug
                            print(documentUploadJson)

                            # get file id after upload
                            fileAttachedId = json.dumps(documentUploadJson['id'])

                            # debug
                            print(type(fileAttachedId))
                            print(fileAttachedId)

                            # ATTACH UPLOADED FILE TO NEW CREATED TICKET

                            # post headers
                            headersPost = {'Content-Type': 'application/json',
                                           'Session-Token': sessionToken,
                                           'App-Token': appToken,
                                           }

                            # post json data - ticket body
                            data = {"input": {"itemtype": "Ticket", "items_id": ticketNewId, "tickets_id": ticketNewId, "documents_id": fileAttachedId}}

                            # create ticket
                            requestAddFileToTicket = requests.post(glpiApiBaseUrl + '/Document_Item/', data=json.dumps(data), headers=headersPost)

                            # get response on request of add ticket
                            responseAddFileToTicket = requestAddFileToTicket.json()

                            # debug
                            print(responseAddFileToTicket)

                            # null arrays with file path
                            del arrayOfAttachedFiles[:]


                # UPLOAD ATTACHED SCREENSHOT

                # if array of attached screenshots is not empty, then upload screenshot
                if len(arrayOfAttachedScreenshots) > 0:

                    for screenshotForAttach in range(len(arrayOfAttachedScreenshots)):

                        # screenshot name
                        screenshotBaseName = ntpath.basename(arrayOfAttachedScreenshots[screenshotForAttach])

                        # screenshot name with path
                        screenshotNameWithPath = arrayOfAttachedScreenshots[screenshotForAttach]

                        headersPost = {
                            'Session-Token': sessionToken,
                            'App-Token': appToken,
                        }

                        multipart_form_data = {
                            'uploadManifest': (
                            None, '{"input": {"name": "screenshotAttached.png", "_filename": ["screenshotAttached.png"]}}'),
                            'filename[0]': (screenshotBaseName, open(screenshotNameWithPath, 'rb')),
                        }

                        # screenshot add request
                        responseDocumentUpload = requests.post(glpiApiBaseUrl + '/Document/',
                                                               headers=headersPost,
                                                               files=multipart_form_data)

                        # get upload result
                        documentUploadJson = responseDocumentUpload.json()

                        # debug
                        print(documentUploadJson)

                        # get screenshot file id after upload
                        screenshotAttachedId = json.dumps(documentUploadJson['id'])

                        # debug
                        print(type(screenshotAttachedId))
                        print(screenshotAttachedId)

                        # ATTACH UPLOADED SCREENSHOT TO NEW CREATED TICKET

                        # post headers
                        headersPost = {'Content-Type': 'application/json',
                                       'Session-Token': sessionToken,
                                       'App-Token': appToken,
                                       }

                        # post json data - ticket body
                        data = {
                            "input": {"itemtype": "Ticket", "items_id": ticketNewId, "tickets_id": ticketNewId,
                                      "documents_id": screenshotAttachedId}}

                        # create ticket
                        requestAddScreenshotToTicket = requests.post(glpiApiBaseUrl + '/Document_Item/',
                                                               data=json.dumps(data), headers=headersPost)

                        # get response on request of add ticket
                        responseAddScreenshotToTicket = requestAddScreenshotToTicket.json()

                        # debug
                        print(responseAddScreenshotToTicket)

                        # null arrays with file path
                        del arrayOfAttachedScreenshots[:]

                # hide ticketwin, show popup
                self.close()

                #screenshotAddMarker = "no"

                # show message with ticket id
                QMessageBox.about(self, _("Ticket accepted"), _("Your ticket has been accepted under the number") +
                                  ": " + ticketNewId)

                #MainWin().getTicketsList()
                #destroy = MainWin()


# SHOW TICKET WIN
class ShowTicketWin(QWidget):
    def __init__(self):
        super().__init__()

        # block parent window while open this window
        self.setWindowModality(Qt.ApplicationModal)
        self.initUI()

    def initUI(self):

        # debug
        print("TicketID: " + str(myTicketIdInTableOfTickets))

        # create showticket win
        self.setMinimumSize(850, 650)
        self.resize(850, 650)
        self.center()
        self.setWindowTitle(appName)
        self.setWindowIcon(QIcon('img\ico.png'))

        # showticket label create
        self.showTicketLabelHead = QLabel(self)
        self.showTicketLabelHead.setText(_("Ticket") + ' ' + myTicketIdInTableOfTickets)
        self.showTicketHeadLabelFont = QFont("Arial", 16, QFont.Bold)
        self.showTicketLabelHead.setFont(self.showTicketHeadLabelFont)

        # showticket solutions label create
        self.showTicketSolutionsLabelHead = QLabel(self)
        self.showTicketSolutionsLabelHead.setText(_("Solution"))
        self.showTicketSolutionsLabelHeadFont = QFont("Arial", 16, QFont.Bold)
        self.showTicketSolutionsLabelHead.setFont(self.showTicketSolutionsLabelHeadFont)

        # showticket followups label create
        self.showTicketFollowupsLabelHead = QLabel(self)
        self.showTicketFollowupsLabelHead.setText(_("Comments"))
        self.showTicketFollowupsLabelHeadFont = QFont("Arial", 16, QFont.Bold)
        self.showTicketFollowupsLabelHead.setFont(self.showTicketFollowupsLabelHeadFont)

        #################

        # TABLES IN TICKET

        # GET TICKET DATA (TABLE WITH TICKET NAME)

        # хидеры запроса тикета
        headersGet = {'Content-Type': 'application/json',
                      'Session-Token': sessionToken,
                      'App-Token': appToken,
                      }

        responseTicketGet = requests.get(glpiApiBaseUrl + '/Ticket/' + myTicketIdInTableOfTickets, headers=headersGet)

        # get ticket data json
        ticketDataJson = responseTicketGet.json()

        # debug
        print(type(ticketDataJson))
        print(ticketDataJson)

        myTicketAuthor = (userFirstname + ' ' + userRealname)
        myTicketCreateDate = ticketDataJson['date']
        myTicketContent = ticketDataJson['content']
        myTicketStatusId = ticketDataJson['status']

        # convert ticket status from ID to HUMAN READABLE
        if myTicketStatusId == 1:
            myTicketStatus = _("New")
        elif myTicketStatusId == 2:
            myTicketStatus = _("In progress (assigned)")
        elif myTicketStatusId == 3:
            myTicketStatus = _("In progress (planned)")
        elif myTicketStatusId == 4:
            myTicketStatus = _("Awaiting decision")
        elif myTicketStatusId == 5:
            myTicketStatus = _("Solved")
        elif myTicketStatusId == 6:
            myTicketStatus = _("Closed")

        # debug
        #print("TICKET STATUS IN TICKET: " + str(myTicketStatusId))

        # draw table
        tableTicketData = QTableWidget(self)  # create table
        tableTicketData.setColumnCount(4)  # set number of columns
        tableTicketData.setRowCount(1)  # and one string in table
        tableTicketData.setEditTriggers(QTableWidget.NoEditTriggers)  # disable edit cells
        #tableTicketData.setSelectionBehavior(QTableWidget.SelectRows)  # select full row instead of one cell
        tableTicketData.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)  # smooth scroll
        tableTicketData.verticalHeader().setVisible(False)  # hide vertical headers (number of row)
        #tableTicketData.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)  # stretch rows in vertical to content with WORD WRAP
        tableTicketData.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)  # resize rows in vertical to content with WORD WRAP

        tableTicketData.setStyleSheet("""
            QTableWidget::item {
             selection-color: black;
             selection-background-color: lightblue;
             padding: 5px;
             border: none;
             }
            """)

        # headers of table style
        tableTicketData.horizontalHeader().setStyleSheet("""
            QHeaderView::section {padding: 8px; background-color: lightgrey; border: 1px; }
            """)

        header = tableTicketData.horizontalHeader()

        # stretch last column
        #header.setStretchLastSection(True)

        # resize width of ALL columns to content
        #header.setSectionResizeMode(QHeaderView.ResizeToContents)

        # headers of table
        itemTableTicketDataHeaderAuthor = QTableWidgetItem(_("Author"))
        # itemTableHeaderId.setBackground(QColor(255, 255, 0))
        itemTableTicketDataHeaderAuthor.setToolTip(_("Author"))
        itemTableTicketDataHeaderAuthor.setFont(QFont("Arial", 10, QFont.Bold))
        tableTicketData.setHorizontalHeaderItem(0, itemTableTicketDataHeaderAuthor)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # resize column to contents

        itemTableTicketDataHeaderACreateDate = QTableWidgetItem(_("Date"))
        itemTableTicketDataHeaderACreateDate.setToolTip(_("Creation date"))
        itemTableTicketDataHeaderACreateDate.setFont(QFont("Arial", 10, QFont.Bold))
        tableTicketData.setHorizontalHeaderItem(1, itemTableTicketDataHeaderACreateDate)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # resize column to contents

        itemTableTicketDataHeaderContent = QTableWidgetItem(_("Ticket text"))
        itemTableTicketDataHeaderContent.setToolTip(_("Ticket text"))
        itemTableTicketDataHeaderContent.setFont(QFont("Arial", 10, QFont.Bold))
        tableTicketData.setHorizontalHeaderItem(2, itemTableTicketDataHeaderContent)
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # stretch column

        itemTableTicketStatusHeaderContent = QTableWidgetItem(_("Status"))
        itemTableTicketStatusHeaderContent.setToolTip(_("Ticket status"))
        itemTableTicketStatusHeaderContent.setFont(QFont("Arial", 10, QFont.Bold))
        tableTicketData.setHorizontalHeaderItem(3, itemTableTicketStatusHeaderContent)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # resize column to contents

        # fill tableTicketData
        tableTicketData.setItem(0, 0, QTableWidgetItem(myTicketAuthor))
        tableTicketData.setItem(0, 1, QTableWidgetItem(myTicketCreateDate))
        tableTicketData.setItem(0, 2, QTableWidgetItem(myTicketContent))
        tableTicketData.setItem(0, 3, QTableWidgetItem(myTicketStatus))

        # set alignment for text in ALL columns
        for columnNumber in range(4):
            tableTicketData.item(0, columnNumber).setTextAlignment(Qt.AlignLeft | Qt.AlignTop)

        #tableTicketData.item(0, 0).setBackground(QColor(211, 211, 211))

        ######
        ### GET SIGNED SPECIALIST START

        # хидеры запроса тикета
        headersGet = {'Content-Type': 'application/json',
                      'Session-Token': sessionToken,
                      'App-Token': appToken,
                      }

        responseTicketGet = requests.get(glpiApiBaseUrl + '/Ticket/' + myTicketIdInTableOfTickets + '/Ticket_User', headers=headersGet)

        # get users in ticket data json
        ticketDataUsersJson = responseTicketGet.json()

        # debug
        print(type(ticketDataUsersJson))
        print(ticketDataUsersJson)

        ticketUsersCount=len(ticketDataUsersJson)

        arrayTicketUsersAssignedSpecsId = []

        # get users in ticket
        for ticketUserNumber in range(ticketUsersCount):
            ticketUser = (ticketDataUsersJson[ticketUserNumber])
            print(ticketUser)

            # parse json data
            ticketUserId = ticketUser['users_id']
            ticketUserType = ticketUser['type']

            # debug
            print("Ticket user ID: " + str(ticketUserId))

            # if type of user is ASSIGNED SPEC
            if ticketUserType == 2:
                arrayTicketUsersAssignedSpecsId.append(ticketUserId)

        print("Array users assigned ID: " + str(arrayTicketUsersAssignedSpecsId))


        # if assisned spec in ticket exist
        if len(arrayTicketUsersAssignedSpecsId) >= 0:

            assignedSpecsCount = len(arrayTicketUsersAssignedSpecsId)

            # draw table
            ticketAssignedSpecsRowCount = assignedSpecsCount

            tableAssignedSpecs = QTableWidget(self)  # create table
            tableAssignedSpecs.setColumnCount(1)  # set number of columns
            tableAssignedSpecs.setRowCount(ticketAssignedSpecsRowCount)  # and one string in table
            tableAssignedSpecs.setEditTriggers(QTableWidget.NoEditTriggers)  # disable edit cells
            #tableSolutions.setSelectionBehavior(QTableWidget.SelectRows)  # select full row instead of one cell
            tableAssignedSpecs.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)  # smooth scroll
            tableAssignedSpecs.verticalHeader().setVisible(False)  # hide vertical headers (number of row)
            tableAssignedSpecs.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)  # resize rows in vertical to content with WORD WRAP

            tableAssignedSpecs.setStyleSheet("""
                QTableWidget::item {
                 selection-color: black;
                 selection-background-color: lightblue;
                 padding: 2px;
                 border: none;
                 }
                """)

            # headers of table style
            tableAssignedSpecs.horizontalHeader().setStyleSheet("""
                QHeaderView::section {padding: 8px; background-color: lightgrey; border: 1px; }
                """)

            # SORT
            # table.setSortingEnabled(True)

            headerAssignedSpecs = tableAssignedSpecs.horizontalHeader()

            # stretch last column
            headerAssignedSpecs.setStretchLastSection(True)

            # resize width of column to content
            headerAssignedSpecs.setSectionResizeMode(QHeaderView.ResizeToContents)

            # headers of table
            itemTicketAssignedSpecsTableHeaderAuthor = QTableWidgetItem(_("Specialist"))
            itemTicketAssignedSpecsTableHeaderAuthor.setToolTip(_("Assigned specialist"))
            itemTicketAssignedSpecsTableHeaderAuthor.setFont(QFont("Arial", 10, QFont.Bold))
            tableAssignedSpecs.setHorizontalHeaderItem(0, itemTicketAssignedSpecsTableHeaderAuthor)

            # get solution data
            for ticketAssignedSpecNumber in range(assignedSpecsCount):

                # GET Name of User-Author of Solution by userID WITH ADMINSESSIONTOKEN

                # request headers
                headersGet = {'Content-Type': 'application/json',
                              'Session-Token': sessionToken,
                              'App-Token': appToken,
                              }

                ticketAssignedSpecId = arrayTicketUsersAssignedSpecsId[ticketAssignedSpecNumber]

                responseAssignedSpec = requests.get(
                    glpiApiBaseUrl + '/User/' + str(ticketAssignedSpecId),
                    headers=headersGet)

                # debug
                print(responseAssignedSpec)

                # pycharm 2018 x32 python 3.4
                responseAssignedSpecJson = responseAssignedSpec.json()

                # debug
                print(responseAssignedSpecJson)
                print(type(responseAssignedSpecJson))

                # get spec name (LOGIN)
                try:
                    ticketAssignedSpecLogin = responseAssignedSpecJson['name']
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
                    ticketAssignedSpecLogin = ""
                    pass

                # get spec names
                ticketAssignedSpecFirstname = responseAssignedSpecJson['firstname']
                ticketAssignedSpecSecondname = responseAssignedSpecJson['realname']

                ticketAssignedSpecFullName = (str(ticketAssignedSpecFirstname) + ' ' + str(ticketAssignedSpecSecondname))

                # if user's first name or second name exist - fill solution with it
                if ticketAssignedSpecFirstname or ticketAssignedSpecSecondname:
                    ticketAssignedSpecFullName = (str(ticketAssignedSpecFirstname) + ' ' + str(ticketAssignedSpecSecondname))
                else:
                    # else fill solution with user login
                    ticketAssignedSpecFullName = ticketAssignedSpecLogin

                # fill table
                tableAssignedSpecs.setItem(ticketAssignedSpecNumber, 0, QTableWidgetItem(str(ticketAssignedSpecFullName)))

            # sort table by date (1 column) with ascend
            tableAssignedSpecs.sortItems(1, Qt.AscendingOrder)

        ### GET SIGNED SPECIALIST END
        ######


        ######
        ### GET SIGNED GROUP SPECIALIST START

        # хидеры запроса тикета
        headersGet = {'Content-Type': 'application/json',
                      'Session-Token': sessionToken,
                      'App-Token': appToken,
                      }

        responseTicketGet = requests.get(glpiApiBaseUrl + '/Ticket/' + myTicketIdInTableOfTickets + '/Group_Ticket', headers=headersGet)

        # get users in ticket data json
        ticketDataGroupJson = responseTicketGet.json()

        # debug
        print(type(ticketDataGroupJson))
        print(ticketDataGroupJson)

        ticketGroupCount=len(ticketDataGroupJson)

        arrayTicketAssignedGroupsId = []

        # get groups in ticket
        for ticketGroupNumber in range(ticketGroupCount):
            ticketGroup = (ticketDataGroupJson[ticketGroupNumber])
            print(ticketGroup)

            # parse json data
            ticketGroupId = ticketGroup['groups_id']
            ticketGroupType = ticketGroup['type']

            # debug
            print("Ticket GROUP ID: " + str(ticketGroupId))

            # if type of GROUP is ASSIGNED SPEC
            if ticketGroupType == 2:
                arrayTicketAssignedGroupsId.append(ticketGroupId)

        print("Array users assigned ID: " + str(arrayTicketAssignedGroupsId))


        # if assisned groups in ticket exist
        if len(arrayTicketAssignedGroupsId) >= 0:

            assignedGroupsCount = len(arrayTicketAssignedGroupsId)

            # draw table
            ticketAssignedGroupsRowCount = assignedGroupsCount

            tableAssignedGroups = QTableWidget(self)  # create table
            tableAssignedGroups.setColumnCount(1)  # set number of columns
            tableAssignedGroups.setRowCount(ticketAssignedGroupsRowCount)  # and one string in table
            tableAssignedGroups.setEditTriggers(QTableWidget.NoEditTriggers)  # disable edit cells
            #tableSolutions.setSelectionBehavior(QTableWidget.SelectRows)  # select full row instead of one cell
            tableAssignedGroups.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)  # smooth scroll
            tableAssignedGroups.verticalHeader().setVisible(False)  # hide vertical headers (number of row)
            tableAssignedGroups.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)  # resize rows in vertical to content with WORD WRAP

            tableAssignedGroups.setStyleSheet("""
                QTableWidget::item {
                 selection-color: black;
                 selection-background-color: lightblue;
                 padding: 2px;
                 border: none;
                 }
                """)

            # headers of table style
            tableAssignedGroups.horizontalHeader().setStyleSheet("""
                QHeaderView::section {padding: 8px; background-color: lightgrey; border: 1px; }
                """)

            # SORT
            # table.setSortingEnabled(True)

            headerAssignedGroups = tableAssignedGroups.horizontalHeader()

            # stretch last column
            headerAssignedGroups.setStretchLastSection(True)

            # resize width of column to content
            headerAssignedGroups.setSectionResizeMode(QHeaderView.ResizeToContents)

            # headers of table
            itemTicketAssignedGroupsTableHeaderAuthor = QTableWidgetItem(_("Group of specialists"))
            itemTicketAssignedGroupsTableHeaderAuthor.setToolTip(_("Assigned group of specialists"))
            itemTicketAssignedGroupsTableHeaderAuthor.setFont(QFont("Arial", 10, QFont.Bold))
            tableAssignedGroups.setHorizontalHeaderItem(0, itemTicketAssignedGroupsTableHeaderAuthor)

            # get solution data
            for ticketAssignedGroupNumber in range(assignedGroupsCount):

                # GET Name of Group of Solution by userID WITH ADMINSESSIONTOKEN

                # request headers
                headersGet = {'Content-Type': 'application/json',
                              'Session-Token': sessionToken,
                              'App-Token': appToken,
                              }

                ticketAssignedGroupId = arrayTicketAssignedGroupsId[ticketAssignedGroupNumber]

                responseAssignedGroup = requests.get(
                    glpiApiBaseUrl + '/Group/' + str(ticketAssignedGroupId),
                    headers=headersGet)

                # debug
                print(responseAssignedGroup)

                # pycharm 2018 x32 python 3.4
                responseAssignedGroupJson = responseAssignedGroup.json()

                # debug
                print(responseAssignedGroupJson)
                print(type(responseAssignedGroupJson))

                # get solution author's name
                ticketAssignedGroupName = responseAssignedGroupJson['name']

                # fill table
                tableAssignedGroups.setItem(ticketAssignedGroupNumber, 0, QTableWidgetItem(str(ticketAssignedGroupName)))

            # sort table by date (1 column) with ascend
            tableAssignedGroups.sortItems(1, Qt.AscendingOrder)

        ### GET SIGNED GROUP OF SPECIALIST END
        ######


        ######
        ### GET TICKET SOLUTION JSON (TABLE WITH SOLUTION)

        # request headers
        headersGet = {'Content-Type': 'application/json',
                      'Session-Token': sessionToken,
                      'App-Token': appToken,
                      }
        # range (default: 0-50): a string with a couple of number for start and end of pagination separated by a '-'. Ex: 150-200. Optional.
        responseTicketGet = requests.get(glpiApiBaseUrl + '/Ticket/' + myTicketIdInTableOfTickets + '/ITILSolution/?range=0-999999', headers=headersGet)

        # get list of followups json
        ticketJsonListOfSolutions = responseTicketGet.json()

        # debug
        print(type(ticketJsonListOfSolutions))
        print(len(ticketJsonListOfSolutions))
        print(ticketJsonListOfSolutions)

        ticketSolutionsCount = len(ticketJsonListOfSolutions)

        if ticketSolutionsCount > 0:

            # draw table
            ticketSolutionsRowCount = ticketSolutionsCount

            tableSolutions = QTableWidget(self)  # create table
            tableSolutions.setColumnCount(3)  # set number of columns
            tableSolutions.setRowCount(ticketSolutionsRowCount)  # and one string in table
            tableSolutions.setEditTriggers(QTableWidget.NoEditTriggers)  # disable edit cells
            #tableSolutions.setSelectionBehavior(QTableWidget.SelectRows)  # select full row instead of one cell
            tableSolutions.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)  # smooth scroll
            tableSolutions.verticalHeader().setVisible(False)  # hide vertical headers (number of row)
            tableSolutions.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)  # resize rows in vertical to content with WORD WRAP
            #tableSolutions.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)  # stretch rows in vertical to content with WORD WRAP
            #tableSolutions.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)  # scroll off
            #tableSolutions.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)  # scroll off

            tableSolutions.setStyleSheet("""
                QTableWidget::item {
                 selection-color: black;
                 selection-background-color: lightblue;
                 padding: 5px;
                 border: none;
                 }
                """)

            # headers of table style
            tableSolutions.horizontalHeader().setStyleSheet("""
                QHeaderView::section {padding: 8px; background-color: lightgrey; border: 1px; }
                """)

            # SORT
            # table.setSortingEnabled(True)

            headerSolutions = tableSolutions.horizontalHeader()

            # stretch last column
            headerSolutions.setStretchLastSection(True)

            # resize width of column to content
            headerSolutions.setSectionResizeMode(QHeaderView.ResizeToContents)

            # headers of table
            itemTicketSolutionsTableHeaderAuthor = QTableWidgetItem(_("Author"))
            # itemTableHeaderId.setBackground(QColor(255, 255, 0))
            itemTicketSolutionsTableHeaderAuthor.setToolTip(_("Author"))
            itemTicketSolutionsTableHeaderAuthor.setFont(QFont("Arial", 10, QFont.Bold))
            tableSolutions.setHorizontalHeaderItem(0, itemTicketSolutionsTableHeaderAuthor)

            itemTicketSolutionsTableHeaderCreateDate = QTableWidgetItem(_("Date"))
            itemTicketSolutionsTableHeaderCreateDate.setToolTip(_("Creation date"))
            itemTicketSolutionsTableHeaderCreateDate.setFont(QFont("Arial", 10, QFont.Bold))
            tableSolutions.setHorizontalHeaderItem(1, itemTicketSolutionsTableHeaderCreateDate)

            itemTicketSolutionsTableHeaderContent = QTableWidgetItem(_("Solution"))
            itemTicketSolutionsTableHeaderContent.setToolTip(_("Solution text"))
            itemTicketSolutionsTableHeaderContent.setFont(QFont("Arial", 10, QFont.Bold))
            tableSolutions.setHorizontalHeaderItem(2, itemTicketSolutionsTableHeaderContent)

            # get solution data
            for ticketSolutionNumber in range(ticketSolutionsCount):

                ticketSolution = (ticketJsonListOfSolutions[ticketSolutionNumber])
                print("ticketSolution:")
                print(ticketSolution)
                print('\r')

                # get solution author
                ticketSolutionAuthorId = ticketSolution['users_id']
                print(ticketSolutionAuthorId)

                ################

                # GET Name of User-Author of Solution by userID WITH ADMINSESSIONTOKEN

                # request headers
                headersGet = {'Content-Type': 'application/json',
                              'Session-Token': sessionToken,
                              'App-Token': appToken,
                              }

                responseSolutionAuthor = requests.get(
                    glpiApiBaseUrl + '/User/' + str(ticketSolutionAuthorId),
                    headers=headersGet)

                # debug
                print(responseSolutionAuthor)

                # pycharm 2018 x32 python 3.4
                responseSolutionAuthorJson = responseSolutionAuthor.json()

                # debug
                print(responseSolutionAuthorJson)
                print(type(responseSolutionAuthorJson))

                # get solution author's name(LOGIN)
                try:
                    ticketSolutionAuthorLogin = responseSolutionAuthorJson['name']
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
                    ticketSolutionAuthorLogin = ""
                    pass

                # get solution author's firstname
                try:
                    ticketSolutionAuthorFirstname = responseSolutionAuthorJson['firstname']
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
                    ticketSolutionAuthorFirstname = ""
                    pass

                # get solution author's secondname
                try:
                    ticketSolutionAuthorSecondname = responseSolutionAuthorJson['realname']
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
                    ticketSolutionAuthorSecondname = ""
                    pass

                # debug
                print(ticketSolutionAuthorLogin)
                print(ticketSolutionAuthorFirstname)
                print(ticketSolutionAuthorSecondname)

                # if user's first name or second name exist - fill solution with it
                if ticketSolutionAuthorFirstname or ticketSolutionAuthorSecondname:
                    ticketSolutionAuthorFullName = (str(ticketSolutionAuthorFirstname) + ' ' + str(ticketSolutionAuthorSecondname))
                else:
                    # else fill solution with user login
                    ticketSolutionAuthorFullName = ticketSolutionAuthorLogin

                # get solution create date
                ticketSolutionCreateDate = ticketSolution['date_creation']
                print(ticketSolutionCreateDate)

                # get solution content
                ticketSolutionContent = ticketSolution['content']

                # double convertion from HTML markdown to text
                # (exactly in this format GLPI shows the text of the solution or followup!)
                # For example:
                # convert "&#60;p&#62;Решение&#60;/p&#62;" to "<p>Решение</p>", and then convert to "Решение"
                ticketSolutionContent = markdownify.markdownify(markdownify.markdownify(ticketSolutionContent))

                # remove HTML-TAG "&lt;p&gt;" from solution content
                ticketSolutionContent = ticketSolutionContent.replace('&lt;p&gt;', '')
                ticketSolutionContent = ticketSolutionContent.replace('&lt;/p&gt;', '')

                # debug
                print(ticketSolutionContent)

                # fill table
                tableSolutions.setItem(ticketSolutionNumber, 0, QTableWidgetItem(str(ticketSolutionAuthorFullName)))
                tableSolutions.setItem(ticketSolutionNumber, 1, QTableWidgetItem(str(ticketSolutionCreateDate)))
                tableSolutions.setItem(ticketSolutionNumber, 2, QTableWidgetItem(str(ticketSolutionContent)))

                # set alignment for text in ALL columns
                for columnNumber in range(3):
                    tableSolutions.item(0, columnNumber).setTextAlignment(Qt.AlignLeft | Qt.AlignTop)

                #table.item(ticketFollowupNumber, 0).setBackground(QColor(211,211,211))

                # auto scroll down to table of followups
                itemSolutionLastRow = tableSolutions.item((ticketSolutionsCount - 1), 0)
                tableSolutions.scrollToItem(itemSolutionLastRow, QAbstractItemView.PositionAtTop)

                # TMP FOR SORT
                # create a normal QTableWidgetItem
                # a = QTableWidgetItem()
                # a.setText(str(ticketFollowupNumber))
                # table.setItem(ticketFollowupNumber, 0, a)

                # select row
                #table.selectRow(ticketFollowupsCount - 1)

            # sort table by date (1 column) with ascend
            tableSolutions.sortItems(1, Qt.AscendingOrder)

        if ticketSolutionsCount == 0:
            print(_("There is no solution"))

            # TABLE WITH NO SOLUTION

            tableSolutions = QTableWidget(self)
            tableSolutions.setColumnCount(1)

            header = tableSolutions.horizontalHeader()
            header.setStretchLastSection(True)

            # set table header
            tableSolutions.setHorizontalHeaderLabels([_("There is no solution")])

            # set header align
            tableSolutions.horizontalHeaderItem(0).setTextAlignment(Qt.AlignHCenter)


        #################
        print("ticket SOLUTIONS count: " + str(ticketSolutionsCount))
        #################

        ######
        # GET TICKET FOLLOWUP JSON (TABLE WITH FOLLOWUPS)

        # reauest headers
        headersGet = {'Content-Type': 'application/json',
                      'Session-Token': sessionToken,
                      'App-Token': appToken,
                      }
        # range (default: 0-50): a string with a couple of number for start and end of pagination separated by a '-'. Ex: 150-200. Optional.
        responseTicketGet = requests.get(glpiApiBaseUrl + '/Ticket/' + myTicketIdInTableOfTickets + '/TicketFollowup/?range=0-999999', headers=headersGet)

        # get list of followups json
        ticketJsonListOfFollowups = responseTicketGet.json()

        # debug
        print(type(ticketJsonListOfFollowups))
        print(len(ticketJsonListOfFollowups))
        print(ticketJsonListOfFollowups)

        ticketFollowupsCount = len(ticketJsonListOfFollowups)

        if ticketFollowupsCount > 0:

            # draw table
            ticketRowCount = ticketFollowupsCount

            table = QTableWidget(self)  # reate table
            table.setColumnCount(3)  # set columns number
            table.setRowCount(ticketRowCount)  # and one string in table
            table.setEditTriggers(QTableWidget.NoEditTriggers)  # disable edit cells
            #table.setSelectionBehavior(QTableWidget.SelectRows)  # select full row instead of one cell
            table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)  # smooth scroll
            table.verticalHeader().setVisible(False)  # hide vertical headers (number of row)
            table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)  # resize rows in vertical to content with WORD WRAP

            table.setStyleSheet("""
                QTableWidget::item {
                 selection-color: black;
                 selection-background-color: lightblue;
                 padding: 5px;
                 border: none;
                 }
                """)

            # headers of table style
            table.horizontalHeader().setStyleSheet("""
                QHeaderView::section {padding: 8px; background-color: lightgrey; border: 1px; }
                """)

            # SORT
            # table.setSortingEnabled(True)

            header = table.horizontalHeader()

            # stretch last column
            header.setStretchLastSection(True)

            # resize width of column to content
            header.setSectionResizeMode(QHeaderView.ResizeToContents)

            # headers of table
            itemTicketTableHeaderAuthor = QTableWidgetItem(_("Author"))
            # itemTableHeaderId.setBackground(QColor(255, 255, 0))
            itemTicketTableHeaderAuthor.setToolTip(_("Author"))
            itemTicketTableHeaderAuthor.setFont(QFont("Arial", 10, QFont.Bold))
            table.setHorizontalHeaderItem(0, itemTicketTableHeaderAuthor)

            itemTicketTableHeaderCreateDate = QTableWidgetItem(_("Date"))
            itemTicketTableHeaderCreateDate.setToolTip(_("Creation date"))
            itemTicketTableHeaderCreateDate.setFont(QFont("Arial", 10, QFont.Bold))
            table.setHorizontalHeaderItem(1, itemTicketTableHeaderCreateDate)

            itemTicketTableHeaderContent = QTableWidgetItem(_("Comment"))
            itemTicketTableHeaderContent.setToolTip(_("Comment text"))
            itemTicketTableHeaderContent.setFont(QFont("Arial", 10, QFont.Bold))
            table.setHorizontalHeaderItem(2, itemTicketTableHeaderContent)

            # get followup data
            for ticketFollowupNumber in range(ticketFollowupsCount):

                ticketFollowup = (ticketJsonListOfFollowups[ticketFollowupNumber])
                print(ticketFollowup)
                print('\r')

                # get followup author
                ticketFollowupAuthorId = ticketFollowup['users_id']
                print("ticketFollowupAuthorId: " + str(ticketFollowupAuthorId))

                ################

                # GET Name of User-Author of Followup by userID WITH ADMINSESSIONTOKEN

                # request headers
                headersGet = {'Content-Type': 'application/json',
                              'Session-Token': sessionToken,
                              'App-Token': appToken,
                              }

                responseFollowupAuthor = requests.get(
                    glpiApiBaseUrl + '/User/' + str(ticketFollowupAuthorId),
                    headers=headersGet)

                # debug
                print(responseFollowupAuthor)

                # pycharm 2018 x32 python 3.4
                responseFollowupAuthorJson = responseFollowupAuthor.json()

                # debug
                print(responseFollowupAuthorJson)
                print(type(responseFollowupAuthorJson))

                # get followup author's name
                try:
                    ticketFollowupAuthorLogin = responseFollowupAuthorJson['name']
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
                    ticketFollowupAuthorLogin = ""
                    pass

                try:
                    ticketFollowupAuthorFirstname = responseFollowupAuthorJson['firstname']
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
                    ticketFollowupAuthorFirstname = ""
                    pass

                try:
                    ticketFollowupAuthorSecondname = responseFollowupAuthorJson['realname']
                except Exception as e:
                    logging.error('Error at %s', 'division', exc_info=e)
                    ticketFollowupAuthorSecondname = ""
                    pass

                # debug
                print(ticketFollowupAuthorLogin)
                print(ticketFollowupAuthorFirstname)
                print(ticketFollowupAuthorSecondname)

                # change ticket Author's name to "Me"
                if userId == ticketFollowupAuthorId:
                    ticketFollowupAuthorFullName = _("Me")
                else:
                    # if user's first name or second name exist - fill comment with it
                    if ticketFollowupAuthorFirstname or ticketFollowupAuthorSecondname:
                        ticketFollowupAuthorFullName = (
                                    str(ticketSolutionAuthorFirstname) + ' ' + str(ticketSolutionAuthorSecondname))
                    else:
                        # else fill solution with user login
                        ticketFollowupAuthorFullName = ticketFollowupAuthorLogin

                # get followup create date
                ticketFollowupCreateDate = ticketFollowup['date_creation']
                print(ticketFollowupCreateDate)

                # get followup content
                ticketFollowupContent = ticketFollowup['content']

                # double convertion from HTML markdown to text
                # (exactly in this format GLPI shows the text of the solution or followup!)
                # For example:
                # convert "&#60;p&#62;Решение&#60;/p&#62;" to "<p>Решение</p>", and then convert to "Решение"
                ticketFollowupContent = markdownify.markdownify(markdownify.markdownify(ticketFollowupContent))

                print(ticketFollowupContent)

                # fill table
                table.setItem(ticketFollowupNumber, 0, QTableWidgetItem(str(ticketFollowupAuthorFullName)))
                table.setItem(ticketFollowupNumber, 1, QTableWidgetItem(str(ticketFollowupCreateDate)))
                table.setItem(ticketFollowupNumber, 2, QTableWidgetItem(str(ticketFollowupContent)))

                #table.item(ticketFollowupNumber, 0).setBackground(QColor(211,211,211))

                # auto scroll down to table of followups
                itemLastRow = table.item((ticketFollowupsCount - 1), 0)
                table.scrollToItem(itemLastRow, QAbstractItemView.PositionAtTop)

                # TMP FOR SORT
                # create a normal QTableWidgetItem
                # a = QTableWidgetItem()
                # a.setText(str(ticketFollowupNumber))
                # table.setItem(ticketFollowupNumber, 0, a)

                # select row
                #table.selectRow(ticketFollowupsCount - 1)

            # sort table by date (1 column) with ascend
            table.sortItems(1, Qt.AscendingOrder)

        if ticketFollowupsCount == 0:
            print(_("There is no comments"))

            # TABLE WITH FOLLOWUPS

            table = QTableWidget(self)
            table.setColumnCount(1)

            header = table.horizontalHeader()
            header.setStretchLastSection(True)

            # Устанавливаем заголовки таблицы
            table.setHorizontalHeaderLabels([_("There is no comments")])

            # Устанавливаем выравнивание на заголовки
            table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignHCenter)


        #################
        print("ticket followup count: " + str(ticketFollowupsCount))
        #################

        # followup text entry
        self.followupBodyEntry = QPlainTextEdit(placeholderText=_("Write a comment..."))
        self.followupBodyEntry.setFont(QFont("Decorative", 8))
        self.followupBodyEntry.setFixedSize(550, 50)

        # add ticket button
        self.followupAddButton = QPushButton(_("Send") + " (Ctrl+Enter)", self)
        self.followupAddButton.setFixedSize(160, 50)
        self.followupAddButton.clicked.connect(self.addFollowup)

        # if ticket is closed - disable followup text entry & add button
        if myTicketStatusId == 6:
            self.followupBodyEntry.setDisabled(True)
            self.followupAddButton.setDisabled(True)
            self.followupBodyEntry.setPlaceholderText("")
            self.followupAddButton.setToolTip(_("Comments cannot be added to the closed ticket"))
            #self.followupAddButton.setToolTipDuration(0)

        #################

        # showticket grid create
        grid = QGridLayout()

        # showticket label show in grid
        grid.addWidget(self.showTicketLabelHead, 0, 0, 1, 4, alignment=Qt.AlignTop | Qt.AlignCenter)

        grid.addWidget(tableTicketData, 1, 0, 2, 3)

        # table with assigned spec
        tableAssignedSpecs.setFixedWidth(200)
        tableAssignedSpecs.setFixedHeight(100)
        grid.addWidget(tableAssignedSpecs, 1, 3, 1, 1)

        # table with assigned spec
        tableAssignedGroups.setFixedWidth(200)
        tableAssignedGroups.setFixedHeight(100)
        grid.addWidget(tableAssignedGroups, 2, 3, 1, 1)

        # showticket solutions label show in grid
        grid.addWidget(self.showTicketSolutionsLabelHead, 3, 0, 1, 4, alignment=Qt.AlignTop | Qt.AlignCenter)

        # table of solutions data show in grid
        grid.addWidget(tableSolutions, 4, 0, 1, 4)

        # showticket followups label show in grid
        grid.addWidget(self.showTicketFollowupsLabelHead, 5, 0, 1, 4, alignment=Qt.AlignTop | Qt.AlignCenter)

        # table of followups data show in grid
        grid.addWidget(table, 6, 0, 1, 4)

        # showticket addfollowup entry show in grid
        grid.addWidget(self.followupBodyEntry, 7, 0, 1, 3, alignment=Qt.AlignVCenter | Qt.AlignHCenter)

        # showticket addfollowup BUTTON show in grid
        grid.addWidget(self.followupAddButton, 7, 3, 1, 1, alignment=Qt.AlignVCenter | Qt.AlignHCenter)

        self.setLayout(grid)

        self.show()

    # center window
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    # ADD FOLLOWUP

    # add followup func
    def addFollowup(self):

        # text of followup body entry - get vars from entrys
        followupBody = self.followupBodyEntry.toPlainText()

        # if ticket body is empty
        if followupBody == "":

            QMessageBox.about(self, _("Error"), _("Comment field must not be empty"))

        else:

            # post headers
            headersPost = {'Content-Type': 'application/json',
                           'Session-Token': sessionToken,
                           'App-Token': appToken,
                           }

            # post json data - ticket body
            data = {"input": {"tickets_id": myTicketIdInTableOfTickets, "content": followupBody}}

            # create ticket
            requestAddFollowup = requests.post(
                glpiApiBaseUrl + '/Ticket/' + myTicketIdInTableOfTickets + '/TicketFollowup', data=json.dumps(data),
                headers=headersPost)

            # get response on request of add ticket
            responseAddFollowup = requestAddFollowup.json()

            # debug
            print(responseAddFollowup)

            # if response is correct json
            if type(responseAddFollowup).__name__ == 'dict':
                print("responseAddFollowup is NOT correct")

                # refresh ticket win with followups
                self.close()
                self.exec_ = ShowTicketWin()

    # press Enter to addFollowup
    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key_Enter or key == Qt.Key_Return:
            self.addFollowup()


if __name__ == '__main__':
    app = QApplication(sys.argv)

    # show authwin
    ex = AuthWin()

    sys.exit(app.exec_())
