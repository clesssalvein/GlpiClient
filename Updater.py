#!/usr/bin/python3
# -*- coding: utf-8 -*-


# MODULES

from vars import *
import os
import sys
import time
import shutil
import logging
import wget
from zipfile import ZipFile
from distutils.dir_util import copy_tree


# APP START

# gettext multilang
_ = translate.gettext
translate.install()

if os.path.exists(updateDirPath):
    # print("Update exist!")

    if os.path.isfile(updateDirPath):
        # print("Update is NOT a directiry! Remove file Update")
        os.remove(updateDirPath, dir_fd=None)
    else:
        # print("Update is a directory! Remove directory Update")
        shutil.rmtree(updateDirPath)

    # print("Create directory Update")
    os.mkdir(updateDirPath, mode=0o777, dir_fd=None)
else:
    # print("Update DOESN'T exist! Create directory Update")
    os.mkdir(updateDirPath, mode=0o777, dir_fd=None)

try:
    # get file update

    print(_("App update..."))
    print("\r")

    # download app update
    wget.download("ftp://" + ftpServerUser + ":" + ftpServerPass + "@" + ftpServerHost + ":" + ftpServerPort + ftpPath +
                  appNameZip, out=updateDirPath)

    # wait update for write to disk
    time.sleep(5)

    print("\n")

    # try unzip
    try:
        # unzip app
        with ZipFile(updateDirPath + '/' + appNameZip, 'r') as zipObj:
            # Extract all contents of zip file in current directory
            zipObj.extractall(updateDirPath)
    except Exception as e:
        print(_("Fail to unzip update"))
        logging.error('Error at %s', 'division', exc_info=e)
        pass

except Exception as e:
    print(_("Fail to download update"))
    logging.error('Error at %s', 'division', exc_info=e)
    pass

time.sleep(3)

try:
    copy_tree(updateDirPath + '/' + appDirName, "")
except Exception:
    pass

print(_("This window will be closed automatically..."))

time.sleep(3)

# start app
os.startfile(appExeFile)

sys.exit()
