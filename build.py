# SPDX-License-Identifier: AGPL-1.0-only
# Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
import os
import shutil
import win32crypt
import base64
import sys
import zipfile
import re

MSBUILD_PATH = r"C:\Dev\VS2017\MSBuild\15.0\Bin\MSBuild.exe"
NSIS_PATH = r'C:\Dev\NSIS\makeNSIS.EXE'


SIGNTOOL_PATH = r'c:\Program Files (x86)\Windows Kits\10\bin\10.0.15063.0\x86\signtool.exe'
SIGNTOOL_KEY_PATH = "" # path to key file
SIGNTOOL_PASS = "" # password

def RmTree(path):
  try:
    print ('Deleting %s' % path)
    shutil.rmtree(path)
  except FileNotFoundError:
    pass
  
def Run(s):
  print ('Running %s' % s)
  x = os.system(s)
  if x:
    raise Exception('Command failed (%d) : %s' % (x, s))

def CopyFile(src, dst):
  shutil.copyfile(src, dst)

def SignExe(src):
  print ('Signing %s' % src)
  cmd = r'""c:\Program Files (x86)\Windows Kits\10\bin\10.0.15063.0\x86\signtool.exe" sign /f "%s" /p %s /t http://timestamp.verisign.com/scripts/timstamp.dll "%s"' % (SIGNTOOL_KEY_PATH, SIGNTOOL_PASS, src)
  #cmd = r'""c:\Program Files (x86)\Windows Kits\10\bin\10.0.15063.0\x86\signtool.exe" sign %s ' % (SIGNTOOL_KEY_PATH, )
  x = os.system(cmd)
  if x:
    raise Exception('Signing failed (%d) : %s' % (x, cmd))

def GetVersion():
  for line in open(BASE + '/tunsafe_config.h', 'r'):
    m = re.match('^#define TUNSAFE_VERSION_STRING "TunSafe (.*)"$', line)
    if m:
      return m.group(1)
  raise Exception('Version not found')

#

#os.system(r'""')

command = sys.argv[1]

BASE = r'D:\Code\TunSafe'


if command == 'build_tap':
  Run(r'%s /V4 installer\tap\tap-windows6.nsi'  % NSIS_PATH)
  SignExe(r'installer\tap\TunSafe-TAP-9.21.2.exe')
  sys.exit(0)

if 1:
  RmTree(BASE + r'\Win32\Release')
  RmTree(BASE + r'\x64\Release')
  Run('%s TunSafe.sln /t:Clean;Rebuild /p:Configuration=Release /p:Platform=x64' % MSBUILD_PATH)
  Run('%s TunSafe.sln /t:Clean;Rebuild /p:Configuration=Release /p:Platform=Win32' % MSBUILD_PATH)

if 1:
  CopyFile(BASE + r'\Win32\Release\TunSafe.exe',
           BASE + r'\installer\x86\TunSafe.exe')

  SignExe(BASE + r'\installer\x86\TunSafe.exe')
  CopyFile(BASE + r'\x64\Release\TunSafe.exe',
           BASE + r'\installer\x64\TunSafe.exe')
  SignExe(BASE + r'\installer\x64\TunSafe.exe')

VERSION = GetVersion()

Run(r'%s /V4 -DPRODUCT_VERSION=%s installer\tunsafe.nsi ' % (NSIS_PATH, VERSION))
SignExe(BASE + r'\installer\TunSafe-%s.exe' % VERSION)

zipf = zipfile.ZipFile(BASE + '\installer\TunSafe-%s-x86.zip' % VERSION, 'w', zipfile.ZIP_DEFLATED)
zipf.write(BASE + r'\installer\x86\TunSafe.exe', 'TunSafe.exe')
zipf.write(BASE + r'\installer\License.txt', 'License.txt')
zipf.write(BASE + r'\installer\ChangeLog.txt', 'ChangeLog.txt')
zipf.write(BASE + r'\installer\TunSafe.conf', 'Config\\TunSafe.conf')
zipf.close()

zipf = zipfile.ZipFile(BASE + '\installer\TunSafe-%s-x64.zip' % VERSION, 'w', zipfile.ZIP_DEFLATED)
zipf.write(BASE + r'\installer\x64\TunSafe.exe', 'TunSafe.exe')
zipf.write(BASE + r'\installer\License.txt', 'License.txt')
zipf.write(BASE + r'\installer\ChangeLog.txt', 'ChangeLog.txt')
zipf.write(BASE + r'\installer\TunSafe.conf', 'Config\\TunSafe.conf')
zipf.close()
