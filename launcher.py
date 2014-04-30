# MASSIVE/CVL Launcher - easy secure login for the MASSIVE Desktop and the CVL
#
# Copyright (c) 2012-2013, Monash e-Research Centre (Monash University, Australia)
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# In addition, redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# -  Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# -  Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# -  Neither the name of the Monash University nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. SEE THE
# GNU GENERAL PUBLIC LICENSE FOR MORE DETAILS.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Enquiries: help@massive.org.au

# launcher.py
"""
A wxPython GUI to provide easy login to the MASSIVE Desktop.
It can be run using "python launcher.py", assuming that you
have an appropriate (32-bit or 64-bit) version of Python 
installed (*), wxPython, and the dependent Python modules 
listed in the DEPENDENCIES file.

(*) wxPython 2.8.x on Mac OS X doesn't support 64-bit mode.

The py2app module is required to build the "MASSIVE Launcher.app"
application bundle on Mac OS X, which can be built as follows:

   python create_mac_bundle.py py2app

To build a DMG containing the app bundle and a symbolic link to
Applications, you can run:

   python package_mac_version.py <version_number>

See: https://confluence-vre.its.monash.edu.au/display/CVL/MASSIVE+Launcher+Mac+OS+X+build+instructions

The PyInstaller module, bundled with the Launcher code is used
to build the Windows and Linux executables. The Windows setup wizard
(created with InnoSetup) can be built using:

   package_windows_version.bat C:\path\to\code\signing\certificate.pfx <certificate_password>

assuming that you have InnoSetup installed and that you have signtool.exe installed for
code signing.

See: https://confluence-vre.its.monash.edu.au/display/CVL/MASSIVE+Launcher+Windows+build+instructions

If you want to build a stand-alone Launcher binary for Mac or Windows
without using a code-signing certificate, you can do so by commenting
out the code-signing functionality in package_mac_version.py and in
package_windows_version.bat.  In other words, sorry, this is not 
possible at present without modifying the packaging scripts.

A self-contained Linux binary distribution can be built using
PyInstaller, as described on the following wiki page.

See: https://confluence-vre.its.monash.edu.au/display/CVL/MASSIVE+Launcher+Linux+build+instructions

"""


# Make sure that the Launcher doesn't attempt to write to
# "MASSIVE Launcher.exe.log", because it might not have
# permission to do so.
import sys
if sys.platform.startswith("win"):
    sys.stderr = sys.stdout

if sys.platform.startswith("win"):
    import _winreg
import subprocess
import wx
import time
import traceback
import threading
import os
import HTMLParser
import urllib2
import launcher_version_number
import xmlrpclib
import appdirs
import ConfigParser
import datetime
import shlex
import inspect
import requests
import ssh
from StringIO import StringIO
import logging
import LoginTasks
from utilityFunctions import *
import cvlsshutils.sshKeyDist
import cvlsshutils
import launcher_progress_dialog
from menus.IdentityMenu import IdentityMenu
import tempfile
from cvlsshutils.KeyModel import KeyModel
import siteConfig
import Queue

if sys.platform.startswith("darwin"):
    from MacMessageDialog import LauncherMessageDialog
elif sys.platform.startswith("win"):
    from WindowsMessageDialog import LauncherMessageDialog
elif sys.platform.startswith("linux"):
    from LinuxMessageDialog import LauncherMessageDialog
from logger.Logger import logger
import collections
import optionsDialog
import LauncherOptionsDialog

from utilityFunctions import LAUNCHER_URL
import dialogtext
dialogs=dialogtext.default()

class FileDrop(wx.FileDropTarget):
    def __init__(self, window):
        super(FileDrop,self).__init__()
        self.window = window

    def OnDropFiles(self, x, y, filenames):
        if len(filenames)!=1:
            pass
        else:
            self.window.loadSession(None,filenames[0])


class LauncherMainFrame(wx.Frame):
    PERM_SSH_KEY=0
    TEMP_SSH_KEY=1


    def shouldSave(self,item):
        # I should be able to use a python iterator here
        shouldSave=False
        for ctrl in self.savedControls:
            if isinstance(item,ctrl) and 'jobParams' in item.GetName():
                shouldSave=True
        return shouldSave

# Use this method to read a specifig section of the preferences file
    def loadConfig(self):
        assert self.prefs == None
        self.prefs=ConfigParser.SafeConfigParser(allow_no_value=True)
        if (os.path.exists(launcherPreferencesFilePath)):
            with open(launcherPreferencesFilePath,'r') as o:
                self.prefs.readfp(o)

    def getPrefsSection(self,section):
        assert self.prefs != None
        options = {}
        if self.prefs.has_section(section):
            optionsList =  self.prefs.items(section)
            for option in optionsList:
                key = option[0]
                value = option[1]
                if value=='True':
                    value = True
                if value=='False':
                    value = False
                options[key] = value
        return options

    def setPrefsSection(self,section,options):
        assert self.prefs != None
        if not self.prefs.has_section(section):
            self.prefs.add_section(section)
        for key in options.keys():
            self.prefs.set(section,key,"%s"%options[key])
        pass
    
# Use this method to a) Figure out if we have a default site b) load the parameters for that site.
    def loadPrefs(self,window=None,site=None):
        assert self.prefs != None
        if window==None:
            window=self
        if (site==None):
            siteConfigComboBox=self.FindWindowByName('jobParams_configName')
            try:
                site=siteConfigComboBox.GetValue()
            except:
                pass
#            if (site==None or site==""):
#                if self.prefs.has_option("Launcher Config","siteConfigDefault"):
#                    siteConfigDefault = self.prefs.get("Launcher Config","siteConfigDefault")
#                    if siteConfigDefault in self.sites.keys():
#                        siteConfigComboBox.SetValue(siteConfigDefault)
#                        site=siteConfigDefault
#                        self.loadPrefs(window=self,site=site)
        if (site != None):
            if self.prefs.has_section(site):
                for item in window.GetChildren():
                    if self.shouldSave(item):
                        name=item.GetName()
                        if self.prefs.has_option(site,name):
                            val=self.prefs.get(site,name)
                            try: # Most wx Controls expect a string in SetValue, but at least SpinCtrl expects an int.
                                item.SetValue(val)
                            except TypeError:
                                item.SetValue(int(val))
                    else:
                        self.loadPrefs(window=item,site=site)

    def savePrefsEventHandler(self,event):
        threading.Thread(target=self.savePrefs).start()
        event.Skip()
        
    def savePrefs(self,window=None,section=None):
        assert self.prefs!=None
        specialSections=['Global Preferences','configured_sites']
        write=False
        # If we called savePrefs without a window specified, its the root of recussion
        if (window==None and not section in specialSections):
            write=True
            window=self
        if (section in specialSections):
            write=True
            window=None
        if (section==None):
            try:
                configName=self.FindWindowByName('jobParams_configName').GetValue()
                if (configName!=None):
                    if (not self.prefs.has_section("Launcher Config")):
                        self.prefs.add_section("Launcher Config")
                    self.prefs.set("Launcher Config","siteConfigDefault",'%s'%configName)
                    self.savePrefs(section=configName)
            except:
                pass
        elif (section!=None):
            if (not self.prefs.has_section(section)):
                self.prefs.add_section(section)
            try:
                for item in window.GetChildren():
                    if self.shouldSave(item):
                        self.prefs.set(section,item.GetName(),'%s'%item.GetValue())
                    else:
                        self.savePrefs(section=section,window=item)
            except:
                pass
        if (write):
            with open(launcherPreferencesFilePath,'w') as o:
                self.prefs.write(o)



    def __init__(self, parent, id, title):

        super(LauncherMainFrame,self).__init__(parent, id, title, style=wx.DEFAULT_FRAME_STYLE )
        dt=FileDrop(self)
        self.SetDropTarget(dt)
        self.programName=title
        self.SetSizer(wx.BoxSizer(wx.VERTICAL))
        self.SetAutoLayout(0)

        self.savedControls=[]
        self.savedControls.append(wx.TextCtrl)
        self.savedControls.append(wx.ComboBox)
        self.savedControls.append(wx.SpinCtrl)

        self.prefs=None
        self.loginProcess=[]
        self.logWindow = None
        self.progressDialog = None

        if sys.platform.startswith("win"):
            _icon = wx.Icon('MASSIVE.ico', wx.BITMAP_TYPE_ICO)
            self.SetIcon(_icon)

        if sys.platform.startswith("linux"):
            import MASSIVE_icon
            self.SetIcon(MASSIVE_icon.getMASSIVElogoTransparent128x128Icon())

        self.loadConfig()

        self.menu_bar  = wx.MenuBar()

        self.file_menu = wx.Menu()
        self.menu_bar.Append(self.file_menu, "&File")
        shareDesktop=wx.MenuItem(self.file_menu,wx.ID_ANY,"&Save a shared session")
        self.file_menu.AppendItem(shareDesktop)
        self.Bind(wx.EVT_MENU, self.saveSessionEvent, id=shareDesktop.GetId())
        loadSession=wx.MenuItem(self.file_menu,wx.ID_ANY,"&Load a shared session")
        self.file_menu.AppendItem(loadSession)
        self.Bind(wx.EVT_MENU, self.loadSessionEvent, id=loadSession.GetId())
        loadDefaultSessions=wx.MenuItem(self.file_menu,wx.ID_ANY,"&Load defaults")
        self.file_menu.AppendItem(loadDefaultSessions)
        self.loadDefaultSessionsId=loadDefaultSessions.GetId()
        self.Bind(wx.EVT_MENU, self.loadDefaultSessionsEvent, id=loadDefaultSessions.GetId())
        manageSites=wx.MenuItem(self.file_menu,wx.ID_ANY,"&Manage sites")
        self.file_menu.AppendItem(manageSites)
        self.Bind(wx.EVT_MENU,self.manageSitesEventHandler,id=manageSites.GetId())
        if sys.platform.startswith("win") or sys.platform.startswith("linux"):
            self.file_menu.Append(wx.ID_EXIT, "E&xit", "Close window and exit program.")
            self.Bind(wx.EVT_MENU, self.onExit, id=wx.ID_EXIT)
           
            

        #if sys.platform.startswith("darwin"):
            ## Only do this for Mac OS X, because other platforms have
            ## a right-click pop-up menu for wx.TextCtrl with Copy,
            ## Select All etc. Plus, the menu doesn't look that good on
            ## the MASSIVE Launcher main dialog, and doesn't work for
            ## non Mac platforms, because FindFocus() will always
            ## find the window/dialog which contains the menu.
            #self.edit_menu = wx.Menu()
            #self.edit_menu.Append(wx.ID_CUT, "Cut", "Cut the selected text")
            #self.Bind(wx.EVT_MENU, self.onCut, id=wx.ID_CUT)
            #self.edit_menu.Append(wx.ID_COPY, "Copy", "Copy the selected text")
            #self.Bind(wx.EVT_MENU, self.onCopy, id=wx.ID_COPY)
            #self.edit_menu.Append(wx.ID_PASTE, "Paste", "Paste text from the clipboard")
            #self.Bind(wx.EVT_MENU, self.onPaste, id=wx.ID_PASTE)
            #self.edit_menu.Append(wx.ID_SELECTALL, "Select All")
            #self.Bind(wx.EVT_MENU, self.onSelectAll, id=wx.ID_SELECTALL)
            #self.menu_bar.Append(self.edit_menu, "&Edit")
        self.edit_menu = wx.Menu()
        self.edit_menu.Append(wx.ID_CUT, "Cu&t", "Cut the selected text")
        self.Bind(wx.EVT_MENU, self.onCut, id=wx.ID_CUT)
        self.edit_menu.Append(wx.ID_COPY, "&Copy", "Copy the selected text")
        self.Bind(wx.EVT_MENU, self.onCopy, id=wx.ID_COPY)
        self.edit_menu.Append(wx.ID_PASTE, "&Paste", "Paste text from the clipboard")
        self.Bind(wx.EVT_MENU, self.onPaste, id=wx.ID_PASTE)
        self.edit_menu.Append(wx.ID_SELECTALL, "Select &All")
        self.Bind(wx.EVT_MENU, self.onSelectAll, id=wx.ID_SELECTALL)
        self.edit_menu.AppendSeparator()
        id_preferences=wx.NewId()
        if sys.platform.startswith("win") or sys.platform.startswith("linux"):
            self.edit_menu.Append(id_preferences, "P&references\tCtrl-P")
        else:
            self.edit_menu.Append(id_preferences, "&Preferences")
        self.Bind(wx.EVT_MENU, self.onOptions, id=id_preferences)
        self.menu_bar.Append(self.edit_menu, "&Edit")

        self.identity_menu = IdentityMenu()
        options=self.getPrefsSection('Global Preferences')
        if options.has_key('auth_mode'):
            auth_mode = int(options['auth_mode'])
        else:
            auth_mode = 0
        self.identity_menu.initialize(self,auth_mode=auth_mode)
        self.menu_bar.Append(self.identity_menu, "&Identity")

        self.help_menu = wx.Menu()
        helpContentsMenuItemID = wx.NewId()
        self.help_menu.Append(helpContentsMenuItemID, "&%s Help"%self.programName)
        self.Bind(wx.EVT_MENU, self.onHelpContents, id=helpContentsMenuItemID)
        self.help_menu.AppendSeparator()
        emailHelpAtMassiveMenuItemID = wx.NewId()
        self.help_menu.Append(emailHelpAtMassiveMenuItemID, "Email &help@massive.org.au")
        self.Bind(wx.EVT_MENU, self.onEmailHelpAtMassive, id=emailHelpAtMassiveMenuItemID)
        emailCvlHelpAtMonashMenuItemID = wx.NewId()
        self.help_menu.Append(emailCvlHelpAtMonashMenuItemID, "Email &cvl-help@monash.edu")
        self.Bind(wx.EVT_MENU, self.onEmailCvlHelpAtMonash, id=emailCvlHelpAtMonashMenuItemID)
        submitDebugLogMenuItemID = wx.NewId()
        self.help_menu.Append(submitDebugLogMenuItemID, "&Submit debug log")
        self.Bind(wx.EVT_MENU, self.onSubmitDebugLog, id=submitDebugLogMenuItemID)
        # On Mac, the About menu item will automatically be moved from 
        # the Help menu to the "MASSIVE Launcher" menu, so we don't
        # need a separator.
        if not sys.platform.startswith("darwin"):
            self.help_menu.AppendSeparator()
        self.help_menu.Append(wx.ID_ABOUT,   "&About %s"%self.programName)
        self.Bind(wx.EVT_MENU, self.onAbout, id=wx.ID_ABOUT)
        self.menu_bar.Append(self.help_menu, "&Help")

        self.SetTitle(self.programName)


        self.loginDialogPanel = wx.Panel(self, wx.ID_ANY)
        self.loginDialogPanel.SetSizer(wx.BoxSizer(wx.VERTICAL))
        self.GetSizer().Add(self.loginDialogPanel)

        self.loginFieldsPanel = wx.Panel(self.loginDialogPanel, wx.ID_ANY)
        self.loginFieldsPanel.SetSizer(wx.BoxSizer(wx.VERTICAL))
        self.loginDialogPanel.GetSizer().Add(self.loginFieldsPanel, flag=wx.EXPAND|wx.TOP|wx.LEFT|wx.RIGHT, border=10)

        widgetWidth1 = 180
        widgetWidth2 = 180
        if not sys.platform.startswith("win"):
            widgetWidth2 = widgetWidth2 + 25
        widgetWidth3 = 75


        
        self.noneVisible={}
        self.noneVisible['usernamePanel']=False
        self.noneVisible['projectPanel']=False
        self.noneVisible['execHostPanel']=False
        self.noneVisible['resourcePanel']=False
        self.noneVisible['resolutionPanel']=False
        self.noneVisible['cipherPanel']=False
        self.noneVisible['debugCheckBoxPanel']=False
        self.noneVisible['advancedCheckBoxPanel']=False
        self.noneVisible['optionsDialog']=False


        self.sites={}
        self.siteConfigPanel = wx.Panel(self.loginFieldsPanel, wx.ID_ANY)
        self.siteConfigPanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        self.configLabel = wx.StaticText(self.siteConfigPanel, wx.ID_ANY, 'Site')
        self.siteConfigPanel.GetSizer().Add(self.configLabel, proportion=0, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND, border=5)
        self.siteConfigComboBox = wx.ComboBox(self.siteConfigPanel, wx.ID_ANY, choices=self.sites.keys(), style=wx.CB_READONLY,name='jobParams_configName')
        self.siteConfigComboBox.Bind(wx.EVT_COMBOBOX, self.onSiteConfigChanged)
        self.siteConfigPanel.GetSizer().Add(self.siteConfigComboBox, proportion=1,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.loginFieldsPanel.GetSizer().Add(self.siteConfigPanel,proportion=0,flag=wx.EXPAND)

        self.loginHostPanel=wx.Panel(self.loginFieldsPanel,name='loginHostPanel')
        self.loginHostPanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        self.loginHostLabel = wx.StaticText(self.loginHostPanel, wx.ID_ANY, 'Server name or IP',name='label_loginHost')
        self.loginHostPanel.GetSizer().Add(self.loginHostLabel, proportion=1,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.loginHostTextField = wx.TextCtrl(self.loginHostPanel, wx.ID_ANY, size=(widgetWidth2, -1),name='jobParams_loginHost')
        self.loginHostPanel.GetSizer().Add(self.loginHostTextField, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.loginFieldsPanel.GetSizer().Add(self.loginHostPanel,proportion=0,flag=wx.EXPAND)


        self.usernamePanel=wx.Panel(self.loginFieldsPanel,name='usernamePanel')
        self.usernamePanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        self.usernameLabel = wx.StaticText(self.usernamePanel, wx.ID_ANY, 'Username',name='label_username')
        self.usernamePanel.GetSizer().Add(self.usernameLabel, proportion=1,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.usernameTextField = wx.TextCtrl(self.usernamePanel, wx.ID_ANY, size=(widgetWidth2, -1),name='jobParams_username')
        self.usernamePanel.GetSizer().Add(self.usernameTextField, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.loginFieldsPanel.GetSizer().Add(self.usernamePanel,proportion=0,flag=wx.EXPAND)

        self.projectPanel = wx.Panel(self.loginFieldsPanel,wx.ID_ANY,name="projectPanel")
        self.projectPanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        self.projectLabel = wx.StaticText(self.projectPanel, wx.ID_ANY, 'Project')
        self.projectPanel.GetSizer().Add(self.projectLabel, proportion=1, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL|wx.EXPAND, border=5)

        self.projectField = wx.TextCtrl(self.projectPanel, wx.ID_ANY, size=(widgetWidth2, -1), name='jobParams_project')
        #self.projectComboBox.Bind(wx.EVT_TEXT, self.onProjectTextChanged)
        self.projectPanel.GetSizer().Add(self.projectField, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.loginFieldsPanel.GetSizer().Add(self.projectPanel, proportion=0,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL)

        self.resourcePanel = wx.Panel(self.loginFieldsPanel, wx.ID_ANY,name="resourcePanel")
        self.resourcePanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))

        self.hoursLabel = wx.StaticText(self.resourcePanel, wx.ID_ANY, 'Hours requested')
        self.resourcePanel.GetSizer().Add(self.hoursLabel, proportion=1,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL,border=5)
        # Maximum of 336 hours is 2 weeks:
        #self.massiveHoursField = wx.SpinCtrl(self.massiveLoginFieldsPanel, wx.ID_ANY, value=self.massiveHoursRequested, min=1,max=336)
        self.hoursField = wx.SpinCtrl(self.resourcePanel, wx.ID_ANY, size=(widgetWidth3,-1), min=1,max=336,name='jobParams_hours')
        self.resourcePanel.GetSizer().Add(self.hoursField, proportion=0,flag=wx.TOP|wx.BOTTOM|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL,border=5)
        self.nodesLabel = wx.StaticText(self.resourcePanel, wx.ID_ANY, 'Nodes')
        self.resourcePanel.GetSizer().Add(self.nodesLabel, proportion=0,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL,border=5)
        self.nodesField = wx.SpinCtrl(self.resourcePanel, wx.ID_ANY, value="1", size=(widgetWidth3,-1), min=1,max=10,name='jobParams_nodes')
        self.resourcePanel.GetSizer().Add(self.nodesField, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.ppnLabel = wx.StaticText(self.resourcePanel, wx.ID_ANY, 'PPN',name='ppnLabel')
        self.resourcePanel.GetSizer().Add(self.ppnLabel, proportion=0,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL,border=5)
        self.ppnField = wx.SpinCtrl(self.resourcePanel, wx.ID_ANY, value="12", size=(widgetWidth3,-1), min=1,max=12,name='jobParams_ppn')
        self.resourcePanel.GetSizer().Add(self.ppnField, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.loginFieldsPanel.GetSizer().Add(self.resourcePanel, proportion=0,border=0,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL)


        self.resolutionPanel = wx.Panel(self.loginFieldsPanel,name="resolutionPanel")
        self.resolutionPanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        self.resolutionLabel = wx.StaticText(self.resolutionPanel, wx.ID_ANY, 'Resolution',name='label_resolution')
        self.resolutionPanel.GetSizer().Add(self.resolutionLabel, proportion=1,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL, border=5)


        defaultResolution = "Default resolution"
        vncDisplayResolutions = [
            defaultResolution, "1024x768", "1152x864", "1280x800", "1280x1024", "1360x768", "1366x768", "1440x900", "1600x900", "1680x1050", "1920x1080", "1920x1200", "7680x3200",
            ]
        self.resolutionField = wx.ComboBox(self.resolutionPanel, wx.ID_ANY, value=defaultResolution, choices=vncDisplayResolutions, size=(widgetWidth2, -1), style=wx.CB_DROPDOWN,name='jobParams_resolution')
        self.resolutionPanel.GetSizer().Add(self.resolutionField, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.loginFieldsPanel.GetSizer().Add(self.resolutionPanel,proportion=0,flag=wx.EXPAND)

        
        self.cipherPanel = wx.Panel(self.loginFieldsPanel,name="cipherPanel")
        self.cipherPanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        self.sshTunnelCipherLabel = wx.StaticText(self.cipherPanel, wx.ID_ANY, 'SSH tunnel cipher',name='label_cipher')
        self.cipherPanel.GetSizer().Add(self.sshTunnelCipherLabel, proportion=1,flag=wx.EXPAND|wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.ALIGN_CENTER_VERTICAL, border=5)

        if sys.platform.startswith("win"):
            defaultCipher = "arcfour"
            sshTunnelCiphers = ["3des-cbc", "aes128-cbc", "blowfish-cbc", "arcfour"]
        else:
            defaultCipher = "arcfour128"
            sshTunnelCiphers = ["3des-cbc", "aes128-cbc", "blowfish-cbc", "arcfour128"]
        self.sshTunnelCipherComboBox = wx.ComboBox(self.cipherPanel, wx.ID_ANY, value=defaultCipher, choices=sshTunnelCiphers, size=(widgetWidth2, -1), style=wx.CB_DROPDOWN,name='jobParams_cipher')
        self.cipherPanel.GetSizer().Add(self.sshTunnelCipherComboBox, proportion=0,flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT|wx.EXPAND|wx.ALIGN_CENTER_VERTICAL, border=5)
        self.loginFieldsPanel.GetSizer().Add(self.cipherPanel,proportion=0,flag=wx.EXPAND)
        self.checkBoxPanel = wx.Panel(self.loginFieldsPanel,name="checkBoxPanel")
        self.checkBoxPanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        
        p = wx.Panel(self.checkBoxPanel,name="debugCheckBoxPanel")
        p.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        l = wx.StaticText(p, wx.ID_ANY, 'Show debug window')
        c = wx.CheckBox(p, wx.ID_ANY, "",name='debugCheckBox')
        c.Bind(wx.EVT_CHECKBOX, self.onDebugWindowCheckBoxStateChanged)
        p.GetSizer().Add(l,border=5,flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT)
        p.GetSizer().Add(c,border=5,flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT)
        self.checkBoxPanel.GetSizer().Add(p,flag=wx.ALIGN_LEFT)
    
        t=wx.StaticText(self.checkBoxPanel,label="")
        self.checkBoxPanel.GetSizer().Add(t,proportion=1,flag=wx.EXPAND)
  
        p = wx.Panel(self.checkBoxPanel,name="advancedCheckBoxPanel")
        p.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
        l = wx.StaticText(p, wx.ID_ANY, 'Show Advanced Options')
        c = wx.CheckBox(p, wx.ID_ANY, "",name='advancedCheckBox')
        c.Bind(wx.EVT_CHECKBOX, self.onAdvancedVisibilityStateChanged)
        p.GetSizer().Add(l,border=5,flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT)
        p.GetSizer().Add(c,border=5,flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT)
        self.checkBoxPanel.GetSizer().Add(p,flag=wx.ALIGN_RIGHT)

        self.loginFieldsPanel.GetSizer().Add(self.checkBoxPanel,flag=wx.ALIGN_BOTTOM|wx.EXPAND,proportion=1)

        #self.tabbedView.AddPage(self.loginFieldsPanel, "Login")

        #self.loginDialogPanelSizer.Add(self.tabbedView, flag=wx.EXPAND|wx.TOP|wx.LEFT|wx.RIGHT, border=10)

        # Buttons Panel

        self.buttonsPanel = wx.Panel(self.loginDialogPanel, wx.ID_ANY)
        #self.buttonsPanel.SetSizer(wx.FlexGridSizer(rows=1, cols=4, vgap=5, hgap=10))
        self.buttonsPanel.SetSizer(wx.BoxSizer(wx.HORIZONTAL))

        self.exitButton = wx.Button(self.buttonsPanel, wx.ID_ANY, 'Exit')
        self.buttonsPanel.GetSizer().Add(self.exitButton, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT, border=10)
        self.Bind(wx.EVT_BUTTON, self.onExit,  id=self.exitButton.GetId())

        self.loginButton = wx.Button(self.buttonsPanel, wx.ID_ANY, 'Login')
        self.buttonsPanel.GetSizer().Add(self.loginButton, flag=wx.TOP|wx.BOTTOM|wx.LEFT|wx.RIGHT, border=10)
        self.loginButton.Bind(wx.EVT_BUTTON, self.savePrefsEventHandler)
        self.loginButton.Bind(wx.EVT_BUTTON, self.onLogin)
        self.loginButton.SetDefault()


        #self.preferencesButton.Show(False)

        self.loginDialogPanel.GetSizer().Add(self.buttonsPanel, flag=wx.ALIGN_RIGHT|wx.BOTTOM|wx.LEFT|wx.RIGHT, border=15)

        self.loginDialogStatusBar = LauncherStatusBar(self)


        #self.Fit()
        #self.Layout()
        #self.menu_bar.Show(False)

        #self.Centre()

        self.logWindow = wx.Frame(self, title="%s Debug Log"%self.programName, name="%s Debug Log"%self.programName,pos=(200,150),size=(700,450))
        self.logWindow.Bind(wx.EVT_CLOSE, self.onCloseDebugWindow)
        self.logWindowPanel = wx.Panel(self.logWindow)
        self.logTextCtrl = wx.TextCtrl(self.logWindowPanel, style=wx.TE_MULTILINE|wx.TE_READONLY)
        logWindowSizer = wx.FlexGridSizer(rows=2, cols=1, vgap=0, hgap=0)
        logWindowSizer.AddGrowableRow(0)
        logWindowSizer.AddGrowableCol(0)
        logWindowSizer.Add(self.logTextCtrl, flag=wx.EXPAND)
        self.submitDebugLogButton = wx.Button(self.logWindowPanel, wx.ID_ANY, 'Submit debug log')
        self.Bind(wx.EVT_BUTTON, self.onSubmitDebugLog, id=self.submitDebugLogButton.GetId())
        logWindowSizer.Add(self.submitDebugLogButton, flag=wx.ALIGN_RIGHT|wx.TOP|wx.BOTTOM|wx.RIGHT, border=10)
        self.logWindowPanel.SetSizer(logWindowSizer)
        if sys.platform.startswith("darwin"):
            font = wx.Font(13, wx.MODERN, wx.NORMAL, wx.NORMAL, False, u'Courier New')
        else:
            font = wx.Font(11, wx.MODERN, wx.NORMAL, wx.NORMAL, False, u'Courier New')
        self.logTextCtrl.SetFont(font)

        if sys.platform.startswith("win"):
            _icon = wx.Icon('MASSIVE.ico', wx.BITMAP_TYPE_ICO)
            self.logWindow.SetIcon(_icon)

        if sys.platform.startswith("linux"):
            import MASSIVE_icon
            self.logWindow.SetIcon(MASSIVE_icon.getMASSIVElogoTransparent128x128Icon())

        logger.sendLogMessagesToDebugWindowTextControl(self.logTextCtrl)

        import getpass
        logger.debug('getpass.getuser(): ' + getpass.getuser())

        logger.debug('sys.platform: ' + sys.platform)

        import platform

        logger.debug('platform.architecture: '  + str(platform.architecture()))
        logger.debug('platform.machine: '       + str(platform.machine()))
        logger.debug('platform.node: '          + str(platform.node()))
        logger.debug('platform.platform: '      + str(platform.platform()))
        logger.debug('platform.processor: '     + str(platform.processor()))
        logger.debug('platform.release: '       + str(platform.release()))
        logger.debug('platform.system: '        + str(platform.system()))
        logger.debug('platform.version: '       + str(platform.version()))
        logger.debug('platform.uname: '         + str(platform.uname()))

        if sys.platform.startswith("win"):
            logger.debug('platform.win32_ver: ' + str(platform.win32_ver()))

        if sys.platform.startswith("darwin"):
            logger.debug('platform.mac_ver: ' + str(platform.mac_ver()))

        if sys.platform.startswith("linux"):
            logger.debug('platform.linux_distribution: ' + str(platform.linux_distribution()))
            logger.debug('platform.libc_ver: ' + str(platform.libc_ver()))

        logger.debug('launcher_version_number.version_number: ' + launcher_version_number.version_number)
        import commit_def
        logger.debug('launcher commit hash: ' + commit_def.LATEST_COMMIT)
        logger.debug('cvlsshutils commit hash: ' + commit_def.LATEST_COMMIT_CVLSSHUTILS)
        self.contacted_massive_website = False

        self.Bind(wx.EVT_CLOSE,self.onExit)
        self.startupinfo = None
        try:
            self.startupinfo = subprocess.STARTUPINFO()
            self.startupinfo.dwFlags |= subprocess._subprocess.STARTF_USESHOWWINDOW
            self.startupinfo.wShowWindow = subprocess.SW_HIDE
        except:
            # On non-Windows systems, the previous block will throw:
            # "AttributeError: 'module' object has no attribute 'STARTUPINFO'".
            if sys.platform.startswith("win"):
                logger.debug('exception: ' + str(traceback.format_exc()))

        self.creationflags = 0
        try:
            import win32process
            self.creationflags = win32process.CREATE_NO_WINDOW
        except:
            # On non-Windows systems, the previous block will throw an exception.
            if sys.platform.startswith("win"):
                logger.debug('exception: ' + str(traceback.format_exc()))

        # launcherMainFrame.keyModel must be initialized before the
        # user presses the Login button, because the user might
        # use the Identity Menu to delete their key etc. before
        # pressing the Login button.
        self.keyModel = KeyModel(startupinfo=self.startupinfo,creationflags=self.creationflags,temporaryKey=False)

        #self.loadPrefs()

    def manageSitesEventHandler(self,event):
        t=threading.Thread(target=self.manageSites)
        t.start()

    def getSitePrefs(self,queue):
        options = self.getPrefsSection('configured_sites')
        siteList=[]
        for s in options.keys():
            if 'siteurl' in s:
                site=options[s]
                number=int(s[7:])
                enabled=options['siteenabled%i'%number]
                if enabled=='True':
                    enabled=True
                elif enabled=='False':
                    enabled=False
                name=options['sitename%i'%number]
                siteList.append({'url':site,'enabled':enabled,'name':name,'number':number})
                siteList.sort(key=lambda x:x['number'])
        queue.put(siteList)

    def getNewSites(self,queue):
        newlist=[]
        try:
            if sys.platform.startswith("linux"):
                f=open(os.path.join(sys.path[0],"masterList.url"),'r')
            else:
                f=open("masterList.url",'r')
            url=f.read().rstrip()
            logger.debug("master list of sites is available at %s"%url)
            newlist=siteConfig.getMasterSites(url)
            queue.put(newlist)
        except requests.exceptions.RequestException as e:
            logger.debug("getNewSites: Exception %s"%e)
            logger.debug("getNewSites: Traceback %s"%traceback.format_exc())
            queue.put(None)
        except Exception as e:
            logger.debug("getNewSites: Exception %s"%e)
            logger.debug("getNewSites: Traceback %s"%traceback.format_exc())
            queue.put(None)
        finally:
            f.close()

    def showSiteListDialog(self,siteList,newlist,q):
        import siteListDialog
        dlg=siteListDialog.siteListDialog(parent=self,siteList=siteList,newSites=newlist,style=wx.DEFAULT_DIALOG_STYLE|wx.RESIZE_BORDER)
        r=dlg.ShowModal()
        q.put([r,dlg.getList()])

    def loadNewSitesNonBlocking(self,time=None):
        r=Queue.Queue()
        timeoutObject=object()
        threading.Thread(target=self.getNewSites,args=[r]).start()
        if time!=None:
            timer=threading.Timer(time,r.put,args=[timeoutObject])
            timer.start()
        dq=Queue.Queue()
        wx.CallAfter(self.createMultiButtonDialog,parent=self,title="",message=dialogs.loadingSiteList.message,ButtonLabels=dialogs.loadingSiteList.ButtonLabels,q=dq)
        progressdlg=dq.get()
        wx.CallAfter(self.showModalFromThread,progressdlg,r)
        wx.CallAfter(wx.BeginBusyCursor)
        newlist=r.get()
        wx.CallAfter(wx.EndBusyCursor)
        try:
            wx.CallAfter(progressdlg.EndModal,wx.ID_OK)
        except:
            pass
        if isinstance(newlist,type([])):
            pass
        elif newlist == timeoutObject:
            raise siteConfig.TimeoutException("Timeout loading new sites")
        elif newlist == None:
            raise siteConfig.TimeoutException("Timeout loading new sites")
        elif isinstance(newlist,type("")):
            raise siteConfig.StatusCode(newlist)
        else:
            raise siteConfig.CancelException("Canceled load new sites")
        return newlist

    def manageSites(self):
        siteList=[]
        tlist=[]

        retry=True
        try:
            newlist=self.loadNewSitesNonBlocking(time=10)
        except siteConfig.CancelException:
            newlist=[]
            retry=False
        except siteConfig.TimeoutException:
            newlist=[]
            retry=True
        except siteConfig.StatusCode as e:
            newlist=[]
            retry=False
            dq=Queue.Queue()
            wx.CallAfter(self.createMultiButtonDialog,parent=self,title="",message=dialogs.siteListOtherException.message,ButtonLabels=dialogs.siteListOtherException.ButtonLabels,q=dq)
            dlg=dq.get()
            q=Queue.Queue()
            wx.CallAfter(self.showModalFromThread,dlg,q)
            button=q.get()


        q=Queue.Queue()
        threading.Thread(target=self.getSitePrefs,args=[q]).start()
        wx.CallAfter(wx.BeginBusyCursor)
        origSiteList=q.get()
        wx.CallAfter(wx.EndBusyCursor)

        if origSiteList==[] and newlist==[] and retry==True:


            q=Queue.Queue()
            dq=Queue.Queue()
            wx.CallAfter(self.createMultiButtonDialog,parent=self,title="",message=dialogs.siteListRetry.message,ButtonLabels=dialogs.siteListRetry.ButtonLabels,q=dq)
            dlg=dq.get()
            wx.CallAfter(self.showModalFromThread,dlg,q)
            button=q.get()
            if button==0:
                retry=False
            while retry:
                try:
                    newlist=self.loadNewSitesNonBlocking(time=None)
                    if isinstance(newlist,type([])) and newlist!=[]:
                        retry=False
                    if newlist==None:
                        retry=True
                except Exception as e:
                    logger.debug("getNewSites: Exception %s"%e)
                    logger.debug("getNewSites: Traceback %s"%traceback.format_exc())
                    q=Queue.Queue()
                    dq=Queue.Queue()
                    wx.CallAfter(self.createMultiButtonDialog,parent=self,title="",message=dialogs.siteListOtherException.message,ButtonLabels=dialogs.siteListOtherException.ButtonLabels,q=dq)
                    dlg=dq.get()
                    wx.CallAfter(self.showModalFromThread,dlg,q)
                    button=q.get()
                    retry=False
                if retry:
                    wx.CallAfter(self.showModalFromThread,dlg,q)
                    button=q.get()
                    if button==0:
                        retry=False
                

        q=Queue.Queue()

        import copy
        for newsite in newlist:
            if newsite.has_key('replaces'):
                replaced=False
                urls=newsite['replaces']
                siteListCopy=copy.copy(origSiteList)
                for site in siteListCopy:
                    if site['url'] in urls:
                        if not newsite.has_key('enabled'):
                            newsite['enabled']=site['enabled']
                        origSiteList.remove(site)

        wx.CallAfter(self.showSiteListDialog,origSiteList,newlist,q)
        r=q.get()
        if (r[0] == wx.ID_OK):
            newSiteList=r[1]
            changed=False
            if len(newSiteList) == len(origSiteList):
                for i in range(0,len(newSiteList)):
                    if newSiteList[i]['url']!=origSiteList[i]['url'] or newSiteList[i]['enabled']!=origSiteList[i]['enabled'] or newSiteList[i]['name']!=origSiteList[i]['name']:
                        changed=True
            else:
                changed=True
            if changed:
                options={}
                i=0
                for s in newSiteList:
                    options['siteurl%i'%i]='%s'%s['url']
                    options['siteenabled%i'%i]='%s'%s['enabled']
                    options['sitename%i'%i]='%s'%s['name']
                    i=i+1

                self.prefs.remove_section('configured_sites')
                self.setPrefsSection('configured_sites',options)
                self.savePrefs(section='configured_sites')

                launcherMainFrame.loadDefaultSessions(True)

    def loadSessionEvent(self,event):
        dlg=wx.FileDialog(self,"Load a session",style=wx.FD_OPEN)
        status=dlg.ShowModal()
        if status==wx.ID_CANCEL:
            logger.debug('loadSession cancled')
        f=open(dlg.GetPath(),'r')
        self.loadSession(f)
        f.close()

    def loadSession(self,f,path=None):
        import json
        if path!=None:
            f=open(path,'r')
        saved=siteConfig.GenericJSONDecoder().decode(f.read())
        if isinstance(saved,list):
            self.sites={}
            keyorder=saved[0]
            for key in keyorder:
                    nk = key
                    i=1
                    while nk in self.sites.keys():
                        i=i+1
                        nk = key+" %s"%i
                    self.sites[nk]=saved[1][key]
        else:
            self.sites=saved
        cb=self.FindWindowByName('jobParams_configName')
        for i in range(0,cb.GetCount()):
            cb.Delete(0)
        for s in self.sites.keys():
            cb.Append(s)
        cb.SetSelection(0)
        if path!=None:
            f.close()
        self.updateVisibility()


    def createMultiButtonDialog(self,q,*args,**kwargs):
        dlg=LauncherOptionsDialog.multiButtonDialog(*args,**kwargs)
        q.put(dlg)

    def showModalFromThread(self,dlg,q):
        r=dlg.ShowModal()
        q.put(r)

    def loadDefaultSessions(self,redraw=True):
        sites=self.getPrefsSection(section='configured_sites')
        retry=True
        while sites.keys() == [] and retry:
            q=Queue.Queue()
            dq=Queue.Queue()
            wx.CallAfter(self.createMultiButtonDialog,parent=self,message=dialogs.siteListFirstUseInfo.message,ButtonLabels=dialogs.siteListFirstUseInfo.ButtonLabels,title="",q=dq)
            dlg=dq.get()
            wx.CallAfter(self.showModalFromThread,dlg,q)
            button=q.get()
            if button==0:
                retry=False
            else:
                self.manageSites()
                sites=self.getPrefsSection(section='configured_sites')
            
        wx.CallAfter(wx.BeginBusyCursor)
        q=Queue.Queue()
        wx.CallAfter(self.createMultiButtonDialog,parent=self,title="",message=dialogs.loadingFlavours.message,ButtonLabels=dialogs.loadingFlavours.ButtonLabels,q=q)
        dlg=q.get()
        wx.CallAfter(dlg.ShowModal)
        self.sites=siteConfig.getSites(self.prefs,os.path.dirname(launcherPreferencesFilePath))
        wx.CallAfter(dlg.EndModal,0)
        wx.CallAfter(wx.EndBusyCursor)
        wx.CallAfter(self.loadDefaultSessionsGUI,redraw)

    def loadDefaultSessionsGUI(self,redraw):
        cb=self.FindWindowByName('jobParams_configName')
        # attempt to preserve the selection on the combo box if the site remains in the list. If not, set the selection to 0
        try:
            sn=cb.GetValue()
        except:
            sn=''
                    
        
        if (sn==None or sn==""):
            if self.prefs.has_option("Launcher Config","siteConfigDefault"):
                sn = self.prefs.get("Launcher Config","siteConfigDefault")


        for i in range(0,cb.GetCount()):
            cb.Delete(0)
        for s in self.sites.keys():
            cb.Append(s)
        if sn!=None and sn in self.sites.keys():
            cb.SetValue(sn)
        else:
            try:
                if len(self.sites.keys())>0:
                    cb.SetSelection(0)
                else:
                    logger.debug("unable to set the default flavour. Apparently there are no flavours available")  
            except:
                logger.debug("unable to set the default flavour. Apparently there are no flavours available")  
            
        #cb.SetSelection(0)
        if (redraw):
            self.loadPrefs()
            self.updateVisibility()
        #    self.updateVisibility(self.noneVisible)

    def loadDefaultSessionsEvent(self,event):
        t=threading.Thread(target=self.loadDefaultSessions,args=[True])
        t.start()

    def saveSessionEvent(self,event):
        self.saveSession()


    def saveSessionThreadTarget(self,q):
        filename = q.get(block=True)
        sc = q.get(block=True)
        if sc!=None and filename!=None:
            try:
                f=open(filename,'w')
                logger.debug('opened file %s to save the session to'%filename)
            except Exception as e:
                logger.debug('error opening file for saving')
                raise e
            logger.debug('retrieved the session configuration from the loginProcess')
        if sc==None:
            sc=q.get()
        if sc==None:
            return
        mydict={}
        mydict['Saved Session']=sc
        import json
        s=json.dumps(mydict,f,cls=siteConfig.GenericJSONEncoder,sort_keys=True,indent=4,separators=(',',': '))
        f.write(s)
        f.close()

        


    def saveSession(self):
        import Queue
        q=Queue.Queue()
        dlg=wx.FileDialog(self,"Save your desktop session",style=wx.FD_SAVE|wx.FD_OVERWRITE_PROMPT)
        status=dlg.ShowModal()
        if status==wx.ID_CANCEL:
            logger.debug('saveSession canceled')
            return
        filename=dlg.GetPath()
        q.put(filename)
        # Abuse of queue.get as a flow control mechanism.
        t=threading.Thread(target=self.loginProcess[0].getSharedSession,args=[q])
        t.start()
        t=threading.Thread(target=self.saveSessionThreadTarget,args=[q])
        t.start()

    def checkVersionNumber(self):
        # Check for the latest version of the launcher:
        try:
            myHtmlParser = MyHtmlParser('MassiveLauncherLatestVersionNumber')
            feed = urllib2.urlopen(LAUNCHER_URL, timeout=10)
            html = feed.read()
            myHtmlParser.feed(html)
            myHtmlParser.close()

            latestVersionNumber = myHtmlParser.latestVersionNumber
            htmlComments = myHtmlParser.htmlComments
            htmlCommentsSplit1 = htmlComments.split("<pre id=\"CHANGES\">")
            htmlCommentsSplit2 = htmlCommentsSplit1[1].split("</pre>")
            latestVersionChanges = htmlCommentsSplit2[0].strip()
            self.contacted_massive_website = True
        except:
            logger.debug(traceback.format_exc())
            self.contacted_massive_website = False
            dlg = wx.MessageDialog(self, "Warning: Could not contact the MASSIVE website to check version number.\n\n",
                                "%s"%self.programName, wx.OK | wx.ICON_INFORMATION)
            wx.CallAfter(dlg.ShowModal)

            latestVersionNumber = launcher_version_number.version_number
            latestVersionChanges = ''

        if latestVersionNumber > launcher_version_number.version_number:
            import new_version_alert_dialog
            newVersionAlertDialog = new_version_alert_dialog.NewVersionAlertDialog(self, wx.ID_ANY, self.programName, latestVersionNumber, latestVersionChanges, LAUNCHER_URL)
            wx.CallAfter(newVersionAlertDialog.ShowModal)
            logger.debug('Old launcher version !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
            logger.debug('launcher version: ' + str(launcher_version_number.version_number))


    def buildJobParams(self,window):
        jobParams={}
        for item in window.GetChildren():
            name = item.GetName()
            if ('jobParam' in name):
                (prefix,keyname) = name.split('_') 
                jobParams[keyname]=item.GetValue()
            r = self.buildJobParams(item)
            jobParams.update(r)
        if jobParams.has_key('resolution'):
            try:
                a=int(jobParams['resolution'][0])
            except:
                displaySize = wx.DisplaySize()
                desiredWidth = displaySize[0] * 0.99
                desiredHeight = displaySize[1] * 0.85
                jobParams['resolution'] = str(int(desiredWidth)) + "x" + str(int(desiredHeight))

        return jobParams

    def onSiteConfigChanged(self,event):
        self.Freeze()
        self.loadPrefs(site=event.GetEventObject().GetValue())
        self.updateVisibility()
        self.Thaw()
        self.configName=self.FindWindowByName('jobParams_configName').GetValue()


    def onAdvancedVisibilityStateChanged(self, event):
        self.updateVisibility()

    def showAll(self,window=None):
        if window==None:
            window=self
        window.Show(True)
        for p in window.GetChildren():
            self.showAll(p)

    def updateVisibility(self,visible=None):
        #self.showAll()
        #self.Fit()
        #self.Layout()
        advanced=self.FindWindowByName('advancedCheckBox').GetValue()
        if visible==None:
            try:
                sc=None
                sc=self.FindWindowByName('jobParams_configName').GetValue()
                visible = self.sites[sc].visibility
            except Exception as e:
                logger.debug('updateVisibility: looking for site %s'%sc)
                logger.debug('updateVisibility: no visibility information associated with the siteConfig configName: %s'%sc)
                logger.debug("sc: %s exception:%s"%(sc,e))
                visible={}
        for key in visible.keys():
            try:
                window=self.FindWindowByName(key) #Panels and controls are all subclasses of windows
                if visible[key]==False:
                    window.Hide()
                if visible[key]==True:
                    window.Show()
                if visible[key]=='Advanced' and advanced==True:
                    window.Show()
                if visible[key]=='Advanced' and advanced==False:
                    window.Hide()
            except:
                pass # a value in the dictionary didn't correspond to a named component of the panel. Fail silently.
        self.logWindow.Show(self.FindWindowByName('debugCheckBox').GetValue())

    def onDebugWindowCheckBoxStateChanged(self, event):
        self.logWindow.Show(event.GetEventObject().GetValue())

    def onCloseDebugWindow(self, event):
        self.FindWindowByName('debugCheckBox').SetValue(False)
        self.logWindow.Show(False)

    def onHelpContents(self, event):
        from help.HelpController import helpController
        if helpController is not None and helpController.initializationSucceeded:
            helpController.DisplayContents()
        else:
            wx.MessageBox("Unable to open: " + helpController.launcherHelpUrl,
                          "Error", wx.OK|wx.ICON_EXCLAMATION)

    def onEmailHelpAtMassive(self, event):
        import webbrowser
        webbrowser.open("mailto:help@massive.org.au")

    def onEmailCvlHelpAtMonash(self, event):
        import webbrowser
        webbrowser.open("mailto:cvl-help@monash.edu")

    def onSubmitDebugLog(self, event):
        logger.dump_log(launcherMainFrame,submit_log=True,showFailedToOpenRemoteDesktopMessage=False)

    def onAbout(self, event):
        dlg = LauncherMessageDialog(self, dialogs.aboutMessage.message, self.programName, helpEmailAddress="cvl-help@massive.org.au" )
        dlg.ShowModal()
        dlg.Destroy()

    def onExit(self, event):
        # Clean-up (including qdel if necessary) is now done in LoginTasks.py
        # No longer using temporary private key file, 
        # so there's no need to delete it as part of clean-up.
        if len(self.loginProcess)>0:
            dlg=LauncherOptionsDialog.multiButtonDialog(parent=self,message=dialogs.confirmQuit.message,ButtonLabels=dialogs.confirmQuit.ButtonLabels,title="")
            if dlg.ShowModal()==1:
                return
        for lp in self.loginProcess:
            logger.debug("LauncherMainFrame.onExit: calling shutdown on a loginprocess")
            lp.shutdown()

        try:
            if hasattr(self, 'loginProcess') and self.loginProcess is not None:
                logger.debug("launcher.py: onExit: Calling self.loginProcess.shutdownReal().")
                self.loginProcess.shutdownReal()
            else:
                logger.debug("launcher.py: onExit: Didn't find a login process to shut down.")

            logger.dump_log(launcherMainFrame)
        finally:
            os._exit(0)


    def onOptions(self, event, tabIndex=0):

        options = self.getPrefsSection("Global Preferences")
        dlg = optionsDialog.GlobalOptionsDialog(self,wx.ID_ANY,"Global Options",options,tabIndex)
        rv = dlg.ShowModal()
        if rv == wx.OK:
            options = dlg.getOptions()
            self.setPrefsSection("Global Preferences",options)
            self.savePrefs(section="Global Preferences")
        dlg.Destroy()
        auth_mode = int(self.getPrefsSection('Global Preferences')['auth_mode'])
        self.identity_menu.setRadio(auth_mode)
        self.identity_menu.disableItems(auth_mode)

    def onCut(self, event):
        textCtrl = self.FindFocus()
        if textCtrl is not None:
            textCtrl.Cut()

    def onCopy(self, event):
        textCtrl = self.FindFocus()
        if textCtrl is not None:
            textCtrl.Copy()

    def onPaste(self, event):
        textCtrl = self.FindFocus()
        if textCtrl is not None:
            textCtrl.Paste()

    def onSelectAll(self, event):
        textCtrl = self.FindFocus()
        if textCtrl is not None:
            textCtrl.SelectAll()

    def SetCursor(self, cursor):
        self.massiveLoginDialogPanel.SetCursor(cursor)
        self.massiveLoginFieldsPanel.SetCursor(cursor)
        self.massiveLoginHostLabel.SetCursor(cursor)
        self.massiveProjectLabel.SetCursor(cursor)
        self.massiveHoursLabel.SetCursor(cursor)
        self.massiveVncDisplayResolutionLabel.SetCursor(cursor)
        self.massiveSshTunnelCipherLabel.SetCursor(cursor)
        self.massiveUsernameLabel.SetCursor(cursor)
        self.massiveLoginHostComboBox.SetCursor(cursor)
        self.massiveVncDisplayResolutionComboBox.SetCursor(cursor)
        self.massiveSshTunnelCipherComboBox.SetCursor(cursor)
        self.massiveProjectComboBox.SetCursor(cursor)
        self.massiveHoursField.SetCursor(cursor)
        self.massiveUsernameTextField.SetCursor(cursor)

        self.cvlLoginDialogPanel.SetCursor(cursor)
        self.cvlSimpleLoginFieldsPanel.SetCursor(cursor)
        self.cvlAdvancedLoginFieldsPanel.SetCursor(cursor)
        self.cvlConnectionProfileLabel.SetCursor(cursor)
        self.cvlConnectionProfileComboBox.SetCursor(cursor)
        self.cvlUsernameLabel.SetCursor(cursor)
        self.cvlUsernameTextField.SetCursor(cursor)
        self.cvlVncDisplayResolutionLabel.SetCursor(cursor)
        self.cvlVncDisplayResolutionComboBox.SetCursor(cursor)
        self.cvlSshTunnelCipherLabel.SetCursor(cursor)
        self.cvlSshTunnelCipherComboBox.SetCursor(cursor)

        self.buttonsPanel.SetCursor(cursor)
        self.preferencesButton.SetCursor(cursor)
        self.exitButton.SetCursor(cursor)
        self.loginButton.SetCursor(cursor)

        if self.progressDialog!=None:
            self.progressDialog.SetCursor(cursor)

        super(LauncherMainFrame, self).SetCursor(cursor)

    def queryAuthMode(self):
        var='auth_mode'
        options=self.getPrefsSection('Global Preferences')
        # Create a dialog that will never be shown just so we get an authorative list of options
        dlg = optionsDialog.GlobalOptionsDialog(self,wx.ID_ANY,"Global Options",options,0)
        auth_mode=dlg.FindWindowByName(var)
        choices=[]
        nmodes=auth_mode.GetCount()
        for i in range(0,nmodes):
            choices.append(auth_mode.GetString(i))
        dlg.Destroy()
        configName=self.FindWindowByName('jobParams_configName').GetValue()
        dlg = LauncherOptionsDialog.multiButtonDialog(launcherMainFrame,message=dialogs.queryAuthMode.message,title=self.programName,ButtonLabels=choices,helpEmailAddress=self.sites[configName].displayStrings.helpEmailAddress)
        rv=dlg.ShowModal()
        if rv in range(0,nmodes):
            options['auth_mode'] = int(rv)
            self.setPrefsSection('Global Preferences',options)
            self.identity_menu.setRadio(rv)
            self.identity_menu.disableItems(rv)
            return int(rv)
        else:
            self.queryAuthMode()
    def loginComplete(self,lp,oldParams,jobParams):
        shouldSave=False
        for k in jobParams:
            if oldParams.has_key(k): 
                # This is a bit messy, but some of our parameters get converted from ints to strings
                # Specifically nodes is requsted as an int from a SpinCtrl but is updated to a string from the output of qstat.
                if not oldParams[k] == jobParams[k] and isinstance(oldParams[k],type(jobParams[k])):
                    winName='jobParams_%s'%k
                    try:
                        self.FindWindowByName(winName).SetValue(jobParams[k])
                        shouldSave=True
                    except Exception as e:
                        logger.debug("launcher: Couldn't update the parameter %s %s %s"%(k,e,e.__class__))
                        pass
                elif isinstance(oldParams[k],int) and int(jobParams[k])!= oldParams[k]:
                    try:
                        self.FindWindowByName(winName).SetValue(int(jobParams[k]))
                        shouldSave=True
                    except Exception as e:
                        logger.debug("launcher: Couldn't update the parameter %s %s %s"%(k,e,e.__class__))
                        pass
        try:
            self.loginProcess.remove(lp)
        except:
            logger.debug("launcher: Couldn't remove the loginprocess")
        if shouldSave:
            wx.CallAfter(self.Refresh)
            threading.Thread(target=self.savePrefs).start()
        self.loginButton.Enable()
        options = self.getPrefsSection("Global Preferences")
        if int(options['logstats'])==0:
            import StatsLogger
            statslogger=StatsLogger.StatsLogger(options['uuid'],success=True,jobParams=jobParams)
            threading.Thread(target=statslogger.post,args=["https://cvl.massive.org.au/logstats"]).start()

    def loginCancel(self,lp,oldParams,jobParams):
        self.loginProcess.remove(lp)
        self.loginButton.Enable()
        options = self.getPrefsSection("Global Preferences")
        if int(options['logstats'])==0:
            import StatsLogger
            statslogger=StatsLogger.StatsLogger(options['uuid'],success=False,jobParams=jobParams)
            threading.Thread(target=statslogger.post,args=["https://cvl.massive.org.au/logstats"]).start()


    def onLoginProcessComplete(self, jobParams):
        self.loginProcess = None
        logger.debug("launcher.py: onLogin: Enabling login button.")
        # The refresh below is a workaround for a Windows bug where a
        # dark-coloured rectangle appears in the middle of the main
        # dialog's current panel after a completed or canceled login session:
        self.massiveLoginDialogPanel.Refresh()
        self.cvlLoginDialogPanel.Refresh()
        self.loginButton.Enable()

    def onLogin(self, event):

        logger.debug("launcher.py: onLogin: Disabling login button.")
        self.loginButton.Disable()

        configName=self.FindWindowByName('jobParams_configName').GetValue()
        if configName=="" or configName==None:
            dlg=LauncherMessageDialog(self,"Please select a site to log into first","Please select a site")
            dlg.ShowModal()
            return
        jobParams={}
        import platform
        platformstr="\""
        platformstr=platformstr+'platform.machine: '       + str(platform.machine())
        platformstr=platformstr+' platform.node: '          + str(platform.node())
        platformstr=platformstr+' platform.platform: '      + str(platform.platform())
        platformstr=platformstr+' platform.processor: '     + str(platform.processor())
        platformstr=platformstr+' platform.release: '       + str(platform.release())
        platformstr=platformstr+' platform.system: '        + str(platform.system())
        platformstr=platformstr+' platform.version: '       + str(platform.version())
        platformstr=platformstr+"\""
        jobParams = self.buildJobParams(self)
        if jobParams['username'] == "":
            dlg = LauncherMessageDialog(self,
                    "Please enter your username.",
                    #"MASSIVE/CVL Launcher", style=wx.OK | wx.ICON_INFORMATION)
                    self.programName)
            dlg.ShowModal()
            self.loginButton.Enable()
            usernamefield = self.FindWindowByName('jobParams_username')
            usernamefield.SetFocus()
            return


        logger.debug("Username: " + jobParams['username'])
        logger.debug("Config: " + configName)

        userCanAbort=True
        maximumProgressBarValue = 10

        dotSshDir = os.path.join(os.path.expanduser('~'), '.ssh')
        if not os.path.exists(dotSshDir):
            os.makedirs(dotSshDir)

        # project hours and nodes will be ignored for the CVL login, but they will be used for Massive.
        configName=self.FindWindowByName('jobParams_configName').GetValue()
        options=self.getPrefsSection('Global Preferences')
        self.savePrefs(section="Global Preferences")
        if not options.has_key('auth_mode'):
            mode=self.queryAuthMode()
            if mode==wx.ID_CANCEL:
                self.onLoginProcessComplete(None)
                return
            options['auth_mode']=mode
            self.setPrefsSection('Global Preferences',options)
            self.savePrefs(section="Global Preferences")
            self.identity_menu.disableItems(mode)
#        if not options.has_key('logstats'):
#            options['logstats']=0
        dlg = optionsDialog.GlobalOptionsDialog(self,wx.ID_ANY,"Global Options",options,0)
        dlg.saveOptions()
        options=dlg.getOptions()
        self.setPrefsSection('Global Preferences',options)
        self.savePrefs(section="Global Preferences")
        jobParams=self.buildJobParams(self)
        jobParams['wallseconds']=int(jobParams['hours'])*60*60
        if int(options['auth_mode'])==LauncherMainFrame.TEMP_SSH_KEY:
            logger.debug("launcherMainFrame.onLogin: using a temporary Key pair")
            try:
                if 'SSH_AUTH_SOCK' in os.environ:
                    os.environ['PREVIOUS_SSH_AUTH_SOCK'] = os.environ['SSH_AUTH_SOCK']
                del os.environ['SSH_AUTH_SOCK']
                logger.debug("launcherMainFrame.onLogin: spawning an ssh-agent (not using the existing agent)")
            except:
                logger.debug("launcherMainFrame.onLogin: spawning an ssh-agent (no existing agent found)")
                pass
            self.keyModel=KeyModel(temporaryKey=True,startupinfo=self.startupinfo)
            removeKeyOnExit = True
        else:
            logger.debug("launcherMainFrame.onLogin: using a permanent Key pair")
            self.keyModel=KeyModel(temporaryKey=False,startupinfo=self.startupinfo)
        jobParams=self.buildJobParams(self)
        jobParams['strudel_platform']=platformstr
        jobParams['wallseconds']=int(jobParams['hours'])*60*60
        self.configName=self.FindWindowByName('jobParams_configName').GetValue()
        autoExit=False
        globalOptions = self.getPrefsSection("Global Preferences")
        lp=LoginTasks.LoginProcess(self,jobParams,self.keyModel,siteConfig=self.sites[self.configName],displayStrings=self.sites[self.configName].displayStrings,autoExit=autoExit,globalOptions=globalOptions,startupinfo=self.startupinfo)
        oldParams  = jobParams.copy()
        lp.setCallback(lambda jobParams: self.loginComplete(lp,oldParams,jobParams))
        lp.setCancelCallback(lambda jobParams: self.loginCancel(lp,oldParams,jobParams))
        self.loginProcess.append(lp)
        lp.doLogin()
        event.Skip()

class LauncherStatusBar(wx.StatusBar):
    def __init__(self, parent):
        wx.StatusBar.__init__(self, parent)

        self.SetFieldsCount(2)
        #self.SetStatusText('Welcome to MASSIVE', 0)
        self.SetStatusWidths([-5, -2])

class MyApp(wx.App):
    def OnInit(self):

        appDirs = appdirs.AppDirs("strudel", "Monash University")
        appUserDataDir = appDirs.user_data_dir
        # Add trailing slash:
        appUserDataDir = os.path.join(appUserDataDir,"")
        if not os.path.exists(appUserDataDir):
            os.makedirs(appUserDataDir)

        global launcherPreferencesFilePath 
        launcherPreferencesFilePath = os.path.join(appUserDataDir,"strudel.cfg")

        if sys.platform.startswith("win"):
            os.environ['CYGWIN'] = "nodosfilewarning"

        logger.setGlobalLauncherPreferencesFilePath(launcherPreferencesFilePath)
        sys.modules[__name__].launcherMainFrame = LauncherMainFrame(None, wx.ID_ANY, 'Strudel Beta')
        launcherMainFrame = sys.modules[__name__].launcherMainFrame
        launcherMainFrame.SetStatusBar(launcherMainFrame.loginDialogStatusBar)
        launcherMainFrame.SetMenuBar(launcherMainFrame.menu_bar)
        launcherMainFrame.Fit()
        launcherMainFrame.Layout()
        launcherMainFrame.Center()
        launcherMainFrame.Show(True)
        evt=wx.PyCommandEvent(wx.wxEVT_COMMAND_MENU_SELECTED,id=launcherMainFrame.loadDefaultSessionsId)
        wx.PostEvent(launcherMainFrame.GetEventHandler(),evt)
        t=threading.Thread(target=launcherMainFrame.checkVersionNumber)
        t.start()

        return True

if __name__ == '__main__':
    app = MyApp(False) # Don't automatically redirect sys.stdout and sys.stderr to a Window.
    app.MainLoop()
