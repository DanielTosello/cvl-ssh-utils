#!/usr/bin/python

import wx
import wx.html
import os
import sys

from logger.Logger import logger

class CreateNewKeyDialog(wx.Dialog):
    def __init__(self, parent, progressDialog, id, title, defaultPrivateKeyLocation, displayStrings,displayMessageBoxReportingSuccess=True):
        wx.Dialog.__init__(self, parent, id, title, wx.DefaultPosition)

        self.displayStrings = displayStrings
        self.displayMessageBoxReportingSuccess = displayMessageBoxReportingSuccess

        self.closedProgressDialog = False
        self.parent = parent
        self.progressDialog = progressDialog
        if self.progressDialog is not None:
            self.progressDialog.Show(False)
            self.closedProgressDialog = True

        self.createNewKeyDialogSizer = wx.FlexGridSizer(rows=1, cols=1, vgap=0, hgap=0)
        self.SetSizer(self.createNewKeyDialogSizer)

        self.createNewKeyDialogPanel = wx.Panel(self, wx.ID_ANY)
        self.createNewKeyDialogPanelSizer = wx.FlexGridSizer(rows=6,cols=2,vgap=0,hgap=0)
        self.createNewKeyDialogPanel.SetSizer(self.createNewKeyDialogPanelSizer)

        self.createNewKeyDialogSizer.Add(self.createNewKeyDialogPanel, flag=wx.LEFT|wx.RIGHT|wx.TOP|wx.BOTTOM, border=15)

        self.instructionsLabel1 = wx.StaticText(self.createNewKeyDialogPanel, wx.ID_ANY, 
            "The Launcher needs to create a private key to authenticate against remote servers such as MASSIVE.\n") 
        if self.displayStrings!=None:
            self.instructionsLabel1.SetLabel(self.displayStrings.newPassphrase)
        self.createNewKeyDialogPanelSizer.Add(self.instructionsLabel1, flag=wx.EXPAND|wx.BOTTOM, border=15)

        # Passphrase panel

        self.validPassphrase = False

        self.passphrasePanel = wx.Panel(self.createNewKeyDialogPanel, wx.ID_ANY)

        self.passphraseGroupBox = wx.StaticBox(self.passphrasePanel, wx.ID_ANY, label="Enter a passphrase to protect your private key")
        self.passphraseGroupBoxSizer = wx.StaticBoxSizer(self.passphraseGroupBox, wx.VERTICAL)
        self.passphrasePanel.SetSizer(self.passphraseGroupBoxSizer)

        self.innerPassphrasePanel = wx.Panel(self.passphrasePanel, wx.ID_ANY)
        self.innerPassphrasePanel.SetMinSize(wx.Size(450,-1))
        self.innerPassphrasePanelSizer = wx.FlexGridSizer(rows=2, cols=3, vgap=0, hgap=10)
        self.innerPassphrasePanel.SetSizer(self.innerPassphrasePanelSizer)

        self.passphraseLabel = wx.StaticText(self.innerPassphrasePanel, wx.ID_ANY, "Passphrase:")
        self.innerPassphrasePanelSizer.Add(self.passphraseLabel, flag=wx.EXPAND)

        self.passphraseField = wx.TextCtrl(self.innerPassphrasePanel, wx.ID_ANY,style=wx.TE_PASSWORD)
        self.innerPassphrasePanelSizer.Add(self.passphraseField, flag=wx.EXPAND)
        self.passphraseField.SetFocus()

        self.passphraseStatusLabel1 = wx.StaticText(self.innerPassphrasePanel, wx.ID_ANY, "")
        self.innerPassphrasePanelSizer.Add(self.passphraseStatusLabel1, flag=wx.EXPAND|wx.LEFT, border=50)

        self.repeatPassphraseLabel = wx.StaticText(self.innerPassphrasePanel, wx.ID_ANY, "Repeat passphrase:")
        self.innerPassphrasePanelSizer.Add(self.repeatPassphraseLabel, flag=wx.EXPAND)

        self.repeatPassphraseField = wx.TextCtrl(self.innerPassphrasePanel, wx.ID_ANY,style=wx.TE_PASSWORD)
        self.innerPassphrasePanelSizer.Add(self.repeatPassphraseField, flag=wx.EXPAND)

        self.passphraseStatusLabel2 = wx.StaticText(self.innerPassphrasePanel, wx.ID_ANY, "")
        self.innerPassphrasePanelSizer.Add(self.passphraseStatusLabel2, flag=wx.EXPAND|wx.LEFT, border=50)

        self.innerPassphrasePanel.Fit()
        self.passphraseGroupBoxSizer.Add(self.innerPassphrasePanel, flag=wx.EXPAND)
        self.passphrasePanel.Fit()

        self.Bind(wx.EVT_TEXT, self.onPassphraseFieldsModified, id=self.passphraseField.GetId())
        self.Bind(wx.EVT_TEXT, self.onPassphraseFieldsModified, id=self.repeatPassphraseField.GetId())

        self.createNewKeyDialogPanelSizer.Add(self.passphrasePanel, flag=wx.EXPAND|wx.BOTTOM, border=15)


        # Private key location

        self.privateKeyLocationPanel = wx.Panel(self.createNewKeyDialogPanel, wx.ID_ANY)

        self.privateKeyLocationGroupBox = wx.StaticBox(self.privateKeyLocationPanel, wx.ID_ANY, label="Location of your private key")
        self.privateKeyLocationGroupBoxSizer = wx.StaticBoxSizer(self.privateKeyLocationGroupBox, wx.VERTICAL)
        self.privateKeyLocationPanel.SetSizer(self.privateKeyLocationGroupBoxSizer)

        self.innerPrivateKeyLocationPanel = wx.Panel(self.privateKeyLocationPanel, wx.ID_ANY)
        self.innerPrivateKeyLocationPanelSizer = wx.FlexGridSizer(rows=1,cols=3,vgap=0,hgap=10)
        self.innerPrivateKeyLocationPanelSizer.AddGrowableCol(1)
        self.innerPrivateKeyLocationPanel.SetSizer(self.innerPrivateKeyLocationPanelSizer)

        self.privateKeyLocationLabel = wx.StaticText(self.innerPrivateKeyLocationPanel, wx.ID_ANY, "Private key file:")
        self.innerPrivateKeyLocationPanelSizer.Add(self.privateKeyLocationLabel)

        self.privateKeyLocationField = wx.TextCtrl(self.innerPrivateKeyLocationPanel, wx.ID_ANY, style=wx.TE_READONLY)
        self.privateKeyLocationField.SetValue(defaultPrivateKeyLocation)

        self.innerPrivateKeyLocationPanelSizer.Add(self.privateKeyLocationField, flag=wx.EXPAND)

        self.browseButton = wx.Button(self.innerPrivateKeyLocationPanel, wx.NewId(), "Browse")
        self.Bind(wx.EVT_BUTTON, self.onBrowse, id=self.browseButton.GetId())
        self.innerPrivateKeyLocationPanelSizer.Add(self.browseButton, flag=wx.BOTTOM, border=5)

        self.innerPrivateKeyLocationPanel.Fit()
        self.privateKeyLocationGroupBoxSizer.Add(self.innerPrivateKeyLocationPanel, flag=wx.EXPAND)
        self.privateKeyLocationPanel.Fit()

        self.createNewKeyDialogPanelSizer.Add(self.privateKeyLocationPanel, flag=wx.EXPAND|wx.BOTTOM, border=15)

        # Buttons panel

        self.buttonsPanel = wx.Panel(self.createNewKeyDialogPanel, wx.ID_ANY)
        self.buttonsPanelSizer = wx.FlexGridSizer(1,3, hgap=5, vgap=5)
        self.buttonsPanel.SetSizer(self.buttonsPanelSizer)
        self.helpButton = wx.Button(self.buttonsPanel, wx.NewId(), "Help")
        self.buttonsPanelSizer.Add(self.helpButton, flag=wx.BOTTOM, border=5)
        self.Bind(wx.EVT_BUTTON, self.onHelp, id=self.helpButton.GetId())
        self.cancelButton = wx.Button(self.buttonsPanel, wx.ID_CANCEL, "Cancel")
        self.buttonsPanelSizer.Add(self.cancelButton, flag=wx.BOTTOM, border=5)
        self.Bind(wx.EVT_BUTTON, self.onCancel, id=wx.ID_CANCEL)
        self.okButton = wx.Button(self.buttonsPanel, wx.ID_OK, "OK")
        self.okButton.SetDefault()
        self.Bind(wx.EVT_BUTTON, self.onOK, id=wx.ID_OK)
        self.buttonsPanelSizer.Add(self.okButton, flag=wx.BOTTOM, border=5)
        self.buttonsPanel.Fit()

        self.createNewKeyDialogPanelSizer.Add(self.buttonsPanel, flag=wx.ALIGN_RIGHT)

        self.Bind(wx.EVT_CLOSE, self.onCancel)

        # Calculate positions on dialog, using sizers

        self.createNewKeyDialogPanel.Fit()
        self.Fit()
        self.CenterOnParent()

    def onPassphraseFieldsModified(self, event):
        self.validPassphrase = False
        if len(self.passphraseField.GetValue())==0:
            #self.passphraseStatusLabel1.SetLabel("Please enter a passphrase.")
            self.passphraseStatusLabel1.SetLabel(self.displayStrings.newPassphraseTitle)
            self.passphraseStatusLabel2.SetLabel("")
        elif len(self.passphraseField.GetValue())>0 and len(self.passphraseField.GetValue())<6:
            #self.passphraseStatusLabel1.SetLabel("Passphrase is too short.")
            self.passphraseStatusLabel1.SetLabel(self.displayStrings.createNewKeyDialogNewPassphraseTooShort)
            self.passphraseStatusLabel2.SetLabel("")
        elif self.passphraseField.GetValue()!=self.repeatPassphraseField.GetValue():
            if self.repeatPassphraseField.GetValue()=="":
                self.passphraseStatusLabel1.SetLabel("")
                self.passphraseStatusLabel2.SetLabel("Please enter your passphrase again.")
            else:
                self.passphraseStatusLabel1.SetLabel("")
                #self.passphraseStatusLabel2.SetLabel("Passphrases don't match!")
                self.passphraseStatusLabel2.SetLabel(self.displayStrings.createNewKeyDialogNewPassphraseMismatch)
        else:
            self.passphraseStatusLabel1.SetLabel("")
            self.passphraseStatusLabel2.SetLabel("Passphrases match!")
            self.validPassphrase = True

    def onOK(self, event):
        if self.passphraseField.GetValue().strip()=="" or not self.validPassphrase:
            if self.passphraseField.GetValue().strip()=="":
                #message = "Please enter a passphrase."
                message = self.displayStrings.newPassphraseTitle
                self.passphraseField.SetFocus()
            elif self.passphraseStatusLabel1.GetLabelText()!="":
                message = self.passphraseStatusLabel1.GetLabelText()
                self.passphraseField.SetFocus()
            elif self.passphraseStatusLabel2.GetLabelText()!="" and self.passphraseStatusLabel2.GetLabelText()!="Passphrases match!":
                message = self.passphraseStatusLabel2.GetLabelText()
                self.repeatPassphraseField.SetFocus()
            else:
                message = "Please enter a valid passphrase."
                self.passphraseField.SetFocus()

            dlg = wx.MessageDialog(self, message,
                            "Strudel", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()
            return
        self.reopenProgressDialogIfNecessary()
        self.EndModal(wx.ID_OK)

    def reopenProgressDialogIfNecessary(self):
        if self.closedProgressDialog:
            if self.progressDialog is not None:
                self.progressDialog.Show(True)

    def onCancel(self, event):
        #self.Show(False)
        #self.reopenProgressDialogIfNecessary()
        self.EndModal(wx.ID_CANCEL)

    def onHelp(self, event):
        from help.HelpController import helpController
        if helpController is not None and helpController.initializationSucceeded:
            helpController.Display("SSH Keys")
        else:
            wx.MessageBox("Unable to open: " + helpController.launcherHelpUrl,
                          "Error", wx.OK|wx.ICON_EXCLAMATION)

    def onBrowse(self, event):
        wx.MessageBox("For now, you must use the Launcher's default private key location.",
                      "Strudel", wx.OK|wx.ICON_EXCLAMATION)
        return
        #saveFileDialog = wx.FileDialog (self, message = 'MASSIVE Launcher private key file...', defaultDir=self.privateKeyDir, defaultFile=self.privateKeyFilename, style = wx.SAVE)
        #if saveFileDialog.ShowModal() == wx.ID_OK:
            #privateKeyFilePath = saveFileDialog.GetPath()
            #(self.privateKeyDir, self.privateKeyFilename) = os.path.split(privateKeyFilePath)
            #self.privateKeyLocationField.SetValue(privateKeyFilePath)

    def getPassphrase(self):
        return self.passphraseField.GetValue()

    def getPrivateKeyFileLocation(self):
        return self.privateKeyLocationField.GetValue()

