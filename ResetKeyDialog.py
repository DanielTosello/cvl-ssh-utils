#!/usr/bin/python

import wx
import wx.html
import os
import sys

from logger.Logger import logger

from KeyModel import KeyModel

class ResetKeyDialog(wx.Dialog):
    def __init__(self, parent, id, title, keyModel, keyInAgent):
        wx.Dialog.__init__(self, parent, id, title, wx.DefaultPosition)

        self.resetKeyDialogSizer = wx.FlexGridSizer(rows=1, cols=1)
        self.SetSizer(self.resetKeyDialogSizer)

        self.resetKeyDialogPanel = wx.Panel(self, wx.ID_ANY)
        self.resetKeyDialogPanelSizer = wx.FlexGridSizer(8,1)
        self.resetKeyDialogPanel.SetSizer(self.resetKeyDialogPanelSizer)

        self.resetKeyDialogSizer.Add(self.resetKeyDialogPanel, flag=wx.LEFT|wx.RIGHT|wx.TOP|wx.BOTTOM, border=15)

        self.keyModel = keyModel
        self.keyInAgent = keyInAgent

        self.instructionsLabel = wx.StaticText(self.resetKeyDialogPanel, wx.ID_ANY, 
                        "This will delete your key, located at: \n\n" +
                        self.keyModel.getPrivateKeyFilePath()+"\n\n"+ 
                        "A new key will be generated, replacing the existing key.\n\n" +
                        "Any servers you had configured to access using this key will again require a password\n" +
                        "on the first login after resetting your key's passphrase.")
        self.resetKeyDialogPanelSizer.Add(self.instructionsLabel, flag=wx.EXPAND|wx.BOTTOM, border=15)

        # Passphrase panel

        self.validPassphrase = False

        self.passphrasePanel = wx.Panel(self.resetKeyDialogPanel, wx.ID_ANY)

        self.passphraseGroupBox = wx.StaticBox(self.passphrasePanel, wx.ID_ANY, label="Enter a new passphrase to protect your private key")
        self.passphraseGroupBoxSizer = wx.StaticBoxSizer(self.passphraseGroupBox, wx.VERTICAL)
        self.passphrasePanel.SetSizer(self.passphraseGroupBoxSizer)

        self.innerPassphrasePanel = wx.Panel(self.passphrasePanel, wx.ID_ANY)
        self.innerPassphrasePanelSizer = wx.FlexGridSizer(2,3, hgap=10)
        self.innerPassphrasePanel.SetSizer(self.innerPassphrasePanelSizer)

        self.passphraseLabel = wx.StaticText(self.innerPassphrasePanel, wx.ID_ANY, "New passphrase:")
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

        self.resetKeyDialogPanelSizer.Add(self.passphrasePanel, flag=wx.EXPAND)

        # Blank space

        self.resetKeyDialogPanelSizer.Add(wx.StaticText(self.resetKeyDialogPanel, wx.ID_ANY, ""))

        # Buttons panel

        self.buttonsPanel = wx.Panel(self.resetKeyDialogPanel, wx.ID_ANY)
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

        self.resetKeyDialogPanelSizer.Add(self.buttonsPanel, flag=wx.ALIGN_RIGHT)

        # Calculate positions on dialog, using sizers

        self.resetKeyDialogPanel.Fit()
        self.Fit()
        self.CenterOnParent()

    def onPassphraseFieldsModified(self, event):
        self.validPassphrase = False
        if len(self.passphraseField.GetValue())==0:
            self.passphraseStatusLabel1.SetLabel("Please enter a passphrase.")
            self.passphraseStatusLabel2.SetLabel("")
        elif len(self.passphraseField.GetValue())>0 and len(self.passphraseField.GetValue())<6:
            self.passphraseStatusLabel1.SetLabel("Passphrase is too short. ")
            self.passphraseStatusLabel2.SetLabel("")
        elif self.passphraseField.GetValue()!=self.repeatPassphraseField.GetValue():
            if self.repeatPassphraseField.GetValue()=="":
                self.passphraseStatusLabel1.SetLabel("")
                self.passphraseStatusLabel2.SetLabel("Please enter your passphrase again.")
            else:
                self.passphraseStatusLabel1.SetLabel("")
                self.passphraseStatusLabel2.SetLabel("Passphrases don't match!")
        else:
            self.passphraseStatusLabel1.SetLabel("")
            self.passphraseStatusLabel2.SetLabel("Passphrases match!")
            self.validPassphrase = True

        self.resetKeyDialogPanel.Fit()
        self.Fit()

    def onOK(self, event):
        if self.passphraseField.GetValue().strip()=="" or not self.validPassphrase:
            if self.passphraseField.GetValue().strip()=="":
                message = "Please enter a passphrase."
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

        success = self.keyModel.deleteKey(ignoreFailureToConnectToAgent=True)
        # deleteKey() method also removes key from agent.
        #if self.keyInAgent:
            #success = success and self.keyModel.removeKeyFromAgent()
        if success:
            logger.debug("Existing Launcher key was successfully deleted!")

            # Now create a new key to replace it.

            def keyCreatedSuccessfullyCallback():
                logger.debug("ResetPassphraseDialog callback: Key created successfully!")
            def keyFileAlreadyExistsCallback():
                logger.debug("ResetPassphraseDialog callback: Key file already exists!")
            def passphraseTooShortCallback():
                logger.debug("ResetPassphraseDialog callback: Passphrase was too short!")
            success = self.keyModel.generateNewKey(self.getPassphrase(),keyCreatedSuccessfullyCallback,keyFileAlreadyExistsCallback,passphraseTooShortCallback)
            if success and self.keyInAgent:
                def keyAddedSuccessfullyCallback():
                    logger.debug("ResetPassphraseDialog.onAddKeyToOrRemoveFromAgent callback: Key added successfully!")
                def passphraseIncorrectCallback():
                    logger.debug("ResetPassphraseDialog.onAddKeyToOrRemoveFromAgent callback: Passphrase incorrect.")
                def privateKeyFileNotFoundCallback():
                    logger.debug("ResetPassphraseDialog.onAddKeyToOrRemoveFromAgent callback: Private key file not found.")
                def failedToConnectToAgentCallback():
                    dlg = wx.MessageDialog(self,
                        "Could not open a connection to your authentication agent.",
                        "Strudel", wx.OK | wx.ICON_INFORMATION)
                    dlg.ShowModal()
                success = keyModelObject.addKeyToAgent(self.passphraseField.GetValue(), keyAddedSuccessfullyCallback, passphraseIncorrectCallback, privateKeyFileNotFoundCallback, failedToConnectToAgentCallback)
                if success:
                    message = "Adding key to agent succeeded."
                    logger.debug(message)
                else:
                    message = "Adding key to agent failed."
                    logger.debug(message)
            if success:
                message = "Your passphrase was reset successfully!"
                logger.debug(message)
            else:
                message = "An error occured while attempting to reset your passphrase."
                logger.debug(message)
        else:
            message = "An error occured while attempting to delete your existing key."
            logger.debug(message)

        dlg = wx.MessageDialog(self,
            message,
            "Strudel", wx.OK | wx.ICON_INFORMATION)
        dlg.ShowModal()

        if success:
            self.Show(False)

    def onCancel(self, event):
        self.Show(False)

    def onHelp(self, event):
        from help.HelpController import helpController
        if helpController is not None and helpController.initializationSucceeded:
            helpController.Display("SSH Keys")
        else:
            wx.MessageBox("Unable to open: " + helpController.launcherHelpUrl,
                          "Error", wx.OK|wx.ICON_EXCLAMATION)

    def getPassphrase(self):
        return self.passphraseField.GetValue()

class MyApp(wx.App):
    def OnInit(self):
        resetKeyDialog = ResetKeyDialog(None, wx.ID_ANY, 'Reset Key')
        resetKeyDialog.Center()
        if resetKeyDialog.ShowModal()==wx.ID_OK:
            logger.debug("Passphrase = " + resetKeyDialog.getPassphrase())
        else:
            logger.debug("User canceled.")
            return False

        return True

#app = MyApp(0)
#app.MainLoop()
