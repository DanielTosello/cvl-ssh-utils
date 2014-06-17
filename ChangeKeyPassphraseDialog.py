#!/usr/bin/python

import wx
import wx.html
import os
import sys

if os.path.abspath("..") not in sys.path:
    sys.path.append(os.path.abspath(".."))

from logger.Logger import logger

class ChangeKeyPassphraseDialog(wx.Dialog):
    def __init__(self, parent, id, title, keyModel):
        wx.Dialog.__init__(self, parent, id, title, wx.DefaultPosition)

        self.changeKeyPassphraseDialogSizer = wx.FlexGridSizer(rows=1, cols=1)
        self.SetSizer(self.changeKeyPassphraseDialogSizer)

        self.changeKeyPassphraseDialogPanel = wx.Panel(self, wx.ID_ANY)
        self.changeKeyPassphraseDialogPanelSizer = wx.FlexGridSizer(8,1)
        self.changeKeyPassphraseDialogPanel.SetSizer(self.changeKeyPassphraseDialogPanelSizer)

        self.changeKeyPassphraseDialogSizer.Add(self.changeKeyPassphraseDialogPanel, flag=wx.LEFT|wx.RIGHT|wx.TOP|wx.BOTTOM, border=15)


        self.keyModel = keyModel

        self.instructionsLabel = wx.StaticText(self.changeKeyPassphraseDialogPanel, wx.ID_ANY, 
                        "This will change the passphrase on your key, located at:\n\n" +
                        self.keyModel.getPrivateKeyFilePath() +
                        "\n\n"+
                        "You will still be able to access servers without a password if you have\n" +
                        "connected to them previously with the Launcher.")
        self.changeKeyPassphraseDialogPanelSizer.Add(self.instructionsLabel, flag=wx.EXPAND|wx.BOTTOM|wx.RIGHT, border=15)

        # Existing passphrase panel

        self.existingPassphrasePanel = wx.Panel(self.changeKeyPassphraseDialogPanel, wx.ID_ANY)

        self.existingPassphraseGroupBox = wx.StaticBox(self.existingPassphrasePanel, wx.ID_ANY, label="Enter your existing passphrase")
        self.existingPassphraseGroupBoxSizer = wx.StaticBoxSizer(self.existingPassphraseGroupBox, wx.VERTICAL)
        self.existingPassphrasePanel.SetSizer(self.existingPassphraseGroupBoxSizer)

        self.innerExistingPassphrasePanel = wx.Panel(self.existingPassphrasePanel, wx.ID_ANY)
        self.innerExistingPassphrasePanelSizer = wx.FlexGridSizer(2,3, hgap=10)
        self.innerExistingPassphrasePanel.SetSizer(self.innerExistingPassphrasePanelSizer)

        self.passphraseLabel = wx.StaticText(self.innerExistingPassphrasePanel, wx.ID_ANY, "Existing passphrase:")
        self.innerExistingPassphrasePanelSizer.Add(self.passphraseLabel, flag=wx.EXPAND)

        self.existingPassphraseField = wx.TextCtrl(self.innerExistingPassphrasePanel, wx.ID_ANY,style=wx.TE_PASSWORD)
        self.innerExistingPassphrasePanelSizer.Add(self.existingPassphraseField, flag=wx.EXPAND)
        self.existingPassphraseField.SetFocus()

        self.innerExistingPassphrasePanel.Fit()
        self.existingPassphraseGroupBoxSizer.Add(self.innerExistingPassphrasePanel, flag=wx.EXPAND)
        self.existingPassphrasePanel.Fit()

        self.changeKeyPassphraseDialogPanelSizer.Add(self.existingPassphrasePanel, flag=wx.EXPAND)

        # Blank space

        self.changeKeyPassphraseDialogPanelSizer.Add(wx.StaticText(self.changeKeyPassphraseDialogPanel, wx.ID_ANY, ""))

        # New passphrase panel

        self.validNewPassphrase = False

        self.newPassphrasePanel = wx.Panel(self.changeKeyPassphraseDialogPanel, wx.ID_ANY)

        self.newPassphraseGroupBox = wx.StaticBox(self.newPassphrasePanel, wx.ID_ANY, label="Enter a new passphrase to protect your private key")
        self.newPassphraseGroupBoxSizer = wx.StaticBoxSizer(self.newPassphraseGroupBox, wx.VERTICAL)
        self.newPassphrasePanel.SetSizer(self.newPassphraseGroupBoxSizer)

        self.innerNewPassphrasePanel = wx.Panel(self.newPassphrasePanel, wx.ID_ANY)
        self.innerNewPassphrasePanelSizer = wx.FlexGridSizer(2,3, hgap=10)
        self.innerNewPassphrasePanel.SetSizer(self.innerNewPassphrasePanelSizer)

        self.passphraseLabel = wx.StaticText(self.innerNewPassphrasePanel, wx.ID_ANY, "New passphrase:")
        self.innerNewPassphrasePanelSizer.Add(self.passphraseLabel, flag=wx.EXPAND)

        self.newPassphraseField = wx.TextCtrl(self.innerNewPassphrasePanel, wx.ID_ANY,style=wx.TE_PASSWORD)
        self.innerNewPassphrasePanelSizer.Add(self.newPassphraseField, flag=wx.EXPAND)

        self.newPassphraseStatusLabel1 = wx.StaticText(self.innerNewPassphrasePanel, wx.ID_ANY, "")
        self.innerNewPassphrasePanelSizer.Add(self.newPassphraseStatusLabel1, flag=wx.EXPAND|wx.LEFT, border=20)

        self.repeatNewPassphraseLabel = wx.StaticText(self.innerNewPassphrasePanel, wx.ID_ANY, "Repeat passphrase:")
        self.innerNewPassphrasePanelSizer.Add(self.repeatNewPassphraseLabel, flag=wx.EXPAND)

        self.repeatNewPassphraseField = wx.TextCtrl(self.innerNewPassphrasePanel, wx.ID_ANY,style=wx.TE_PASSWORD)
        self.innerNewPassphrasePanelSizer.Add(self.repeatNewPassphraseField, flag=wx.EXPAND)

        self.newPassphraseStatusLabel2 = wx.StaticText(self.innerNewPassphrasePanel, wx.ID_ANY, "")
        self.innerNewPassphrasePanelSizer.Add(self.newPassphraseStatusLabel2, flag=wx.EXPAND|wx.LEFT, border=20)

        self.innerNewPassphrasePanel.Fit()
        self.newPassphraseGroupBoxSizer.Add(self.innerNewPassphrasePanel, flag=wx.EXPAND)
        self.newPassphrasePanel.Fit()

        self.Bind(wx.EVT_TEXT, self.onPassphraseFieldsModified, id=self.newPassphraseField.GetId())
        self.Bind(wx.EVT_TEXT, self.onPassphraseFieldsModified, id=self.repeatNewPassphraseField.GetId())

        self.changeKeyPassphraseDialogPanelSizer.Add(self.newPassphrasePanel, flag=wx.EXPAND)

        # Blank space

        self.changeKeyPassphraseDialogPanelSizer.Add(wx.StaticText(self.changeKeyPassphraseDialogPanel, wx.ID_ANY, ""))

        # Buttons panel

        self.buttonsPanel = wx.Panel(self.changeKeyPassphraseDialogPanel, wx.ID_ANY)
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

        self.changeKeyPassphraseDialogPanelSizer.Add(self.buttonsPanel, flag=wx.ALIGN_RIGHT)

        # Calculate positions on dialog, using sizers

        self.changeKeyPassphraseDialogPanel.Fit()
        self.Fit()
        self.CenterOnParent()

    def onPassphraseFieldsModified(self, event):
        self.validNewPassphrase = False
        if len(self.newPassphraseField.GetValue())==0:
            self.newPassphraseStatusLabel1.SetLabel("Please enter a passphrase.")
            #self.newPassphraseStatusLabel1.SetLabel(self.displayStrings.newPassphraseTitle)
            self.newPassphraseStatusLabel2.SetLabel("")
        elif len(self.newPassphraseField.GetValue())>0 and len(self.newPassphraseField.GetValue())<6:
            self.newPassphraseStatusLabel1.SetLabel("Passphrase is too short.")
            #self.newPassphraseStatusLabel1.SetLabel(self.displayStrings.createNewKeyDialogNewPassphraseTooShort)
            self.newPassphraseStatusLabel2.SetLabel("")
        elif self.newPassphraseField.GetValue()!=self.repeatNewPassphraseField.GetValue():
            if self.repeatNewPassphraseField.GetValue()=="":
                self.newPassphraseStatusLabel1.SetLabel("")
                self.newPassphraseStatusLabel2.SetLabel("Enter your passphrase again.")
            else:
                self.newPassphraseStatusLabel1.SetLabel("")
                self.newPassphraseStatusLabel2.SetLabel("Passphrases don't match!")
                #self.newPassphraseStatusLabel2.SetLabel(self.displayStrings.createNewKeyDialogNewPassphraseMismatch)
        else:
            self.newPassphraseStatusLabel1.SetLabel("")
            self.newPassphraseStatusLabel2.SetLabel("Passphrases match!")
            self.validNewPassphrase = True

        self.changeKeyPassphraseDialogPanel.Fit()
        self.Fit()

    def onOK(self, event):

        if self.existingPassphraseField.GetValue().strip()=="":
            message = "Please enter your existing passphrase."
            dlg = wx.MessageDialog(self, message,
                            "Strudel", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()
            self.existingPassphraseField.SetFocus()
            return

        if self.newPassphraseField.GetValue().strip()=="":
            message = "Please enter your new passphrase."
            dlg = wx.MessageDialog(self, message,
                            "Strudel", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()
            self.newPassphraseField.SetFocus()
            return

        if self.newPassphraseStatusLabel1.GetLabelText()!="":
            message = self.newPassphraseStatusLabel1.GetLabelText()
            dlg = wx.MessageDialog(self, message,
                            "Strudel", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()
            self.newPassphraseField.SetFocus()
            return

        if self.newPassphraseStatusLabel2.GetLabelText()!="" and self.newPassphraseStatusLabel2.GetLabelText()!="Passphrases match!":
            message = self.newPassphraseStatusLabel2.GetLabelText()
            dlg = wx.MessageDialog(self, message,
                            "Strudel", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()
            self.repeatNewPassphraseField.SetFocus()
            return


        def existingPassphraseIncorrect():
            dlg = wx.MessageDialog(self, "Your existing passphrase appears to be incorrect.\nPlease enter it again.",
                            "Strudel", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()
            self.existingPassphraseField.SetSelection(-1,-1)
            self.existingPassphraseField.SetFocus()

        def passphraseUpdatedSuccessfullyCallback():
            message = "Passphrase updated successfully!"
            logger.debug(message)
            #dlg = wx.MessageDialog(self, message,
                            #"MASSIVE/CVL Launcher", wx.OK | wx.ICON_INFORMATION)
            #dlg.ShowModal()

        def newPassphraseTooShortCallback():
            # This should have been caught earlier:
            logger.debug("Callback: New passphrase is too short.")

        def keyLockedCallback():
            logger.debug("Callback: Key locked.")
            dlg = wx.MessageDialog(self, "Your key appears to be locked.",
                            "Strudel", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()
            self.existingPassphraseField.SetSelection(-1,-1)
            self.existingPassphraseField.SetFocus()

        success = self.keyModel.changePassphrase(self.existingPassphraseField.GetValue(), self.newPassphraseField.GetValue(),
            passphraseUpdatedSuccessfullyCallback,
            existingPassphraseIncorrect,
            newPassphraseTooShortCallback,
            keyLockedCallback)

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

    def getNewPassphrase(self):
        return self.newPassphraseField.GetValue()

class MyApp(wx.App):
    def OnInit(self):
        changeKeyPassphraseDialog = ChangeKeyPassphraseDialog(None, wx.ID_ANY, 'Change Key Passphrase', os.path.join(os.path.expanduser('~'), '.ssh', "MassiveLauncherKey"))
        changeKeyPassphraseDialog.Center()
        if changeKeyPassphraseDialog.ShowModal()==wx.ID_OK:
            logger.debug("New passphrase = " + changeKeyPassphraseDialog.getNewPassphrase())
        else:
            logger.debug("User canceled.")
            return False

        return True

#app = MyApp(0)
#app.MainLoop()
