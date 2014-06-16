#!/usr/bin/python

import wx
import wx.html
import os
import sys
import subprocess
import re
import traceback

from KeyModel import KeyModel

if os.path.abspath("..") not in sys.path:
    sys.path.append(os.path.abspath(".."))
from sshKeyDist import KeyDist

from logger.Logger import logger

class InspectKeyDialog(wx.Dialog):
    def __init__(self, parent, id, title, keyModel):
        wx.Dialog.__init__(self, parent, id, title, wx.DefaultPosition)

        self.inspectKeyDialogSizer = wx.FlexGridSizer(rows=1, cols=1)
        self.SetSizer(self.inspectKeyDialogSizer)

        self.inspectKeyDialogPanel = wx.Panel(self, wx.ID_ANY)
        self.inspectKeyDialogPanelSizer = wx.FlexGridSizer(10,1)
        self.inspectKeyDialogPanel.SetSizer(self.inspectKeyDialogPanelSizer)

        self.inspectKeyDialogSizer.Add(self.inspectKeyDialogPanel, flag=wx.LEFT|wx.RIGHT|wx.TOP|wx.BOTTOM, border=15)

        self.keyModel = keyModel

        # Instructions label

        self.instructionsLabel = wx.StaticText(self.inspectKeyDialogPanel, wx.ID_ANY, 
            "Strudel needs a private key to authenticate against remote servers.\n\n" + 
            "Here, you can inspect the properties of your Strudel Launcher key.")
        self.inspectKeyDialogPanelSizer.Add(self.instructionsLabel, flag=wx.EXPAND|wx.BOTTOM, border=15)

        # Key properties panel

        self.keyPropertiesPanel = wx.Panel(self.inspectKeyDialogPanel, wx.ID_ANY)

        self.keyPropertiesGroupBox = wx.StaticBox(self.keyPropertiesPanel, wx.ID_ANY, label="Key properties")
        self.keyPropertiesGroupBoxSizer = wx.StaticBoxSizer(self.keyPropertiesGroupBox, wx.VERTICAL)
        self.keyPropertiesPanel.SetSizer(self.keyPropertiesGroupBoxSizer)

        self.innerKeyPropertiesPanel = wx.Panel(self.keyPropertiesPanel, wx.ID_ANY)
        self.innerKeyPropertiesPanelSizer = wx.FlexGridSizer(10,2, hgap=10)
        self.innerKeyPropertiesPanel.SetSizer(self.innerKeyPropertiesPanelSizer)

        self.innerKeyPropertiesPanelSizer.AddGrowableCol(1)

        # Private key location

        self.privateKeyLocationLabel = wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, "Private key file:")
        self.innerKeyPropertiesPanelSizer.Add(self.privateKeyLocationLabel)

        self.privateKeyLocationField = wx.TextCtrl(self.innerKeyPropertiesPanel, wx.ID_ANY, style=wx.TE_READONLY)
        self.privateKeyLocationField.SetValue(self.keyModel.getPrivateKeyFilePath())
        self.innerKeyPropertiesPanelSizer.Add(self.privateKeyLocationField, flag=wx.EXPAND)

        # Blank space

        self.innerKeyPropertiesPanelSizer.Add(wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, ""))
        self.innerKeyPropertiesPanelSizer.Add(wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, ""))

        # Public key location

        self.publicKeyLocationLabel = wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, "Public key file:")
        self.innerKeyPropertiesPanelSizer.Add(self.publicKeyLocationLabel)

        self.publicKeyLocationField = wx.TextCtrl(self.innerKeyPropertiesPanel, wx.ID_ANY, style=wx.TE_READONLY)
        self.populatePublicKeyLocationField()
        self.innerKeyPropertiesPanelSizer.Add(self.publicKeyLocationField, flag=wx.EXPAND)

        # Blank space

        self.innerKeyPropertiesPanelSizer.Add(wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, ""))
        self.innerKeyPropertiesPanelSizer.Add(wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, ""))

        # Public key fingerprint

        self.publicKeyFingerprintLabel = wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, "Public key fingerprint:")
        self.innerKeyPropertiesPanelSizer.Add(self.publicKeyFingerprintLabel)

        self.publicKeyFingerprintField = wx.TextCtrl(self.innerKeyPropertiesPanel, wx.ID_ANY, style=wx.TE_READONLY)

        self.innerKeyPropertiesPanelSizer.Add(self.publicKeyFingerprintField, flag=wx.EXPAND)

        # Blank space

        self.innerKeyPropertiesPanelSizer.Add(wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, ""))
        self.innerKeyPropertiesPanelSizer.Add(wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, ""))

        # Key type

        self.keyTypeLabel = wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, "Key type:")
        self.innerKeyPropertiesPanelSizer.Add(self.keyTypeLabel)

        #self.keyTypeField = wx.TextCtrl(self.innerKeyPropertiesPanel, wx.ID_ANY, style=wx.TE_READONLY)
        #self.keyTypeField.SetValue(keyType)
        self.keyTypeField = wx.StaticText(self.innerKeyPropertiesPanel, wx.ID_ANY, "")

        self.populateFingerprintAndKeyTypeFields()

        self.innerKeyPropertiesPanelSizer.Add(self.keyTypeField, flag=wx.EXPAND)

        self.innerKeyPropertiesPanel.Fit()
        self.keyPropertiesGroupBoxSizer.Add(self.innerKeyPropertiesPanel, flag=wx.EXPAND)
        self.keyPropertiesPanel.Fit()

        self.inspectKeyDialogPanelSizer.Add(self.keyPropertiesPanel, flag=wx.EXPAND)

        # Key in agent explanation label

        self.keyInAgentExplanationLabel = wx.StaticText(self.inspectKeyDialogPanel, wx.ID_ANY, 
            "When you log into a remote server, the Launcher will add your key to an SSH agent,\n" +
            "if it has not been added already. If SSH_AUTH_SOCK is non-empty and the Launcher's\n" +
            "public key fingerprint is present in the SSH agent, then the Launcher key has been\n" +
            "successfully added to the SSH agent.")
        self.inspectKeyDialogPanelSizer.Add(self.keyInAgentExplanationLabel, flag=wx.EXPAND|wx.BOTTOM|wx.TOP, border=15)

        # SSH Agent Properties

        self.agentPropertiesPanel = wx.Panel(self.inspectKeyDialogPanel, wx.ID_ANY)

        self.agentPropertiesGroupBox = wx.StaticBox(self.agentPropertiesPanel, wx.ID_ANY, label="Agent properties")
        self.agentPropertiesGroupBoxSizer = wx.StaticBoxSizer(self.agentPropertiesGroupBox, wx.VERTICAL)
        self.agentPropertiesPanel.SetSizer(self.agentPropertiesGroupBoxSizer)

        self.innerAgentPropertiesPanel = wx.Panel(self.agentPropertiesPanel, wx.ID_ANY)
        self.innerAgentPropertiesPanelSizer = wx.FlexGridSizer(10,2, hgap=10)
        self.innerAgentPropertiesPanelSizer.AddGrowableCol(1)
        self.innerAgentPropertiesPanel.SetSizer(self.innerAgentPropertiesPanelSizer)

        self.innerAgentPropertiesPanelSizer.AddGrowableCol(1)

        self.sshAuthSockLabel = wx.StaticText(self.innerAgentPropertiesPanel, wx.ID_ANY, "SSH_AUTH_SOCK:")
        self.innerAgentPropertiesPanelSizer.Add(self.sshAuthSockLabel)

        self.sshAuthSockField = wx.TextCtrl(self.innerAgentPropertiesPanel, wx.ID_ANY, style=wx.TE_READONLY)

        self.populateSshAuthSockField()

        self.innerAgentPropertiesPanelSizer.Add(self.sshAuthSockField, flag=wx.EXPAND)

        # Blank space

        self.innerAgentPropertiesPanelSizer.Add(wx.StaticText(self.innerAgentPropertiesPanel, wx.ID_ANY, ""))
        self.innerAgentPropertiesPanelSizer.Add(wx.StaticText(self.innerAgentPropertiesPanel, wx.ID_ANY, ""))

        self.fingerprintInAgentLabel = wx.StaticText(self.innerAgentPropertiesPanel, wx.ID_ANY, "Launcher key fingerprint in agent:")
        self.innerAgentPropertiesPanelSizer.Add(self.fingerprintInAgentLabel)

        self.fingerprintInAgentField = wx.TextCtrl(self.innerAgentPropertiesPanel, wx.ID_ANY, style=wx.TE_READONLY)

        self.populateFingerprintInAgentField()

        self.innerAgentPropertiesPanelSizer.Add(self.fingerprintInAgentField, flag=wx.EXPAND)

        self.inspectKeyDialogPanelSizer.Add(self.agentPropertiesPanel, flag=wx.EXPAND)

        # Blank space

        self.innerAgentPropertiesPanelSizer.Add(wx.StaticText(self.innerAgentPropertiesPanel, wx.ID_ANY, ""))

        self.addKeyToOrRemoveKeyFromAgentButton = wx.Button(self.innerAgentPropertiesPanel, wx.ID_ANY, "")
        if self.fingerprintInAgentField.GetValue()=="":
            self.addKeyToOrRemoveKeyFromAgentButton.SetLabel("Add Strudel key to agent")
        else:
            self.addKeyToOrRemoveKeyFromAgentButton.SetLabel("Remove Strudel key from agent")

        self.innerAgentPropertiesPanelSizer.Add(self.addKeyToOrRemoveKeyFromAgentButton, flag=wx.EXPAND|wx.TOP|wx.BOTTOM, border=10)
        self.Bind(wx.EVT_BUTTON, self.onAddKeyToOrRemoveFromAgent, id=self.addKeyToOrRemoveKeyFromAgentButton.GetId())

        self.innerAgentPropertiesPanel.Fit()
        self.agentPropertiesGroupBoxSizer.Add(self.innerAgentPropertiesPanel, flag=wx.EXPAND)
        self.agentPropertiesPanel.Fit()

        # Blank space

        self.inspectKeyDialogPanelSizer.Add(wx.StaticText(self.inspectKeyDialogPanel, wx.ID_ANY, ""))

        # Buttons panel

        self.buttonsPanel = wx.Panel(self.inspectKeyDialogPanel, wx.ID_ANY)
        self.buttonsPanelSizer = wx.FlexGridSizer(1,5, hgap=5, vgap=5)
        self.buttonsPanel.SetSizer(self.buttonsPanelSizer)

        self.deleteKeyButton = wx.Button(self.buttonsPanel, wx.NewId(), "Delete Key")
        self.buttonsPanelSizer.Add(self.deleteKeyButton, flag=wx.BOTTOM, border=5)
        self.Bind(wx.EVT_BUTTON, self.onDeleteKey, id=self.deleteKeyButton.GetId())

        self.changePassphraseButton = wx.Button(self.buttonsPanel, wx.NewId(), "Change Passphrase")
        self.buttonsPanelSizer.Add(self.changePassphraseButton, flag=wx.BOTTOM, border=5)
        self.Bind(wx.EVT_BUTTON, self.onChangePassphrase, id=self.changePassphraseButton.GetId())

        self.resetKeyButton = wx.Button(self.buttonsPanel, wx.NewId(), "Reset Key")
        self.buttonsPanelSizer.Add(self.resetKeyButton, flag=wx.BOTTOM, border=5)
        self.Bind(wx.EVT_BUTTON, self.onResetKey, id=self.resetKeyButton.GetId())

        self.helpButton = wx.Button(self.buttonsPanel, wx.NewId(), "Help")
        self.buttonsPanelSizer.Add(self.helpButton, flag=wx.BOTTOM, border=5)
        self.Bind(wx.EVT_BUTTON, self.onHelp, id=self.helpButton.GetId())

        self.closeButton = wx.Button(self.buttonsPanel, wx.NewId(), "Close")
        self.closeButton.SetDefault()
        self.Bind(wx.EVT_BUTTON, self.onClose, id=self.closeButton.GetId())
        self.buttonsPanelSizer.Add(self.closeButton, flag=wx.BOTTOM, border=5)

        self.buttonsPanel.Fit()

        self.inspectKeyDialogPanelSizer.Add(self.buttonsPanel, flag=wx.ALIGN_RIGHT)

        # Calculate positions on dialog, using sizers

        self.inspectKeyDialogPanel.Fit()
        self.Fit()
        self.CenterOnParent()

    def reloadAllFields(self):
        self.privateKeyLocationField.SetValue(self.keyModel.getPrivateKeyFilePath())
        self.populatePublicKeyLocationField()
        self.populateFingerprintAndKeyTypeFields()
        self.populateFingerprintInAgentField()
        if self.fingerprintInAgentField.GetValue()=="":
            self.addKeyToOrRemoveKeyFromAgentButton.SetLabel("Add Strudel key to agent")
        else:
            self.addKeyToOrRemoveKeyFromAgentButton.SetLabel("Remove Strudel key from agent")

    def populateSshAuthSockField(self):
        if "SSH_AUTH_SOCK" not in os.environ:
            self.startAgent()
        if "SSH_AUTH_SOCK" in os.environ:
            self.sshAuthSockField.SetValue(os.environ["SSH_AUTH_SOCK"])
        else:
            self.sshAuthSockField.SetValue("")

    def populatePublicKeyLocationField(self):
        self.publicKeyFilePath = ""
        if os.path.exists(self.keyModel.getPrivateKeyFilePath() + ".pub"):
            self.publicKeyFilePath = self.keyModel.getPrivateKeyFilePath() + ".pub"
        self.publicKeyLocationField.SetValue(self.publicKeyFilePath)

    def populateFingerprintAndKeyTypeFields(self):

        (publicKeyFingerprint,keyType) = self.keyModel.getFingerprintAndKeyTypeFromPrivateKeyFile()
        if publicKeyFingerprint is not None:
            self.publicKeyFingerprintField.SetValue(publicKeyFingerprint)
        else:
            self.publicKeyFingerprintField.SetValue("")
        if keyType is not None:
            self.keyTypeField.SetLabel(keyType)
        else:
            self.keyTypeField.SetLabel("")

    def populateFingerprintInAgentField(self):

        publicKeyFingerprintInAgent = ""
        key = self.keyModel.fingerprintAgent()
        if key != None:
            sshAddOutComponents = key.split(" ")
            if len(sshAddOutComponents)>1:
                publicKeyFingerprintInAgent = sshAddOutComponents[1]
        self.fingerprintInAgentField.SetValue(publicKeyFingerprintInAgent)

    def onAddKeyToOrRemoveFromAgent(self, event):
        logger.debug("onAddKeyToOrRemoveFromAgent")
        if self.addKeyToOrRemoveKeyFromAgentButton.GetLabel()=="Add Strudel key to agent":
            logger.debug("onAddKeyToOrRemoveFromAgent: Adding key to agent...")

            import cvlsshutils
            ppd = cvlsshutils.PassphraseDialog.passphraseDialog(None,None,wx.ID_ANY,'Unlock Key',"Please enter the passphrase for the key","OK","Cancel")
            (canceled,passphrase) = ppd.getPassword()
            if (canceled):
                logger.debug("onAddKeyToOrRemoveFromAgent: Tried to add key to agent, but user canceld from passphrase dialog.")
                return
            else:
                def keyAddedSuccessfullyCallback():
                    message = "Key added successfully!"
                    logger.debug("InspectKeyDialog.onAddKeyToOrRemoveFromAgent callback: " + message)
                def passphraseIncorrectCallback():
                    message = "Passphrase incorrect."
                    logger.debug("InspectKeyDialog.onAddKeyToOrRemoveFromAgent callback: " + message)
                    dlg = wx.MessageDialog(self, message, "Strudel", wx.OK | wx.ICON_INFORMATION)
                    dlg.ShowModal()
                def privateKeyFileNotFoundCallback():
                    message = "Private key file not found."
                    logger.debug("InspectKeyDialog.onAddKeyToOrRemoveFromAgent callback: " + message)
                    dlg = wx.MessageDialog(self, message, "Strudel", wx.OK | wx.ICON_INFORMATION)
                    dlg.ShowModal()
                def failedToConnectToAgentCallback():
                    message = "Could not open a connection to your authentication agent."
                    logger.debug("InspectKeyDialog.onAddKeyToOrRemoveFromAgent callback: " + message)
                    dlg = wx.MessageDialog(self, message, "Strudel", wx.OK | wx.ICON_INFORMATION)
                    dlg.ShowModal()
                success = self.keyModel.addKeyToAgent(passphrase, keyAddedSuccessfullyCallback, passphraseIncorrectCallback, privateKeyFileNotFoundCallback, failedToConnectToAgentCallback)
                if success:
                    logger.debug("onAddKeyToOrRemoveFromAgent: Added key to agent.")
                    self.populateFingerprintInAgentField()
                    self.addKeyToOrRemoveKeyFromAgentButton.SetLabel("Remove Strudel key from agent")
        elif self.addKeyToOrRemoveKeyFromAgentButton.GetLabel()=="Remove Strudel key from agent":
            logger.debug("onAddKeyToOrRemoveFromAgent: Removing key from agent...")
            success = self.keyModel.removeKeyFromAgent()
            if success:
                logger.debug("onAddKeyToOrRemoveFromAgent: Removed key from agent.")
                self.populateFingerprintInAgentField()
                self.addKeyToOrRemoveKeyFromAgentButton.SetLabel("Add Strudel key to agent")
            else:
                logger.debug("onAddKeyToOrRemoveFromAgent: Failed to remove key from agent.")
                dlg = wx.MessageDialog(self, "Failed to remove key from your agent.", "Strudel", wx.OK | wx.ICON_INFORMATION)
                dlg.ShowModal()

    def onDeleteKey(self,event):
        dlg = wx.MessageDialog(self, 
            "Are you sure you want to delete your key?",
            "Strudel", wx.YES_NO | wx.ICON_QUESTION)
        if dlg.ShowModal()==wx.ID_YES:

            success = self.keyModel.deleteKey(removeFromAgent=True, ignoreFailureToConnectToAgent=True)
            #success = success and self.keyModel.removeKeyFromAgent()
            if success:
                message = "Your Launcher key was successfully deleted!"
            else:
                message = "An error occured while attempting to delete your key."
            dlg = wx.MessageDialog(self, 
                message,
                "Strudel", wx.OK | wx.ICON_INFORMATION)
            dlg.ShowModal()

            if success:
                self.Show(False)

    def onChangePassphrase(self,event):
        from ChangeKeyPassphraseDialog import ChangeKeyPassphraseDialog
        changeKeyPassphraseDialog = ChangeKeyPassphraseDialog(self, wx.ID_ANY, 'Change Key Passphrase', self.keyModel)
        if changeKeyPassphraseDialog.ShowModal()==wx.ID_OK:
            logger.debug("Passphrase changed successfully!")

    def onResetKey(self, event):
        from ResetKeyDialog import ResetKeyDialog
        keyInAgent = self.fingerprintInAgentField.GetValue()!=""
        resetKeyDialog = ResetKeyDialog(self, wx.ID_ANY, 'Reset Key', self.keyModel, keyInAgent)
        resetKeyDialog.ShowModal()

        self.reloadAllFields()

    def onHelp(self, event):
        from help.HelpController import helpController
        if helpController is not None and helpController.initializationSucceeded:
            helpController.Display("SSH Keys")
        else:
            wx.MessageBox("Unable to open: " + helpController.launcherHelpUrl,
                          "Error", wx.OK|wx.ICON_EXCLAMATION)

    def onClose(self, event):
        self.Show(False)
        if hasattr(self,'startedAgent'):
            self.stopAgent() 

    def startAgent(self):
        self.keyModel.startAgent()
        self.startedAgent = True

    def stopAgent(self):
        self.keyModel.stopAgent()

