import wx
from logger.Logger import logger

class passphraseDialog(wx.Dialog):

    def __init__(self, parent, progressDialog, id, title, text, okString, cancelString,helpString="Help! What is all this?"):
        wx.Dialog.__init__(self, parent, id, pos=(200,150), style=wx.DEFAULT_DIALOG_STYLE ^ wx.RESIZE_BORDER)

        self.closedProgressDialog = False
        self.parent = parent
        self.progressDialog = progressDialog
        if self.progressDialog is not None:
            self.progressDialog.Show(False)
            self.closedProgressDialog = True

        self.SetTitle(title)
        self.label = wx.StaticText(self, -1, text)
        self.PassphraseField = wx.TextCtrl(self, wx.ID_ANY,style=wx.TE_PASSWORD ^ wx.TE_PROCESS_ENTER)
        self.PassphraseField.SetFocus()
        self.canceled=True
        self.Cancel = wx.Button(self,wx.ID_CANCEL,label=cancelString)
        self.OK = wx.Button(self,wx.ID_OK,label=okString)
        self.Help = wx.Button(self,-1,label=helpString)

        self.dataPanelSizer=wx.BoxSizer(wx.HORIZONTAL)
        self.dataPanelSizer.Add(self.label,flag=wx.ALL,border=5)
        self.dataPanelSizer.Add(self.PassphraseField,proportion=1,flag=wx.ALL,border=5)

        self.buttonPanelSizer=wx.BoxSizer(wx.HORIZONTAL)
        self.buttonPanelSizer.Add(self.Cancel,0,wx.ALL,5)
        self.buttonPanelSizer.Add(self.Help,0,wx.ALL,5)
        self.buttonPanelSizer.AddStretchSpacer(prop=1)
        self.buttonPanelSizer.Add(self.OK,0,wx.ALL,5)

        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.dataPanelSizer,flag=wx.EXPAND)
        self.sizer.Add(self.buttonPanelSizer,flag=wx.EXPAND)
        self.PassphraseField.Bind(wx.EVT_TEXT_ENTER,self.onEnter)
        self.OK.Bind(wx.EVT_BUTTON,self.onEnter)
        self.OK.SetDefault()
        self.Cancel.Bind(wx.EVT_BUTTON,self.onEnter)
        self.Help.Bind(wx.EVT_BUTTON,self.onHelp)
#
        self.border = wx.BoxSizer(wx.VERTICAL)
        self.border.Add(self.sizer, 0, wx.EXPAND|wx.ALL, 15)
        self.CentreOnParent(wx.BOTH)
        self.SetSizer(self.border)
        self.Fit()

        # User can click close icon in title bar:
        self.Bind(wx.EVT_CLOSE,self.onEnter)

    def onEnter(self,e):
        self.canceled=True
        if (e.GetId() == self.OK.GetId() or e.GetId() == self.PassphraseField.GetId()):
            logger.debug('onEnter: canceled = False')
            self.canceled = False
            self.password = self.PassphraseField.GetValue()
            self.EndModal(wx.ID_OK)
        else:
            logger.debug('onEnter: canceled = True')
            self.canceled = True
            self.password = None
            self.EndModal(wx.ID_CANCEL)

        if self.closedProgressDialog and self.canceled==False:
            if self.progressDialog is not None:
                self.progressDialog.Show(True)

    def onHelp(self,e):
        from help.HelpController import helpController
        helpController.Display("Authentication Overview")

    def getPassword(self):
        try:
            wx.EndBusyCursor()
            stoppedBusyCursor = True
        except:
            stoppedBusyCursor = False
        val = self.ShowModal()
        if stoppedBusyCursor:
            wx.BeginBusyCursor()
        passwd = self.password
        canceled = self.canceled
        self.Destroy()
        return (canceled,passwd)
