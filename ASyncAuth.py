import wx
from HTMLParser import HTMLParser
from logger.Logger import logger
import json
class ASyncAuth():

    class reset_exception(Exception):
        def __init__(self,*args,**kwargs):
            super(ASyncAuth.reset_exception,self).__init__(*args,**kwargs)
            

    class UserPassDialog(wx.Dialog):
        def __init__(self,user=None,*args,**kwargs):
            super(ASyncAuth.UserPassDialog,self).__init__(*args,**kwargs)
            self.SetSizer(wx.BoxSizer(wx.VERTICAL))
            p=wx.Panel(self)
            p.SetSizer(wx.FlexGridSizer(cols=2,rows=2,hgap=15,vgap=15))
            t=wx.StaticText(p,wx.ID_ANY,label='Please Australian Synchrotron Username (email address)')
            p.GetSizer().Add(t)
            tc=wx.TextCtrl(p,wx.ID_ANY,name='username_field')
            tc.SetMinSize((300,-1))
            if user!=None:
                tc.SetValue(user)
            p.GetSizer().Add(tc,proportion=1,flag=wx.EXPAND)
            t=wx.StaticText(p,wx.ID_ANY,label='Please enter your Australian Synchrotron password')
            p.GetSizer().Add(t)
            pc=wx.TextCtrl(p,wx.ID_ANY,name='passwd_field',style=wx.TE_PASSWORD)
            p.GetSizer().Add(pc,proportion=1,flag=wx.EXPAND)
            self.GetSizer().Add(p,proportion=1,flag=wx.EXPAND|wx.ALL,border=15)
            p=wx.Panel(self)
            p.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
            p.GetSizer().Add((1,-1),proportion=1,flag=wx.EXPAND)
            b=wx.Button(p,wx.ID_CANCEL,"Cancel")
            b.Bind(wx.EVT_BUTTON,self.onClose)
            p.GetSizer().Add(b,flag=wx.ALIGN_RIGHT|wx.ALL,border=15)
            b=wx.Button(p,wx.ID_OK,"OK")
            b.Bind(wx.EVT_BUTTON,self.onClose)
            p.GetSizer().Add(b,flag=wx.ALIGN_RIGHT|wx.ALL,border=15)
            self.GetSizer().Add(p,flag=wx.EXPAND|wx.BOTTOM,border=10)
            self.Fit()

        def onClose(self,event):
            rv=event.GetEventObject().GetId()
            self.EndModal(rv)

        def getUser(self):
            return self.FindWindowByName('username_field').GetValue()

        def getPasswd(self):
            return self.FindWindowByName('passwd_field').GetValue()

    def queryUserPass(self,queue,username=None):

        dlg=ASyncAuth.UserPassDialog(parent=self.parent,id=wx.ID_ANY,user=username)
        try:
            wx.EndBusyCursor()
        except:
            pass
        self.progressDialog.Hide()
        if dlg.ShowModal()==wx.ID_OK:
            username=dlg.getUser()
            passwd=dlg.getPasswd()
            queue.put((username,passwd))
        else:
            queue.put(None)
        dlg.Destroy()
        self.progressDialog.Show()
        wx.BeginBusyCursor()
                    

    def getUpdateDict(self):
        d={}
        d['aaf_username']=self.username
        return d
        

    def __init__(self,s,authURL,parent,postFirst=None,extraParams=None,*args,**kwargs):
        self.parent=parent
        if kwargs.has_key('aaf_username'):
            self.username=kwargs['aaf_username']
        else:
            self.username=None
        self.passwd=None
        self.destURL=authURL
        self.postFirst=postFirst

        if kwargs.has_key('progressDialog'):
            self.progressDialog=kwargs['progressDialog']
        else:
            self.progressDialog=None
        self.session=s
        self.clientusername=extraParams['oauthclient']
        self.clientpasswd=extraParams['oauthclientpasswd']

    def gettoken(self):
        retry = True
        while retry:
            import Queue
            queue=Queue.Queue()
            wx.CallAfter(self.queryUserPass,queue,self.username)
            res=queue.get()
            if res==None:
                raise Exception("Login cancelled")
            else:
                (self.username,self.passwd)=res
                logger.debug('queryIdPUserPass set values for user: %s.'%(self.username))
            r=self.session.post(self.destURL,auth=(self.clientusername,self.clientpasswd),data={'grant_type': 'password','username':self.username,'password':self.passwd})
            if r.status_code==200:
                data=json.loads(r.text)
                print "got an access token"
                retry=False
                print r.text
            else:
                print r.text

        return data['data']['access_token']

