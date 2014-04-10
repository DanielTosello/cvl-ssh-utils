import wx
from HTMLParser import HTMLParser
from logger.Logger import logger
class AAF_Auth():
    class nectarLoginForm(HTMLParser):
        def handle_starttag(self,tag,attrs):
            if tag == 'form':
                for attr in attrs:
                    if (attr[0]=='action'):
                        self.postURL=attr[1]
            if tag == 'input':
                for attr in attrs:
                    if attr[0] == 'name' and attr[1] == 'csrfmiddlewaretoken':
                        for iattr in attrs:
                            if iattr[0] == 'value':
                                self.csrfmiddlewaretoken=iattr[1]

    class genericForm(HTMLParser):
        def __init__(self,*args,**kwargs):
            HTMLParser.__init__(self)
            self.processingForm=False
            self.processingOption=False
            self.attrs={}
            self.options=[]
            self.inputs={}

        def handle_starttag(self,tag,attrs):
            if tag == 'form':
                d={}
                for attr in attrs:
                    self.attrs[attr[0]]=attr[1]
                self.processingForm=True
            if self.processingForm and tag == 'input':
                dattrs={}
                for attr in attrs:
                    dattrs[attr[0]]=attr[1]
                if dattrs.has_key('name'):
                    if dattrs.has_key('value'):
                        self.inputs[dattrs['name']]=dattrs['value']
                    else:
                        self.inputs[dattrs['name']]=None

        def handle_endtag(self,tag):
            if tag == 'form':
                self.processingForm=False

    class DSForm(HTMLParser):
        processingForm=False
        processingOption=False
        attrs={}
        options=[]
        def handle_starttag(self,tag,attrs):
            if tag == 'form':
                d={}
                for attr in attrs:
                    self.attrs[attr[0]]=attr[1]
                self.processingForm=True
            if self.processingForm and tag == 'option':
                self.processingOption=True
                d={}
                for attr in attrs:
                    d[attr[0]]=attr[1]
                self.currentOption=d['value']

        def handle_endtag(self,tag):
            if tag == 'form':
                self.processingForm=False
            if tag == 'option':
                self.processingOption=False
                self.options.append((self.currentOption,self.currentData))
        def handle_data(self,data):
            if self.processingOption:
                self.currentData = data


    class IdPDialog(wx.Dialog):
        def __init__(self,options,idp=None,*args,**kwargs):
            super(AAF_Auth.IdPDialog,self).__init__(*args,**kwargs)
            self.SetSizer(wx.BoxSizer(wx.VERTICAL))
            t=wx.StaticText(self,label='Please select your IdP')
            self.GetSizer().Add(t,border=5,flag=wx.EXPAND|wx.ALL)
            self.choice=wx.ComboBox(self,choices=options)
            self.GetSizer().Add(self.choice,border=5,flag=wx.EXPAND|wx.ALL)
            p=wx.Panel(self)
            p.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
            b=wx.Button(p,id=wx.ID_OK,label="OK")
            b.Bind(wx.EVT_BUTTON,self.onClose)
            p.GetSizer().Add(b,border=5,flag=wx.ALL)
            b=wx.Button(p,id=wx.ID_CANCEL,label="Cancel")
            b.Bind(wx.EVT_BUTTON,self.onClose)
            p.GetSizer().Add(b,border=5,flag=wx.ALL)
            self.GetSizer().Add(p)
            if idp!=None:
                try:
                    index=options.index(idp)
                    self.choice.SetSelection(index)
                except Exception as e:
                    pass
            self.Fit()

        def onClose(self,evt):
            self.EndModal(evt.GetEventObject().GetId())

        def GetValue(self):
            s=self.choice.GetSelection()
            if s>0:
                return (s,self.choice.GetStringSelection())
            else:
                return None



    def queryIdP(self,options,queue,idp=None):
        o=[list(t) for t in zip(*options)]

        print("IdP is %s"%idp)
        if idp==None or idp=="" or "Select the" in idp:
            print("Showing IdP dialog")
            dlg=AAF_Auth.IdPDialog(parent=self.parent,id=wx.ID_ANY,options=o[1],idp=idp)
            wx.EndBusyCursor()
            if dlg.ShowModal()==wx.ID_OK:
                res=dlg.GetValue()
                while res==None:
                    dlg1=wx.MessageDialog(parent=self.parent,message='You must select and IdP to continue',style=wx.OK)
                    dlg1.ShowModal()
                    btn=dlg.ShowModal()
                    if btn==wx.ID_OK:
                        res=dlg.GetValue()
                    else:
                        break
                queue.put((o[0][res[0]],res[1]))
            else:
                queue.put(None)
            dlg.Destroy()
            wx.BeginBusyCursor()
        else:
            for i in range(0,len(o[1])):
                if o[1][i]==idp:
                    queue.put((o[0][i],o[1][i]))

    def getPass(self,queue,user,idpName):
        if user==None or idpName==None:
            dlg=wx.PasswordEntryDialog(self.parent,"Please enter the password for your IdP")
        else:
            dlg=wx.PasswordEntryDialog(self.parent,"Please enter the password for %s at %s"%(user,idpName))
        wx.EndBusyCursor()
        retval=dlg.ShowModal()
        if retval==wx.ID_OK:
            queue.put(dlg.GetValue())
        else:
            queue.put(None)
        wx.BeginBusyCursor()
        dlg.Destroy()

    def getUsername(self,queue):
        dlg=wx.TextEntryDialog(self.parent,"Please enter the username for your IdP")
        wx.EndBusyCursor()
        if dlg.ShowModal() == wx.ID_OK:
            queue.put(dlg.GetValue())
        else:
            queue.put(None)
        wx.BeginBusyCursor()
        dlg.Destroy()

    def getIdPChoices(self,session):
        url='https://ds.aaf.edu.au/discovery/DS'
        r=session.get(url,verify=False)
        p=AAF_Auth.DSForm()
        p.feed(r.text)
        return p.options

                    
    def processIdP(self,session,text,url,idpName):
        p = AAF_Auth.genericForm()
        p.feed(text)
        import getpass
        import sys
        import Queue
        userRequired=False
        passwordRequired=False
        queue=Queue.Queue()
        for i in p.inputs.keys():
            if ('user' in i or 'User' in i) and p.inputs[i]==None:
                if self.username==None or self.username=="":
                    userRequired=True
                else:
                    user=self.username
            if ('pass' in i or 'Pass' in i) and p.inputs[i]==None:
                passwordRequired=True
        if userRequired:
            wx.CallAfter(self.getUsername,queue)
            user=queue.get()
            if user==None:
                raise Exception("Login canceled")
        if passwordRequired:
            wx.CallAfter(self.getPass,queue,user,idpName)
            pw=queue.get()
            if pw==None:
                raise Exception("Login canceled")
        for i in p.inputs.keys():
            if ('user' in i or 'User' in i) and p.inputs[i]==None:
                p.inputs[i] = user
            if ('pass' in i or 'Pass' in i) and p.inputs[i]==None:
                p.inputs[i] = pw
        nexturl = p.attrs['action']
        if  not 'http' in nexturl[0:4]:
            nexturl=url.split('/')[0]+'//'+url.split('/')[2]+nexturl

        r=session.post(nexturl,data=p.inputs,verify=False)
        return r

    def getIdP(self):
        return self.idp
        

    def __init__(self,s,destURL,parent,idp=None,*args,**kwargs):
        self.parent=parent
        self.idp=idp
        if kwargs.has_key('aaf_username'):
            self.username=kwargs['aaf_username']
        else:
            self.username=None
        if destURL==None:
            return
        r=s.get(destURL,verify=False)
        if destURL in r.url: # We already have a valid session with the web service
            logger.debug('AAF cycle unnecessary, we\'re already auth\'d to this service')
            self.response=r
            return

        
        if r.url.startswith('https://ds'): # we've been redirected to the AAF discovery service
            logger.debug('AAF cycle sent us to the discovery service. Prompting for the correct IdP')
            p = AAF_Auth.DSForm()
            p.feed(r.text)
            import Queue
            queue=Queue.Queue()
            wx.CallAfter(self.queryIdP,p.options,queue,self.idp)
            res=queue.get()
            if res==None:
                raise Exception("Login cancled")
            else:
                (myidp,self.idp)=res
            d={}
            d['user_idp'] = myidp.encode('ascii')
            d['Select']='Select'
            nexturl = p.attrs['action']
            if  not 'http' in nexturl[0:4]:
                nexturl=r.url.split('/')[0]+'//'+r.url.split('/')[2]+nexturl
            r=s.post(nexturl,data=d,verify=False)

        else:
            logger.debug('AAF cycle bypassed the discovery service. Perhaps the web service sent us directly to an IdP? This is unusual, but within spec')

        if destURL in r.url: # If we have a session with the IdP and the IdP didn't ask to release attributes, we might already be at the destionation URL
            self.response=r
            return
        
        p=AAF_Auth.genericForm() # If we're no at the destURL we should be at either the IdP authentication page, or the IdP attribute release page
        # Not tested. I think if we already have session with the idp, the IdP may return an attribute release form rather than a login form. the method self.idp should still work.
        while (not p.inputs.has_key('SAMLResponse')):
            if destURL in r.url: # I'm puzzled by this, I though the SAMLResponse would always come as a hidden field in a form from the IdP along with a redirect, but apparently not
                self.response=r
                return
            r=self.processIdP(s,r.text,r.url,self.idp)
            p=AAF_Auth.genericForm()
            p.feed(r.text)

        if destURL in r.url: # We have succeeded
            logger.debug('AAF cycle succeeded')
            self.response=r
            return
        nexturl = p.attrs['action']
        r=s.post(nexturl,data=p.inputs,verify=False) # We need one more post? This seems to be the behaviour on NeCTAR
        if destURL in r.url: # We have succeeded
            logger.debug('AAF Cycle succeeded with the extra post')
            self.response=r
            return
        else:
            raise Exception("We went through the whole AAF cycle, but didn't end up where the though we would. This is a bug. Please help us fix this up by sending an email/crash report")
