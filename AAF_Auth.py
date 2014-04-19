import wx
from HTMLParser import HTMLParser
from logger.Logger import logger
class AAF_Auth():

    class reset_exception(Exception):
        def __init__(self,*args,**kwargs):
            super(AAF_Auth.reset_exception,self).__init__(*args,**kwargs)
            
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

    class IdPUserPassDialog(wx.Dialog):
        def __init__(self,options,idp=None,user=None,*args,**kwargs):
            super(AAF_Auth.IdPUserPassDialog,self).__init__(*args,**kwargs)
            self.SetSizer(wx.BoxSizer(wx.VERTICAL))
            p=wx.Panel(self)
            p.SetSizer(wx.FlexGridSizer(cols=2,rows=3,hgap=15,vgap=15))
            t=wx.StaticText(p,wx.ID_ANY,label='Please select your IdP')
            p.GetSizer().Add(t)
            cb=wx.ComboBox(p,choices=options,name='idp_field')
            if idp!=None:
                try:
                    index=options.index(idp)
                    cb.Select(index)
                except Exception as e:
                    pass
            p.GetSizer().Add(cb)
            t=wx.StaticText(p,wx.ID_ANY,label='Please enter your Username')
            p.GetSizer().Add(t)
            tc=wx.TextCtrl(p,wx.ID_ANY,name='username_field')
            if user!=None:
                tc.SetValue(user)
            p.GetSizer().Add(tc,proportion=1,flag=wx.EXPAND)
            t=wx.StaticText(p,wx.ID_ANY,label='Please enter your password')
            p.GetSizer().Add(t)
            pc=wx.TextCtrl(p,wx.ID_ANY,name='passwd_field',style=wx.TE_PASSWORD)
            p.GetSizer().Add(pc,proportion=1,flag=wx.EXPAND)
            self.GetSizer().Add(p,proportion=1,flag=wx.EXPAND|wx.ALL,border=15)
            p=wx.Panel(self)
            p.SetSizer(wx.BoxSizer(wx.HORIZONTAL))
            p.GetSizer().Add((1,-1),proportion=1,flag=wx.EXPAND)
            b=wx.Button(p,wx.ID_CANCEL,"Cancel")
            b.Bind(wx.EVT_BUTTON,self.onClose)
            p.GetSizer().Add(b,flag=wx.ALIGN_RIGHT|wx.RIGHT,border=15)
            b=wx.Button(p,wx.ID_OK,"OK")
            b.Bind(wx.EVT_BUTTON,self.onClose)
            p.GetSizer().Add(b,flag=wx.ALIGN_RIGHT)
            self.GetSizer().Add(p,flag=wx.EXPAND|wx.ALL,border=15)
            self.Fit()

        def onClose(self,event):
            rv=event.GetEventObject().GetId()
            self.EndModal(rv)

        def getIdP(self):
            idp=self.FindWindowByName('idp_field')
            s=idp.GetSelection()
            if s>0:
                return (s,idp.GetStringSelection())
            else:
                return None

        def getUser(self):
            return self.FindWindowByName('username_field').GetValue()

        def getPasswd(self):
            return self.FindWindowByName('passwd_field').GetValue()

    def queryIdPUserPass(self,options,queue,idp=None,username=None):
        o=[list(t) for t in zip(*options)]

        dlg=AAF_Auth.IdPUserPassDialog(parent=self.parent,id=wx.ID_ANY,options=o[1],idp=idp,user=username)
        wx.EndBusyCursor()
        self.progressDialog.Hide()
        if dlg.ShowModal()==wx.ID_OK:
            res=dlg.getIdP()
            while res==None:
                dlg1=wx.MessageDialog(parent=self.parent,message='You must select and IdP to continue',style=wx.OK)
                dlg1.ShowModal()
                btn=dlg.ShowModal()
                if btn==wx.ID_OK:
                    res=dlg.GetValue()
                else:
                    break
            username=dlg.getUser()
            passwd=dlg.getPasswd()
            queue.put((o[0][res[0]],res[1],username,passwd))
        else:
            queue.put(None)
        dlg.Destroy()
        self.progressDialog.Show()
        wx.BeginBusyCursor()



    def getIdPChoices(self,session):
        url='https://ds.aaf.edu.au/discovery/DS'
        r=session.get(url,verify=False)
        p=AAF_Auth.DSForm()
        p.feed(r.text)
        return p.options

                    
    def processIdP(self,session,text,url,idpName,user,pw):
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
                p.inputs[i] = user
            if ('pass' in i or 'Pass' in i) and p.inputs[i]==None:
                p.inputs[i] = pw
        nexturl = p.attrs['action']
        if  not 'http' in nexturl[0:4]:
            nexturl=url.split('/')[0]+'//'+url.split('/')[2]+nexturl

        r=session.post(nexturl,data=p.inputs,verify=False)
        return r

    def getUpdateDict(self):
        d={}
        d['aaf_idp']=self.idp
        d['aaf_username']=self.username
        return d
        

    def __init__(self,s,destURL,parent,*args,**kwargs):
        self.parent=parent
        if kwargs.has_key('aaf_idp'):
            self.idp=kwargs['aaf_idp']
        else:
            self.idp=None
        if kwargs.has_key('aaf_username'):
            self.username=kwargs['aaf_username']
        else:
            self.username=None
        self.passwd=None
        self.destURL=destURL
        if kwargs.has_key('progressDialog'):
            self.progressDialog=kwargs['progressDialog']
        else:
            self.progressDialog=None
        self.session=s

    def auth_cycle(self):
        self.idpoptions=self.getIdPChoices(self.session)
        retry=True
        while retry:
            try:
                r=self.session.get(self.destURL,verify=False)
                if self.destURL in r.url: # We already have a valid session with the web service
                    logger.debug('AAF cycle unnecessary, we\'re already auth\'d to this service')
                    self.response=r
                    return

                import Queue
                queue=Queue.Queue()
                if self.idp==None or 'Select' in self.idp or self.idp == "" or self.username==None or self.username == "" or self.passwd==None or self.passwd=="":
                    wx.CallAfter(self.queryIdPUserPass,self.idpoptions,queue,self.idp,self.username)
                    res=queue.get()
                    if res==None:
                        raise Exception("Login cancled")
                    else:
                        (myidp,self.idp,self.username,self.passwd)=res
                        logger.debug('queryIdPUserPass set values for idp: %s user: %s.'%(self.idp,self.username))
                
                if r.url.startswith('https://ds'): # we've been redirected to the AAF discovery service
                    logger.debug('AAF cycle sent us to the discovery service. Prompting for the correct IdP')
                    p = AAF_Auth.DSForm()
                    p.feed(r.text)
                    logger.debug('querying for IdP, username and password, initial values: %s %s'%(self.idp,self.username))
                    d={}
                    d['user_idp'] = myidp.encode('ascii')
                    d['Select']='Select'
                    nexturl = p.attrs['action']
                    if  not 'http' in nexturl[0:4]:
                        nexturl=r.url.split('/')[0]+'//'+r.url.split('/')[2]+nexturl
                    r=self.session.post(nexturl,data=d,verify=False)

                else:
                    logger.debug('AAF cycle bypassed the discovery service. Perhaps the web service sent us directly to an IdP? This is unusual, but within spec')

                if self.destURL in r.url: # If we have a session with the IdP and the IdP didn't ask to release attributes, we might already be at the destionation URL
                    self.response=r
                    return
                
                p=AAF_Auth.genericForm() # If we're not at the destURL we should be at either the IdP authentication page, or the IdP attribute release page
                # Not tested. I think if we already have session with the idp, the IdP may return an attribute release form rather than a login form. the method self.idp should still work.
                loop=0
                while (not p.inputs.has_key('SAMLResponse')):
                    if self.destURL in r.url: # I'm puzzled by this, I though the SAMLResponse would always come as a hidden field in a form from the IdP along with a redirect, but apparently not
                        self.response=r
                        return
                    logger.debug('processing text as if it was an IdP login form idp')
                    r=self.processIdP(self.session,r.text,r.url,self.idp,self.username,self.passwd)
                    logger.debug('processing text to look for a SAML response')
                    p=AAF_Auth.genericForm()
                    p.feed(r.text)
                    reprompt=False
                    for i in p.inputs.keys():
                        if ('user' in i or 'User' in i):
                            reprompt=True
                    if reprompt:
                        wx.CallAfter(self.queryIdPUserPass,self.idpoptions,queue,self.idp,self.username)
                        res=queue.get()
                        if res==None:
                            raise Exception("Login cancled")
                        else:
                            oldidp=self.idp
                            (myidp,self.idp,self.username,self.passwd)=res
                            if oldidp!=self.idp:
                                raise AAF_Auth.reset_exception

                if self.destURL in r.url: # We have succeeded
                    logger.debug('AAF cycle succeeded')
                    retry=False
                    self.response=r
                    return
                nexturl = p.attrs['action']
                r=self.session.post(nexturl,data=p.inputs,verify=False) # We need one more post? This seems to be the behaviour on NeCTAR
                if self.destURL in r.url: # We have succeeded
                    logger.debug('AAF Cycle succeeded with the extra post')
                    retry=False
                    self.response=r
                    return
                else:
                    raise Exception("We went through the whole AAF cycle, but didn't end up where the though we would. This is a bug. Please help us fix this up by sending an email/crash report")
            except AAF_Auth.reset_exception as e:
                pass
