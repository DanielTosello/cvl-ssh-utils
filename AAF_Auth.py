import wx
from HTMLParser import HTMLParser
from logger.Logger import logger
import threading
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
                    logger.debug("aaf cycle, found a form with attribute %s=%s"%(attr[0],attr[1]))
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
            cb=wx.ComboBox(p,choices=options,style=wx.CB_READONLY,name='idp_field')
            cb.Select(0)
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
            p.GetSizer().Add(b,flag=wx.ALIGN_RIGHT|wx.ALL,border=15)
            b=wx.Button(p,wx.ID_OK,"OK")
            b.Bind(wx.EVT_BUTTON,self.onClose)
            p.GetSizer().Add(b,flag=wx.ALIGN_RIGHT|wx.ALL,border=15)
            self.GetSizer().Add(p,flag=wx.EXPAND|wx.BOTTOM,border=10)
            self.GetSizer().Fit(self)

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

    def wxQueryIdPUserPass(self,options,queue,idp=None,username=None):
        o=[list(t) for t in zip(*options)]

        dlg=AAF_Auth.IdPUserPassDialog(parent=self.parent,id=wx.ID_ANY,options=o[1],idp=idp,user=username)
        try:
            wx.EndBusyCursor()
        except:
            pass
        if self.progressDialog!=None:
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
        if self.progressDialog!=None:
            self.progressDialog.Show()
        wx.BeginBusyCursor()

    def queryIdPUserPass(self,options,queue,idp=None,username=None):
        if self.testcreds!=None:
            queue.put(self.testcreds)
        else:
            wx.CallAfter(self.wxQueryIdPUserPass,options,queue,idp,username)

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
        try:
            nexturl = p.attrs['action']
        except:
            nexturl = url
        #logger.debug('idp form inputs %s'%p.inputs)
        for k in p.inputs.keys():
            if 'RESET' in k.upper():
                logger.debug('deleting the input %s from the attribute release form'%k)
                del p.inputs[k]
        if  not 'http' in nexturl[0:4]:
            nexturl=url.split('/')[0]+'//'+url.split('/')[2]+nexturl

        r=session.post(nexturl,data=p.inputs,verify=False)
        return r

    def getUpdateDict(self):
        d={}
        d['aaf_idp']=self.idp
        d['aaf_username']=self.username
        return d
        

    def __init__(self,s,authURL,parent,postFirst=None,testcreds=None,*args,**kwargs):
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
        self.destURL=authURL
        self.postFirst=postFirst
        self.testcreds=testcreds
        self.verify=False

        if kwargs.has_key('progressDialog'):
            self.progressDialog=kwargs['progressDialog']
        else:
            self.progressDialog=None
        self.session=s

    def guessPageType(self,url,text):
        if url.startswith('https://ds'):
            return "ds"
        if url.startswith(self.destURL):
            return "desturl"
        p=AAF_Auth.genericForm()
        p.feed(text)
        for i in p.inputs.keys():
            if ('user' in i or 'User' in i):
                return "authn"
        if len(p.inputs.keys()) >0:
            return "generic"
        logger.debug('guessPageType didn\'t work %s %s '%(url,self.destURL))
        print('guessPageType didn\'t work %s %s '%(url,self.destURL))
        raise Exception("unknown page type in AAF login process")

    def getNextUrl(self,r,p):
        nexturl = p.attrs['action']
        if nexturl == "":
            nexturl = r.url
        if  not 'http' in nexturl[0:4]:
            nexturl=r.url.split('/')[0]+'//'+r.url.split('/')[2]+nexturl
        return nexturl

    def auth_cycle(self):
        self.idpoptions=self.getIdPChoices(self.session)
        r=self.session.get(self.destURL,verify=self.verify)
        complete=False
        loopcounter=0
        authncount=0
        while not complete and (loopcounter-authncount) < 10:
            loopcounter=loopcounter+1
            pagetype = self.guessPageType(r.url,r.text)
            print "%s %s %s"%(r.url,self.destURL,pagetype)
            # If we have a generic form, we just attempt to post. This is probably either a form that says "login with AAF" or "do you consent to attribute release"
            if pagetype == 'generic':     
                p=AAF_Auth.genericForm()
                p.feed(r.text)
                nexturl = self.getNextUrl(r,p)
                r=self.session.post(nexturl,data=p.inputs,verify=self.verify)
            # If we see the discovery service, we ask the user for their IdP username and password
            if pagetype == 'ds':
                import Queue
                queue=Queue.Queue()
                if self.idp==None or 'Select' in self.idp or self.idp == "" or self.username==None or self.username == "" or self.passwd==None or self.passwd=="":
                    t=threading.Thread(target=self.queryIdPUserPass,args=[self.idpoptions,queue,self.idp,self.username])
                    t.start()
                    res=queue.get()
                    t.join()
                    if res==None:
                        raise Exception("Login cancelled")
                    else:
                        (myidp,self.idp,self.username,self.passwd)=res
                        logger.debug('queryIdPUserPass set values for idp: %s user: %s.'%(self.idp,self.username))
                p = AAF_Auth.DSForm()
                p.feed(r.text)
                logger.debug('querying for IdP, username and password, initial values: %s %s'%(self.idp,self.username))
                d={}
                d['user_idp'] = myidp.encode('ascii')
                d['Select']='Select'
                logger.debug('in auth_cycle, url is %s'%r.url)
                nexturl = self.getNextUrl(r,p)
                r=self.session.post(nexturl,data=d,verify=True)
            # If we see the authentication page we give it the username and password. If we see if more than once we prompt for the IdP username and password. If the IdP changes we raise an exception to reset the whole process
            if pagetype == 'authn':
                if authncount > 0:
                    t=threading.Thread(target=self.queryIdPUserPass,args=[self.idpoptions,queue,self.idp,self.username])
                    t.start()
                    res=queue.get()
                    t.join()
                    if res==None:
                        raise Exception("Login cancled")
                    else:
                        oldidp=self.idp
                        (myidp,self.idp,self.username,self.passwd)=res
                        if oldidp!=self.idp:
                            authncount=0
                            r=self.session.get(self.destURL,verify=self.verify)
                authncount=authncount+1
                r=self.processIdP(self.session,r.text,r.url,self.idp,self.username,self.passwd)
            if pagetype == 'desturl':
                complete=True
        if not complete:
            raise Exception("AAF Authentication failed. It appeared to get in an loop")

