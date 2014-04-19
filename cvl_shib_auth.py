import requests
import wx
import cvlsshutils.RequestsSessionSingleton
import cvlsshutils.AAF_Auth
import json
            
class shibbolethDance():


    def __init__(self,pubkey,parent,*args,**kwargs):
        self.pubkey=pubkey
        self.parent=parent
        self.kwargs=kwargs

    def postKey(self,url):
        data={}
        data['ssh_pub_key']=self.pubkey
        r=self.session.post(url,data=data,verify=False)
        if r.status_code==200:
            if 'json' in r.headers['content-type']:
                returned=json.loads(r.text)
                if isinstance(returned,type({})):
                    self.__dict__.update(returned)
        if r.status_code!=200:
            raise Exception("%s"%r.text)

    def getIdP(self):
        return self.idp

    def getLocalUsername(self):
        if hasattr(self,'username'):
            return self.username
        else:
            raise Exception('Username not set by the cvl_shib_auth module. (It really should have been)')


    def copyID(self):

        # Use of a singleton here means that we should be able to do SSO on any AAF/Shibolleth web service. However we might have to guess the IdP.
        self.session=cvlsshutils.RequestsSessionSingleton.RequestsSessionSingleton().GetSession()
        destURL="https://autht.massive.org.au/cvl/"
        auth=cvlsshutils.AAF_Auth.AAF_Auth(self.session,destURL,parent=self.parent,**self.kwargs)
        auth.auth_cycle()
        self.idp=auth.getIdP()
        self.postKey(destURL)
