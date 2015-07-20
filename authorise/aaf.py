import requests
import wx
import cvlsshutils.RequestsSessionSingleton
import cvlsshutils.AAF_Auth
import passwordAuth
import json
            
class aaf(passwordAuth.passwordAuth):
# inherit the deleteRemoveKey and testAuth methods from the password module


    def __init__(self,parent,keydistObject,authorizedKeysFile=None,url=None,*args,**kwargs):
        self.parent=parent
        self.kwargs=kwargs
        self.pubkey=None
        self.authorizedKeysFile=authorizedKeysFile
        self.keydistObject=keydistObject
        self.url=url
        if self.authorizedKeysFile==None:
            self.authorizedKeysFile="~/.ssh/authorized_keys"

    def postKey(self,url):
        print "posting key to url %s"%url
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

    def getUpdateDict(self):
        print "in get update dict"
        if hasattr(self,'username'):
            self.updateDict['username'] = self.username
        print "returning updateDict"
        return self.updateDict

    def getLocalUsername(self):
        if hasattr(self,'username'):
            return self.username
        else:
            raise Exception('Username not set by the cvl_shib_auth module. (It really should have been)')


    def copyID(self,keyModel,username=None,host=None):
        self.keyModel=keyModel
        self.pubkey=self.keyModel.getPubKey()

        # Use of a singleton here means that we should be able to do SSO on any AAF/Shibolleth web service. However we might have to guess the IdP.
        self.session=cvlsshutils.RequestsSessionSingleton.RequestsSessionSingleton().GetSession()
        destURL=self.url
        auth=cvlsshutils.AAF_Auth.AAF_Auth(self.session,destURL,parent=self.parent,**self.kwargs)
        auth.auth_cycle()
        self.updateDict=auth.getUpdateDict()
        try:
            self.postKey(destURL)
        except Exception as e:
            raise e


