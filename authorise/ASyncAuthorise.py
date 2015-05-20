import requests
import wx
import cvlsshutils.RequestsSessionSingleton
import cvlsshutils.ASyncAuth
import passwordAuth
import json

class ASyncAuthorise(passwordAuth.passwordAuth):
    def __init__(self,parent,keydistObject,url,authorizedKeysFile=None,extraParams=None,*args,**kwargs):
        self.parent=parent
        self.kwargs=kwargs
        self.pubkey=None
        self.authorizedKeysFile=authorizedKeysFile
        self.keydistObject=keydistObject
        self.url=url
        self.extraParams=extraParams
        if self.authorizedKeysFile==None:
            self.authorizedKeysFile="~/.ssh/authorized_keys"

    def postKey(self,apitoken):
        data={}
        data['ssh_pub_key']=self.pubkey
        data['apitoken']=apitoken
        r=self.session.post(self.url,data=data,verify=False)
        if r.status_code==200:
            if 'json' in r.headers['content-type']:
                returned=json.loads(r.text)
                if isinstance(returned,type({})):
                    self.__dict__.update(returned)
                    self.updateDict.update(returned)
        if r.status_code!=200:
            raise Exception("%s"%r.text)

    def getUpdateDict(self):
        return self.updateDict

    def getLocalUsername(self):
        if hasattr(self,'username'):
            return self.username
        else:
            raise Exception('Username not set by the cvl_shib_auth module. (It really should have been)')


    def copyID(self,keyModel,username=None,host=None):
        from logger.Logger import logger
        self.keyModel=keyModel
        self.pubkey=self.keyModel.getPubKey()

        # Use of a singleton here means that we should be able to do SSO on any AAF/Shibolleth web service. However we might have to guess the IdP.
        self.session=cvlsshutils.RequestsSessionSingleton.RequestsSessionSingleton().GetSession()
        destURL='https://portal.synchrotron.org.au:443/api/v1/oauth/token'
        auth=cvlsshutils.ASyncAuth.ASyncAuth(self.session,destURL,parent=self.parent,extraParams=self.extraParams,**self.kwargs)
        apitoken=auth.gettoken()
        self.updateDict=auth.getUpdateDict()
        try:
            self.postKey(apitoken)
        except Exception as e:
            raise e
        logger.info('copied pub key %s to user account %s'%(self.pubkey,self.username))


    
