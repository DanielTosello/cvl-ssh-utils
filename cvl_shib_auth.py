import requests
import wx
import cvlsshutils.RequestsSessionSingleton
import cvlsshutils.AAF_Auth
import json
            
class shibbolethDance():


    def __init__(self,pubkey,parent,authorizedKeysFile=None,*args,**kwargs):
        self.pubkey=pubkey
        self.parent=parent
        self.kwargs=kwargs
        self.authorizedKeysFile=authorizedKeysFile
        if self.authorizedKeysFile==None:
            self.authorizedKeysFile="~/.ssh/authorized_keys"

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

    def getUpdateDict(self):
        return self.updateDict

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
        self.updateDict=auth.getUpdateDict()
        self.postKey(destURL)

    def deleteRemoteKey(self,host,username):
        from logger.Logger import logger
        import traceback
        if self.pubkey!=None:

            try:
                key=self.pubkey.split(' ')[1]
            except:
                key=self.pubkey

            import ssh
            sshClient = ssh.SSHClient()
            sshClient.set_missing_host_key_policy(ssh.AutoAddPolicy())
            try:
                sshClient.connect(hostname=host,timeout=10,username=username,password=None,allow_agent=True,look_for_keys=False)
                cmd="sed \'\\#{key}# D\' -i {authorizedKeysFile}"
                command = cmd.format(key=key,authorizedKeysFile=self.authorizedKeysFile)
                (stdin,stdout,stderr)=sshClient.exec_command(command)
                logger.debug("deleted remote key")
                err=stderr.readlines()
                if err!=[]:
                    raise Exception("unable to delete remote key")
            except:
                logger.debug("unable to delete remote key")
                logger.debug(traceback.format_exc())
