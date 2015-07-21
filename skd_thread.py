import threading
import cvlsshutils.authorise
from logger.Logger import logger
import os
import wx
from PassphraseDialog import passphraseDialog
from CreateNewKeyDialog import CreateNewKeyDialog
import traceback
import Queue
class KeyDist(object):
    def __init__(self,keyModel,parentWindow,progressDialog,jobParams,siteConfig,startupinfo=None,creationflags=0,extraParams={},*args,**kwargs):
        super(KeyDist,self).__init__(*args,**kwargs)
        self.keyModel=keyModel
        self._stopped = threading.Event()
        self.stopAgentOnExit = threading.Event()
        self._exit = threading.Event()
        self.cleanupThread = threading.Thread(target=self.cleanup)
        self.cleanupThread.setDaemon(True)
        self.cleanupThread.start()
        self.parentWindow=parentWindow
        self.progressDialog=progressDialog
        self.extraParams=extraParams
        self.jobParams=jobParams
        self.siteConfig=siteConfig
        self.displayStrings=self.siteConfig.displayStrings
        self.ec2_access_key=None
        self.ec2_secret_key=None
        self.updateDict={}
        self.startupinfo=startupinfo
        self.creationflags=creationflags
        self.removeKeyOnExit=threading.Event()
        self.keyCreated=threading.Event()
        self.cancelMessage=""
        self.password=None
        print "in keydist.__init__ %s"%self.siteConfig.authURL


    def canceled(self):
        return self._exit.isSet()

    def shutdownReal(self):
        self._stopped.set()
        self._exit.set()

    def scanHostKeys(self):
        logger.debug("implement scanHostKeys")

    def authorise(self):

        if self.siteConfig.authURL!=None and 'ASync' in self.siteConfig.authURL:
            copymethod='ASyncAuth'
            try:
                self.extraParams['oauthclient']=self.siteConfig.oauthclient
                self.extraParams['oauthclientpasswd']=self.siteConfig.oauthclientpasswd
            except Exception as e:
                logger.debug('exception %s'%e)
                logger.debug(traceback.format_exc())
                pass
        elif self.siteConfig.authURL!=None:
            copymethod='aaf'
        else:
            copymethod='passwordAuth'
        if self.siteConfig.provision == "NeCTAR":
            copymethod='ec2'
        authorizedKeysFile=None

        if not self.jobParams.has_key('aaf_username'):
            self.jobParams['aaf_username'] = None
        if not self.jobParams.has_key('aaf_idp'):
            self.jobParams['aaf_idp'] = None
        if not self.jobParams.has_key('ec2_access_key'):
            self.jobParams['ec2_access_key'] = None
        if not self.jobParams.has_key('ec2_secret_key'):
            self.jobParams['ec2_secret_key'] = None

        logger.debug('calling authorize factory with extraParams %s'%self.extraParams) 
        self.authoriser = cvlsshutils.authorise.authorise.factory(copymethod=copymethod,parent=self.parentWindow,displayStrings=self.siteConfig.displayStrings,progressDialog=self.progressDialog,authorizedKeysFile=authorizedKeysFile,url=self.siteConfig.authURL,aaf_username=self.jobParams['aaf_username'],aaf_idp=self.jobParams['aaf_idp'],ec2_access_key=self.jobParams['ec2_access_key'],ec2_secret_key=self.jobParams['ec2_secret_key'],keydistObject=self,extraParams=self.extraParams,onFirstLogin=self.siteConfig.onFirstLogin)

        self.scanHostKeys()
        self.sshAgentProcess = None
        try:
            if not self._stopped.isSet():
                self.needAgent()
            if not self._stopped.isSet():
                key = self.keyModel.listKey()
            if key==None:
                if not self._stopped.isSet():
                    self.loadKey()
                if not self._stopped.isSet():
                    key = self.keyModel.listKey()
            if self.testAuth():
                if self.progressDialog!=None:
                    self.progressDialog.Hide()
                return
            else:
                if not self._stopped.isSet():
                    self.copyId()
                authn=False
                niter=0
                while not authn and niter<5:
                    authn=self.testAuth()
                    niter=niter+1
                    if niter>0:
                        import time
                        time.sleep(1)
                if (not self._stopped.isSet()) and authn:
                    self.progressDialog.Hide()
                    return 
                else:
                    self.cancelMessage="canceling because testAuth failed %s times after copyID Completed"%niter
                    self._exit.set()
                    self.progressDialog.Hide()
                    return
        except Exception as e:
            print e
            print traceback.format_exc()
            self._exit.set()
            if self.progressDialog!=None:
                self.progressDialog.Hide()
            return

    def cleanup(self):
        self._exit.wait()
        if self._exit.isSet():
            self._stopped.set()
            if self.removeKeyOnExit.isSet() and self.keyCreated.isSet():
                try:
                    self.authoriser.deleteRemoteKey(host=self.siteConfig.host,username=self.jobParams.username)
                except:
                    pass
                try:
                    self.keyModel.deleteKey()
                except:
                    pass
            if self.stopAgentOnExit.isSet():
                self.keyModel.stopAgent()

    def GetKeyPassphrase(self,queue,incorrect=False):
        if (incorrect):
            ppd = passphraseDialog(self.parentWindow,self.progressDialog,wx.ID_ANY,'Unlock Key',self.displayStrings.passphrasePromptIncorrect,"OK","Cancel")
        else:
            ppd = passphraseDialog(self.parentWindow,self.progressDialog,wx.ID_ANY,'Unlock Key',self.displayStrings.passphrasePrompt,"OK","Cancel")
        (canceled,passphrase) = ppd.getPassword()
        queue.put((canceled,passphrase))


    def getPassphrase(self,queue):
        createNewKeyDialog = CreateNewKeyDialog(self.parentWindow, self.progressDialog, wx.ID_ANY, self.parentWindow.programName, self.keyModel.getPrivateKeyFilePath(),self.displayStrings, displayMessageBoxReportingSuccess=False)
        try:
            wx.EndBusyCursor()
            stoppedBusyCursor = True
        except:
            stoppedBusyCursor = False
        canceled = createNewKeyDialog.ShowModal()==wx.ID_CANCEL
        if stoppedBusyCursor:
            wx.BeginBusyCursor()
        if (not canceled):
            logger.debug("User didn't cancel from CreateNewKeyDialog.")
            passphrase=createNewKeyDialog.getPassphrase()
            queue.put((canceled,passphrase))
        else:
            queue.put((canceled,None))

    def createKey(self):
        logger.debug('in createKey method')
        if not self._stopped.isSet():
            if self.keyModel.isTemporaryKey():
                logger.debug('generating a temporary key passphrase')
                import string
                import random
                oneTimePassphrase=''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(10))
                logger.debug("tempoary key oneTimePassphrase: " + oneTimePassphrase)
                self.password = oneTimePassphrase
                self.removeKeyOnExit.set()
            else:
                logger.debug('requesting a permenant key passphrase')
                queue=Queue.queue()
                wx.CallAfter(self.getPassphrase,queue=queue)
                (canceled,self.password)=queue.get()
                if canceled:
                    self._stopped.set()
                    self.cancelMessage="canceled while requesting a new ssh key passphrase"
                    self._exit.set()
            if not self._stopped.isSet():
                def success(): 
                    logger.debug('succesfully generated a new ssh key')
                    self.keyCreated.set()
                def failure(): 
                    logger.debug("failed to generate a new ssh key")
                    self.cancelMessage="Unable to generate a new key pair"
                    self._stopped.set()
                    self._exit.set()
                if not self._stopped.isSet():
                    logger.debug('generating a new ssh key')
                    self.keyModel.generateNewKey(self.password,success,failure,failure)
                
    def loadKey(self):
        km =self.keyModel
        self._loadKeySuccess = threading.Event()
        self._addKeyComplete = threading.Event()
        self._loadKeySuccess.clear()
        self._addKeyComplete.clear()
        if (self.password!=None):
            password=self.password
        else:
            password=""
        def incorrectCallback():
            queue=Queue.Queue()
            if self.password!=None:
                wx.CallAfter(self.GetKeyPassphrase,incorrect=True,queue=queue)
            else:
                wx.CallAfter(self.GetKeyPassphrase,incorrect=False,queue=queue)
            (canceled,self.password)=queue.get()
            if canceled:
                self._stopped.set()
                self.cancelMessage="cancled while requesting the existing ssh key passphrase"
                self._exit.set()
            self._addKeyComplete.set()
        def loadedCallback():
            self._loadKeySuccess.set()
        def failedToConnectToAgentCallback():
            self.cancelMessage="failed to connect to agent callback"
            self._exit.set()
            self._stopped.set()
        logger.debug("sshKeyDist.loadKeyThread.run: KeyModel information temporary: %s path: %s exists: %s"%(km.isTemporaryKey(),km.getPrivateKeyFilePath(),km.privateKeyExists()))
        if not os.path.exists(self.keyModel.sshPathsObject.sshKeyPath):
            if not self._stopped.isSet():
                self.createKey()
        while not self._loadKeySuccess.isSet() and not self._stopped.isSet() and not self._exit.isSet():
            logger.debug('attempting to add key to the ssh agent')
            if (self.password!=None):
                password=self.password
            else:
                password=""
            km.addKeyToAgent(password,loadedCallback,incorrectCallback,None,failedToConnectToAgentCallback)


    def testAuth(self):
        logger.debug('skd attempting to test authorisation')
        logger.debug('usernamed set to %s'%self.jobParams['username'])
        return self.authoriser.testAuth(keyModel=self.keyModel,username=self.jobParams['username'],host=self.jobParams['loginHost'],timeout=160)

    def ShowErrorDialog(self,msg,queue):
        import sys
        if sys.platform.startswith("darwin"):
            from MacMessageDialog import LauncherMessageDialog
        elif sys.platform.startswith("win"):
            from WindowsMessageDialog import LauncherMessageDialog
        elif sys.platform.startswith("linux"):
            from LinuxMessageDialog import LauncherMessageDialog
        dlg=LauncherMessageDialog(self.parentWindow,msg,self.parentWindow.programName,helpEmailAddress=self.siteConfig.displayStrings.helpEmailAddress)
        dlg.ShowModal()
        logger.dump_log(self.parentWindow,submit_log=True)
        queue.put(None)

    def copyId(self):
        logger.debug("copying the pub key")
        try:
            self.authoriser.copyID(self.keyModel)
        except Exception as e:
            logger.debug("copyID raised an exception %s"%e)
            import traceback
            logger.debug(traceback.format_exc())
            queue=Queue.Queue()
            msg="There was an error authorizing your access\nThe error reported was %s"%e
            wx.CallAfter(self.ShowErrorDialog,"%s"%e,queue=queue)
            queue.get()
        try:
            ud=self.authoriser.getUpdateDict()
            logger.debug('updating updateDict with %s'%ud)
            self.updateDict.update(ud)
            logger.debug('updating jobParams with %s'%ud)
            self.jobParams.update(ud)
        except Exception as e:
            import traceback
            logger.debug(traceback.format_exc())
        try:
            newusername=self.obj.getLocalUsername()
            logger.debug('updating updateDict with new username %s'%newusername)
            self.keydistObject.updateDict['username']=newusername
            logger.debug('updating jobParams with new username %s'%newusername)
            self.jobParams['username']=newusername
        except Exception as e:
            pass

    def needAgent(self):
        try:
            key=self.keyModel.listKey()
            logger.debug("KeyDist.startAgentThread keyModel.listKey returned without exception, we assume an agent is running")
        except Exception as e:
            # If we start the agent, we will stop the agent.
            logger.debug("KeyDist.startAgentThread keyModel.listKey returned an error. Presumably ssh-add was unable to contact the agent, starting an agent")
            self.stopAgentOnExit.set()
            try:
                self.keyModel.startAgent()
            except Exception as e:
                raise Exception("Unable to start the ssh agent: %s"%e)
                logger.debug(traceback.format_exc())

