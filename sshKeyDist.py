import os
import wx
import wx.lib.newevent
import re
from StringIO import StringIO
import logging
from threading import *
import threading
import time
import sys
from os.path import expanduser
import subprocess
import traceback
import socket
from utilityFunctions import HelpDialog
import pkgutil
import signal

from logger.Logger import logger
from PassphraseDialog import passphraseDialog


if not sys.platform.startswith('win'):
    import pexpect

class KeyDist():

    def complete(self):
        returnval = self._completed.isSet()
        return returnval


    class startAgentThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject
            self._stop = Event()

        def stop(self):
            self._stop.set()
        
        def stopped(self):
            return self._stop.isSet()


        def run(self):
            agentenv = None
            self.keydistObject.sshAgentProcess = None
            try:
                key=self.keydistObject.keyModel.listKey()
                logger.debug("KeyDist.startAgentThread keyModel.listKey returned without exception, we assume an agent is running")
            except Exception as e:
                # If we start the agent, we will stop the agent.
                logger.debug("KeyDist.startAgentThread keyModel.listKey returned an error. Presumably ssh-add was unable to contact the agent, starting an agent")
                self.keydistObject.stopAgentOnExit.set()
                logger.debug(traceback.format_exc())
                try:
                    self.keydistObject.keyModel.startAgent()
                except Exception as e:
                    self.keydistObject.cancel(message="I tried to start an ssh agent, but failed with the error message:\n\n%s" % str(e))
                    return

            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_GETPUBKEY,self.keydistObject)
            if (not self.stopped()):
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)

    class loadkeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject
            self._stop = Event()

        def stop(self):
            self._stop.set()
        
        def stopped(self):
            return self._stop.isSet()

        def run(self):
            logger.debug("loadkeyThread: started")
            try:
                logger.debug("loadkeyThread: Trying to open the key file")
                with open(self.keydistObject.keyModel.sshpaths.sshKeyPath,'r'): pass
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LOADKEY,self.keydistObject)
            except Exception as e:
                logger.error("loadkeyThread: Failed to open the key file %s" % str(e))
                self.keydistObject.cancel("Failed to open the key file %s" % str(e))
                return
            if (not self.stopped()):
                logger.debug("loadkeyThread: generating LOADKEY event from loadkeyThread")
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),event)

    class genkeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject
            self._stop = Event()

        def stop(self):
            self._stop.set()
        
        def stopped(self):
            return self._stop.isSet()

        def run(self):
            logger.debug("genkeyThread: started")
            self.nextEvent=None
            def success(): 
                self.nextEvent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LOADKEY,self.keydistObject)
            def failure(): 
                self.keydistObject.cancel("Unable to generate a new key pair")
            self.keydistObject.keyModel.generateNewKey(self.keydistObject.password,success,failure,failure)
            self.keydistObject.keyCreated.set()
            if (not self.stopped() and self.nextEvent != None):
                logger.debug("genkeyThread: generating LOADKEY event from genkeyThread")
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),self.nextEvent)

    class getPubKeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject
            self._stop = Event()

        def stop(self):
            self._stop.set()
        
        def stopped(self):
            return self._stop.isSet()

        def run(self):
            threadid = threading.currentThread().ident
            logger.debug("getPubKeyThread %i: started"%threadid)
            try:
                key = self.keydistObject.keyModel.listKey()
                if (key!=None):
                    self.keydistObject.keyloaded.set()
                    logger.debug("getPubKeyThread %i: key loaded"%threadid)
                    logger.debug("getPubKeyThread %i: found a key, creating TESTAUTH event"%threadid)
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_TESTAUTH,self.keydistObject)
                else:
                    logger.debug("getPubKeyThread %i: did not find a key, creating LOADKEY event"%threadid)
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LOADKEY,self.keydistObject)
            except:
                logger.debug("getPubKeyThread %i: Unable to contact agent"%threadid)
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEEDAGENT,self.keydistObject)

            if (not self.stopped()):
                logger.debug("getPubKeyThread %i: is posting the next event"%threadid)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
            logger.debug("getPubKeyThread %i: stopped"%threadid)

    class scanHostKeysThread(Thread):
        def __init__(self,keydistObject):
            import shlex
            Thread.__init__(self)
            self.keydistObject = keydistObject
            cmdlist=shlex.split('{sshkeygen} -F {host} -f {known_hosts_file}')
            self.ssh_keygen_cmd=[]
            for s in cmdlist:
                self.ssh_keygen_cmd.append(s.format(sshkeygen=self.keydistObject.keyModel.sshpaths.sshKeyGenBinary,host=self.keydistObject.host,known_hosts_file=self.keydistObject.keyModel.sshpaths.sshKnownHosts))
            self.ssh_keyscan_cmd=[]
            for s in shlex.split('{sshscan} -H {host}'):
                self.ssh_keyscan_cmd.append(s.format(sshscan=self.keydistObject.keyModel.sshpaths.sshKeyScanBinary,host=self.keydistObject.host))
            self._stop = Event()

        def stop(self):
            self._stop.set()
        
        def stopped(self):
            return self._stop.isSet()

        def getKnownHostKeys(self):
	    if sys.platform.startswith("win"):
                keygen = subprocess.Popen(" ".join(self.ssh_keygen_cmd),stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True,universal_newlines=True,startupinfo=self.keydistObject.startupinfo,creationflags=self.keydistObject.creationflags)
	    else:
                keygen = subprocess.Popen(self.ssh_keygen_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,universal_newlines=True,startupinfo=self.keydistObject.startupinfo,creationflags=self.keydistObject.creationflags)
            stdout,stderr = keygen.communicate()
            keygen.wait()
            hostkeys=[]
            for line in stdout.split('\n'):
                if (not (line.find('#')==0 or line == '')):
                    hostkeys.append(line)
            return hostkeys
                    
        def appendKey(self,key):
            with open(self.keydistObject.keyModel.sshpaths.sshKnownHosts,'a+') as known_hosts:
                known_hosts.write(key)
                known_hosts.write('\n')
            

        def scanHost(self):
	    if sys.platform.startswith("win"):
                scan = subprocess.Popen(" ".join(self.ssh_keyscan_cmd),stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True,universal_newlines=True,startupinfo=self.keydistObject.startupinfo,creationflags=self.keydistObject.creationflags)
            else:
                scan = subprocess.Popen(self.ssh_keyscan_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,universal_newlines=True,startupinfo=self.keydistObject.startupinfo,creationflags=self.keydistObject.creationflags)
            stdout,stderr = scan.communicate()
            scan.wait()
            hostkeys=[]
            for line in stdout.split('\n'):
                if (not (line.find('#')==0 or line == '')):
                    hostkeys.append(line)
            return hostkeys

        def run(self):
            knownKeys = self.getKnownHostKeys()
            if (len(knownKeys)==0):
                hostKeys = self.scanHost()
                for key in hostKeys:
                    self.appendKey(key)
            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEEDAGENT,self.keydistObject)
            if (not self.stopped()):
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
                        
            

    class testAuthThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject
            self._stop = Event()

        def stop(self):
            self._stop.set()
        
        def stopped(self):
            return self._stop.isSet()

        def run(self):
        
            # I have a problem where I have multiple identity files in my ~/.ssh, and I want to use only identities loaded into the agent
            # since openssh does not seem to have an option to use only an agent we have a workaround, 
            # by passing the -o IdentityFile option a path that does not exist, openssh can't use any other identities, and can only use the agent.
            # This is a little "racy" in that a tempfile with the same path could conceivably be created between the unlink and openssh attempting to use it
            # but since the pub key is extracted from the agent not the identity file I can't see anyway an attacker could use this to trick a user into uploading the attackers key.
            threadid = threading.currentThread().ident
            logger.debug("testAuthThread %i: started"%threadid)
            try:
                if (self.keydistObject.authorise.testAuth(keyModel=self.keydistObject.keyModel,username=self.keydistObject.username,host=self.keydistObject.host,timeout=160)):
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHSUCCESS,self.keydistObject)
                else:
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHFAIL,self.keydistObject)
            except Exception as e:
                import traceback
                logger.debug("testAuth failed with exception %s"%e)
                logger.debug(traceback.format_exc())
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHFAIL,self.keydistObject)


            if (not self.stopped()):
                logger.debug("testAuthThread %i: self.stopped() == False, so posting event: "%threadid + str(newevent))
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
            logger.debug("testAuthThread %i: stopped"%threadid)


    class loadKeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject
            self._stop = Event()

        def stop(self):
            self._stop.set()
        
        def stopped(self):
            return self._stop.isSet()

        def run(self):

            self.nextEvent=None
            threadid=threading.currentThread().ident
            threadname=threading.currentThread().name
            km =self.keydistObject.keyModel
            if (self.keydistObject.password!=None):
                password=self.keydistObject.password
                newevent1 = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_WRONGPASS, self.keydistObject)
            else:
                newevent1 = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED, self.keydistObject)
                password=""
            def incorrectCallback():
                self.nextEvent = newevent1
            def loadedCallback():
                self.nextEvent =KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_GETPUBKEY, self.keydistObject)
            def notFoundCallback():
                self.nextEvent=KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEWPASS_REQ,self.keydistObject)
            def failedToConnectToAgentCallback():
                self.nextEvent=KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEEDAGENT,self.keydistObject)
            logger.debug("sshKeyDist.loadKeyThread.run: KeyModel information temporary: %s path: %s exists: %s"%(km.isTemporaryKey(),km.getPrivateKeyFilePath(),km.privateKeyExists()))
            km.addKeyToAgent(password,loadedCallback,incorrectCallback,notFoundCallback,failedToConnectToAgentCallback)
            if (not self.stopped() and self.nextEvent != None):
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),self.nextEvent)


    class CopyIDThread(Thread):
        def __init__(self,keydist,obj):
            Thread.__init__(self)
            self.keydistObject = keydist
            self.obj=obj
            self._stop = Event()

        def stop(self):
            self._stop.set()
        
        def stopped(self):
            return self._stop.isSet()

        def run(self):
            try:
                pubkey=self.keydistObject.keyModel.getPubKey()
                try:
                    self.keydistObject.authorise.copyID(keyModel=self.keydistObject.keyModel)
                except Exception as e:
                    logger.debug('CopyIDThread, copyID failed with exception: '+str(e))
                    import traceback
                    logger.debug(traceback.format_exc())
                    raise e
                logger.debug("KeyDist.CopyIDThread: copyID returned without error")
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_TESTAUTH,self.keydistObject)
                # The authentication process may pass back parameters (such as the IdP and user@IdP that we wish to save and prepopulate for the user next time
                try:
                    ud=self.obj.getUpdateDict()
                    self.keydistObject.updateDict.update(ud)
                except Exception as e:
                    pass
                # This try catch means that if, in the course of authenticing the user, the authentication mechanism was able to tell us the username
                # That username will be updated. Example. Authenticing via AAF, I know I'm at Monash, and my Monash username is chines.
                # Monash will tell CVL what my email address is. CVL can look up my CVL username based on my email address.
                try:
                    newusername=self.obj.getLocalUsername()
                    self.keydistObject.updateDict['username']=newusername
                except Exception as e:
                    pass
            except Exception as e:
                logger.debug('CopyIDThread: threw exception : ' + str(e))
                self.keydistObject.cancel(message=str(e))
                return
            if (not self.stopped()):
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(), event)
            self.keydistObject.keycopied.set()
            self.keydistObject.__dict__.update(self.keydistObject.updateDict)


    class sshKeyDistEvent(wx.PyCommandEvent):
        def __init__(self,id,keydist,arg=None):
            wx.PyCommandEvent.__init__(self,KeyDist.myEVT_CUSTOM_SSHKEYDIST,id)
            self.keydist = keydist
            self.arg = arg
            self.threadid = threading.currentThread().ident
            self.threadname = threading.currentThread().name

        def newkey(event):
            usingOneTimePassphrase = False
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEWPASS_REQ):
                logger.debug("received NEWPASS_REQ event")
                if event.keydist.keyModel.isTemporaryKey():
                    usingOneTimePassphrase = True
                    import string
                    import random
                    oneTimePassphrase=''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(10))
                    logger.debug("sshKeyDistEvent.newkey: oneTimePassphrase: " + oneTimePassphrase)
                    event.keydist.password = oneTimePassphrase
                else:
                    wx.CallAfter(event.keydist.getPassphrase,event.arg)
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEWPASS_COMPLETE or usingOneTimePassphrase):
                if event.GetId() == KeyDist.EVT_KEYDIST_NEWPASS_COMPLETE:
                    logger.debug("received NEWPASS_COMPLETE event")
                if usingOneTimePassphrase:
                    logger.debug("Using one-time passphrase.")
                t = KeyDist.genkeyThread(event.keydist)
                t.setDaemon(True)
                t.start()
                event.keydist.threads.append(t)
            event.Skip()

        def copyid(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_COPYID):
                pubKeyPath=event.keydist.keyModel.getPrivateKeyFilePath()+".pub"
                with open(pubKeyPath,'r') as f:
                    pubkey=f.read()
                logger.debug("received COPYID event")
                t = KeyDist.CopyIDThread(event.keydist,obj=event.keydist.authorise)
                t.setDaemon(True)
                t.start()
                event.keydist.threads.append(t)
            else:
                event.Skip()

        def scanhostkeys(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_SCANHOSTKEYS):
                logger.debug("received SCANHOSTKEYS event")
                t = KeyDist.scanHostKeysThread(event.keydist)
                t.setDaemon(True)
                t.start()
                event.keydist.threads.append(t)
            event.Skip()



        def shutdownEvent(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_SHUTDOWN):
                logger.debug("received EVT_KEYDIST_SHUTDOWN event")
                nextevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_COMPLETE,event.keydist)
                try:
                    nextevent.arg=event.arg
                except:
                    pass
                event.keydist.shutdownThread=threading.Thread(target=event.keydist.shutdownReal,args=[nextevent])
                event.keydist.shutdownThread.start()
            else:
                event.Skip()

        def completeEvent(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_COMPLETE):
                if (event.keydist.canceled()):
                    if (event.keydist.callback_fail != None):
                        logger.debug("sshKeyDist.completeEvent: calling-back to indicate completion")
                        if event.arg!=None:
                            event.keydist.callback_fail(event.arg)
                        else:
                            event.keydist.callback_fail()

                event.keydist._completed.set()

        def success(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_AUTHSUCCESS):
                logger.debug("received AUTHSUCCESS event")
                event.keydist._completed.set()
                if (event.keydist.callback_success != None):
                    event.keydist.callback_success()
            event.Skip()


        def needagent(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEEDAGENT and not event.keydist.canceled()):
                logger.debug("received NEEDAGENT event")
                t = KeyDist.startAgentThread(event.keydist)
                t.setDaemon(True)
                t.start()
                event.keydist.threads.append(t)
            else:
                event.Skip()

        def listpubkeys(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_GETPUBKEY and not event.keydist.canceled()):
                t = KeyDist.getPubKeyThread(event.keydist)
                t.setDaemon(True)
                t.start()
                logger.debug("received GETPUBKEY event from thread %i %s, starting thread %i %s in response"%(event.threadid,event.threadname,t.ident,t.name))
                event.keydist.threads.append(t)
            else:
                event.Skip()

        def testauth(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_TESTAUTH):
                t = KeyDist.testAuthThread(event.keydist)
                t.setDaemon(True)
                t.start()
                logger.debug("received TESTAUTH event from thread %i %s, starting thread %i %s in response"%(event.threadid,event.threadname,t.ident,t.name))
                event.keydist.threads.append(t)
            else:
                event.Skip()

        def networkError(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_NETWORK_ERROR):
                event.keydist.cancel(message='Network error, could not contact login host.')
                return
            else:
                event.Skip()
            
        def keylocked(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_KEY_LOCKED):
                logger.debug("received KEY_LOCKED event")
                wx.CallAfter(event.keydist.GetKeyPassphrase)
            if (event.GetId() == KeyDist.EVT_KEYDIST_KEY_WRONGPASS):
                logger.debug("received KEY_WRONGPASS event")
                wx.CallAfter(event.keydist.GetKeyPassphrase,incorrect=True)
            event.Skip()

        def loadkey(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_LOADKEY and not event.keydist.canceled()):
                t = KeyDist.loadKeyThread(event.keydist)
                t.setDaemon(True)
                t.start()
                logger.debug("received LOADKEY event from thread %i %s, starting thread %i %s in response"%(event.threadid,event.threadname,t.ident,t.name))
                event.keydist.threads.append(t)
            else:
                event.Skip()

        def authfail(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_AUTHFAIL and not event.keydist.canceled()):
                if(not event.keydist.keyloaded.isSet()):
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LOADKEY,event.keydist)
                    wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
                else:
                    # If the key is loaded into the ssh agent, then authentication failed because the public key isn't on the server.
                    # *****TODO*****
                    # Actually this might not be strictly true. GNOME Keychain (and possibly others) will report a key loaded even if its still locked
                    # we probably need a button that says "I can't remember my old key's passphrase, please generate a new keypair"
                    if (event.keydist.keycopied.isSet()):
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_TESTAUTH,event.keydist)
                        logger.debug("received AUTHFAIL event from thread %i %s posting TESTAUTH event in response"%(event.threadid,event.threadname))
                        wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
                    else:
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_COPYID,event.keydist)
                        logger.debug("received AUTHFAIL event from thread %i %s posting COPYID event in response"%(event.threadid,event.threadname))
                        wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
            else:
                event.Skip()


        def startevent(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_START):
                logger.debug("received KEYDIST_START event")
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_SCANHOSTKEYS,event.keydist)
                wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
            else:
                event.Skip()

    myEVT_CUSTOM_SSHKEYDIST=None
    EVT_CUSTOM_SSHKEYDIST=None
    def __init__(self,parentWindow,progressDialog,notifywindow,keyModel,displayStrings=None,startupinfo=None,creationflags=0,username=None,host=None,authURL=None,aaf_idp=None,aaf_username=None,ec2_access_key=None,ec2_secret_key=None,authorizedKeysFile=None,copymethod='passwordAuth',extraParams=None,*args,**kwargs):

        logger.debug("KeyDist.__init__")

        KeyDist.myEVT_CUSTOM_SSHKEYDIST=wx.NewEventType()
        KeyDist.EVT_CUSTOM_SSHKEYDIST=wx.PyEventBinder(self.myEVT_CUSTOM_SSHKEYDIST,1)
        KeyDist.EVT_KEYDIST_START = wx.NewId()
        KeyDist.EVT_KEYDIST_SHUTDOWN = wx.NewId()
        KeyDist.EVT_KEYDIST_SUCCESS = wx.NewId()
        KeyDist.EVT_KEYDIST_NEEDAGENT = wx.NewId()
        KeyDist.EVT_KEYDIST_NEEDKEYS = wx.NewId()
        KeyDist.EVT_KEYDIST_GETPUBKEY = wx.NewId()
        KeyDist.EVT_KEYDIST_TESTAUTH = wx.NewId()
        KeyDist.EVT_KEYDIST_AUTHSUCCESS = wx.NewId()
        KeyDist.EVT_KEYDIST_AUTHFAIL = wx.NewId()
        KeyDist.EVT_KEYDIST_NEWPASS_REQ = wx.NewId()
        KeyDist.EVT_KEYDIST_NEWPASS_RPT = wx.NewId()
        KeyDist.EVT_KEYDIST_NEWPASS_COMPLETE = wx.NewId()
        KeyDist.EVT_KEYDIST_COPYID = wx.NewId()
        KeyDist.EVT_KEYDIST_KEY_LOCKED = wx.NewId()
        KeyDist.EVT_KEYDIST_KEY_WRONGPASS = wx.NewId()
        KeyDist.EVT_KEYDIST_SCANHOSTKEYS = wx.NewId()
        KeyDist.EVT_KEYDIST_LOADKEY = wx.NewId()
        KeyDist.EVT_KEYDIST_NETWORK_ERROR = wx.NewId()
        KeyDist.EVT_KEYDIST_COMPLETE = wx.NewId()

        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.success)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.needagent)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.listpubkeys)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.testauth)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.authfail)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.startevent)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.newkey)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.copyid)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.keylocked)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.scanhostkeys)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.loadkey)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.networkError)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.completeEvent)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.shutdownEvent)

        self.updateDict={}
        self._completed=Event()
        self.parentWindow = parentWindow
        self.progressDialog = progressDialog
        self.username = username
        self.host = host
        self.displayStrings=displayStrings
        self.notifywindow = notifywindow
        self.sshKeyPath = ""
        self.threads=[]
        self.pubkeyfp = None
        self.keyloaded=Event()
        self.password = None
        self.pubkeylock = Lock()
        self.keycopied=Event()
        self.callback_success=None
        self.callback_fail=None
        self.callback_error = None
        self._canceled=Event()
        self.keyModel = keyModel
        self.removeKeyOnExit=Event()
        self.keyCreated=Event()
        if self.keyModel.isTemporaryKey():
            self.removeKeyOnExit.set()
        self.stopAgentOnExit=Event()
        self.startupinfo = startupinfo
        self.creationflags = creationflags
        self.shuttingDown=Event()
        self.extraParams=extraParams


        import cvlsshutils.authorise
        self.authorise=cvlsshutils.authorise.authorise.factory(copymethod=copymethod,parent=self.parentWindow,displayStrings=self.displayStrings,progressDialog=self.progressDialog,authorizedKeysFile=authorizedKeysFile,url=authURL,aaf_username=aaf_username,aaf_idp=aaf_idp,ec2_access_key=ec2_access_key,ec2_secret_key=ec2_secret_key,keydistObject=self,extraParams=self.extraParams)




    def GetKeyPassphrase(self,incorrect=False):
        if (incorrect):
            ppd = passphraseDialog(self.parentWindow,self.progressDialog,wx.ID_ANY,'Unlock Key',self.displayStrings.passphrasePromptIncorrect,"OK","Cancel")
        else:
            ppd = passphraseDialog(self.parentWindow,self.progressDialog,wx.ID_ANY,'Unlock Key',self.displayStrings.passphrasePrompt,"OK","Cancel")
        (canceled,passphrase) = ppd.getPassword()
        if (canceled):
            self.cancel("Sorry, I can't continue without the passphrase for that key. If you've forgotten the passphrase, you could remove the key and generate a new one. The key is probably located in\n\n" + self.keyModel.getPrivateKeyFilePath() + "*")
            return
        else:
            self.password = passphrase
            event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LOADKEY,self)
            wx.PostEvent(self.notifywindow.GetEventHandler(),event)


    def getLoginPassword(self,incorrect=False):
        if (not incorrect):
            ppd = passphraseDialog(self.parentWindow,self.progressDialog,wx.ID_ANY,'Login Password',self.displayStrings.passwdPrompt.format(**self.__dict__),"OK","Cancel")
        else:
            ppd = passphraseDialog(self.parentWindow,self.progressDialog,wx.ID_ANY,'Login Password',self.displayStrings.passwdPromptIncorrect.format(**self.__dict__),"OK","Cancel")
        (canceled,password) = ppd.getPassword()
        if canceled:
            self.cancel()
            return
        self.password = password
        event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_COPYID,self)
        wx.PostEvent(self.notifywindow.GetEventHandler(),event)

    def getPassphrase(self,reason=None):
        from CreateNewKeyDialog import CreateNewKeyDialog
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
            self.password=createNewKeyDialog.getPassphrase()
            event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEWPASS_COMPLETE,self)
            wx.PostEvent(self.notifywindow.GetEventHandler(),event)
        else:
            logger.debug("KeyDist.getPassphrase: User canceled from CreateNewKeyDialog.")
            self.cancel()

    def distributeKey(self,callback_success=None, callback_fail=None):
        self.callback_fail      = callback_fail
        self.callback_success   = callback_success
        logger.debug("KeyDist.distributeKey: posting EVT_KEYDIST_START")
        event = KeyDist.sshKeyDistEvent(self.EVT_KEYDIST_START, self)
        wx.PostEvent(self.notifywindow.GetEventHandler(), event)
        
    def canceled(self):
        return self._canceled.isSet()

    def cancel(self,message=""):
        if (not self.canceled()):
            self._canceled.set()
            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_SHUTDOWN, self)
            newevent.arg = message
            logger.debug('sshKeyDist.cancel: setting canceled, sending EVT_KEYDIST_SHUTDOWN event.')
            wx.PostEvent(self.notifywindow.GetEventHandler(), newevent)

    def deleteRemoveShutdown(self):
        if self.removeKeyOnExit.isSet():
            logger.debug("sshKeyDist.deleteRemoveShutdown: self.removeKeyOnExit.isSet() is True.")
            if self.keyCreated.isSet():
                logger.debug("sshKeyDist.deleteRemoveShutdown: self.keyCreated.isSet() is True.")
                logger.debug("sshKeyDist.deleteRemoveShutdown: deleting remote key.")
                try:
                    self.authorise.deleteRemoteKey(host=self.host,username=self.username)
                except:
                    pass
                logger.debug("sshKeyDist.deleteRemoveShutdown: deleting temporary key and removing key from agent.")
                try:
                    self.keyModel.deleteKey()
                except:
                    pass
                #logger.debug("sshKeyDist.deleteRemoveShutdown: removing key from agent.")
                #self.keyModel.removeKeyFromAgent()
            else:
                logger.debug("sshKeyDist.deleteRemoveShutdown: self.keyCreated.isSet() is False.")
        else:
            logger.debug("sshKeyDist.deleteRemoveShutdown: self.removeKeyOnExit.isSet() is False.")
        if self.stopAgentOnExit.isSet():
            logger.debug("sshKeyDist.deleteRemoveShutdown: self.stopAgentOnExit.isSet() is True.")
            self.keyModel.stopAgent()
        else:
            logger.debug("sshKeyDist.deleteRemoveShutdown: self.stopAgentOnExit.isSet() is False.")

    def shutdownReal(self,nextevent=None):

        if self.shuttingDown.isSet():
            return
        self.shuttingDown.set()

        logger.debug("sshKeyDist.shutdownReal: calling stop and join on all threads")
        for t in self.threads:
            try:
                t.stop()
                t.join()
            except:
                pass
        self.deleteRemoveShutdown()
        #t=threading.Thread(target=self.deleteRemoveShutdown)
        #t.start()
        #t.join()
        if nextevent!=None:
            wx.PostEvent(self.notifywindow.GetEventHandler(), nextevent)

    def shutdown(self):
        if (not self.canceled()):
            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_SHUTDOWN, self)
            logger.debug('Sending EVT_KEYDIST_SHUTDOWN event.')
            wx.PostEvent(self.notifywindow.GetEventHandler(), newevent)

