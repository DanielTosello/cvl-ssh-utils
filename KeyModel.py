# KeyModel.py

import sys
import os
import subprocess
import tempfile
import traceback
import threading
import re
if sys.platform.startswith('win'):
    from _winreg import *
    import win32gui, win32con
import signal

if os.path.abspath("..") not in sys.path:
    sys.path.append(os.path.abspath(".."))

from logger.Logger import logger

from os.path import expanduser
class sshpaths():
    OPENSSH_BUILD_DIR = 'openssh-cygwin-stdin-build'
    def double_quote(self,x):
        return '"' + x + '"'
    def ssh_binaries(self,temporaryKey=False):
        """
        Locate the ssh binaries on various systems. On Windows we bundle a
        stripped-down OpenSSH build that uses Cygwin.
        """

        if sys.platform.startswith('win'):
            # Assume that our InnoSetup script will set appropriate permissions on the "tmp" directory.

            if hasattr(sys, 'frozen'):
                f = lambda x: os.path.join(os.path.dirname(sys.executable), self.OPENSSH_BUILD_DIR, 'bin', x)
            else:
                try:
                    launcherModulePath = os.path.dirname(pkgutil.get_loader("launcher").filename)
                except:
                    launcherModulePath = os.getcwd()
                f = lambda x: os.path.join(launcherModulePath, self.OPENSSH_BUILD_DIR, 'bin', x)

            sshBinary        = self.double_quote(f('ssh.exe'))
            sftpBinary        = self.double_quote(f('sftp.exe'))
            sshKeyGenBinary  = self.double_quote(f('ssh-keygen.exe'))
            sshKeyScanBinary = self.double_quote(f('ssh-keyscan.exe'))
            if temporaryKey:
                sshAgentBinary   = self.double_quote(f('ssh-agent.exe'))
                #sshAgentBinary   = self.double_quote(f('charade.exe'))
            else:
                #sshAgentBinary   = self.double_quote(f('ssh-agent.exe'))
                sshAgentBinary   = self.double_quote(f('charade.exe'))
            sshAddBinary     = self.double_quote(f('ssh-add.exe'))
            chownBinary      = self.double_quote(f('chown.exe'))
            chmodBinary      = self.double_quote(f('chmod.exe'))
        elif sys.platform.startswith('darwin'):
            sshBinary        = '/usr/bin/ssh'
            sftpBinary        = '/usr/bin/sftp'
            sshKeyGenBinary  = '/usr/bin/ssh-keygen'
            sshKeyScanBinary = '/usr/bin/ssh-keyscan'
            sshAgentBinary   = '/usr/bin/ssh-agent'
            sshAddBinary     = '/usr/bin/ssh-add'
            chownBinary      = '/usr/sbin/chown'
            chmodBinary      = '/bin/chmod'
        else:
            sshBinary        = '/usr/bin/ssh'
            sftpBinary        = '/usr/bin/sftp'
            sshKeyGenBinary  = '/usr/bin/ssh-keygen'
            sshKeyScanBinary = '/usr/bin/ssh-keyscan'
            sshAgentBinary   = '/usr/bin/ssh-agent'
            sshAddBinary     = '/usr/bin/ssh-add'
            chownBinary      = '/bin/chown'
            chmodBinary      = '/bin/chmod'
 
        return (sshBinary, sshKeyGenBinary, sshAgentBinary, sshAddBinary, sshKeyScanBinary, chownBinary, chmodBinary,sftpBinary,)
    
    def ssh_files(self):
        known_hosts_file = os.path.join(expanduser('~'), '.ssh', 'known_hosts')
        sshKeyPath = os.path.join(expanduser('~'), '.ssh', self.keyFileName)

        return (sshKeyPath,known_hosts_file,)

    def __init__(self, keyFileName, massiveLauncherConfig=None, massiveLauncherPreferencesFilePath=None, temporaryKey=False):
        (sshBinary, sshKeyGenBinary, sshAgentBinary, sshAddBinary, sshKeyScanBinary,chownBinary, chmodBinary,sftpBinary,) = self.ssh_binaries(temporaryKey)
        self.keyFileName                = keyFileName
        self.massiveLauncherConfig      = massiveLauncherConfig
        self.massiveLauncherPreferencesFilePath = massiveLauncherPreferencesFilePath
        (sshKeyPath,sshKnownHosts,)     = self.ssh_files()
        self.sshBinary                  = sshBinary
        self.sshKeyGenBinary            = sshKeyGenBinary
        self.sshAgentBinary             = sshAgentBinary
        self.sshAddBinary               = sshAddBinary
        self.sshKeyScanBinary           = sshKeyScanBinary
        self.chownBinary                = chownBinary
        self.chmodBinary                = chmodBinary

        self.sshKeyPath                 = sshKeyPath
        self.sshKnownHosts              = sshKnownHosts
        self.sftpBinary                 = sftpBinary


class KeyModel():

    def __init__(self,temporaryKey=False,startupinfo=None,creationflags=0,launcherKeyName="MassiveLauncherKey"):
        self.temporaryKey=temporaryKey
        if self.temporaryKey:
            sshKey=tempfile.NamedTemporaryFile(prefix=launcherKeyName+"_",delete=True)
            sshKeyName=sshKey.name
            sshKey.close()
        else:
            sshKeyName=launcherKeyName
        self.sshpaths = sshpaths(sshKeyName,temporaryKey=temporaryKey)
        self.sshPathsObject = self.sshpaths
        self.temporaryKey=temporaryKey
        self.keyComment = "Massive Launcher Key"
        if self.temporaryKey:
            self.keyComment+=" temporary key"
        self.startedPageant=threading.Event()
        self.startedAgent=threading.Event()
        self.pageant=None
        if sys.platform.startswith("win"):
            if 'HOME' not in os.environ:
                os.environ['HOME'] = os.path.expanduser('~')
        self.pubKey=None
        self.pubKeyFingerprint=None
        self.addedKey=[]
        self.copiedID=threading.Event()
        self.startupinfo=startupinfo
        self.creationflags=creationflags
        self.stopAgentOnExit=threading.Event()
        self.agentRunning=threading.Event()
#        self._useAAF=False
#
#    def useAAF(self,value=None,url=None):
#        if value!=None:
#            self._useAAF=value
#            self._authURL=url
#        return self._useAAF
#
       
    def getPubKey(self):
        pubKeyPath=self.getPrivateKeyFilePath()+".pub"
        with open(pubKeyPath,'r') as f:
            pubkey=f.read()
            return pubkey
        return None

    def getFingerprint(self):
        try:
            self.listKey()
        except: # exception occurs because we are unable to contact the agent
            self.startAgent()
            self.listKey()
        line=self.fingerprintAgent()
        if line!=None:
            return line.split(" ")[1]
        else:
            return None


    def getFingerprintAndKeyTypeFromPrivateKeyFile(self):
        logger.debug("KeyModel.getFingerprintAndKeyTypeFromPrivateKeyFile")
        proc = subprocess.Popen([self.sshPathsObject.sshKeyGenBinary.strip('"'),"-yl","-f",self.getPrivateKeyFilePath()], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,startupinfo=self.startupinfo,creationflags=self.creationflags)
        stdout,stderr = proc.communicate()

        publicKeyFingerprint = None
        keyType = None 
        if stdout!= None:
            sshKeyGenOutComponents = stdout.split(" ")
            if len(sshKeyGenOutComponents)>1:
                publicKeyFingerprint = sshKeyGenOutComponents[1]
            if len(sshKeyGenOutComponents)>3:
                keyType = sshKeyGenOutComponents[-1].strip().strip("(").strip(")")

        self.pubKeyFingerprint = publicKeyFingerprint
 
        return (publicKeyFingerprint,keyType)

    OPENSSH_BUILD_DIR = 'openssh-cygwin-stdin-build'

    def is_pageant_running(self):
        username = os.path.split(os.path.expanduser('~'))[-1]
        return 'PAGEANT.EXE' in os.popen('tasklist /FI "USERNAME eq %s"' % username).read().upper()

    def start_pageant(self):
        if self.is_pageant_running():
            # Pageant pops up a dialog box if we try to run a second
            # instance, so leave immediately.
            return

        if hasattr(sys, 'frozen'):
            pageant = os.path.join(os.path.dirname(sys.executable), self.OPENSSH_BUILD_DIR, 'bin', 'PAGEANT.EXE')
        else:
            try:
                launcherModulePath = os.path.dirname(pkgutil.get_loader("launcher").filename)
            except:
                launcherModulePath = os.getcwd()
            pageant = os.path.join(launcherModulePath, self.OPENSSH_BUILD_DIR, 'bin', 'PAGEANT.EXE')

        import win32process
        self.pageant = subprocess.Popen([pageant], stdin=None, stdout=None, stderr=None, close_fds=True, startupinfo=self.startupinfo, creationflags=self.creationflags|win32process.DETACHED_PROCESS)
        self.startedPageant.set()



    def stopAgent(self):
        if not self.stopAgentOnExit.isSet():
            return
        logger.debug("KeyModel.stopAgent: stopping the agent")

        logger.debug("KeyModel.stopAgent: On Windows, we will stop charade.exe or ssh-agent.exe (whichever one is running),")
        logger.debug("KeyModel.stopAgent: but we won't stop Pageant, because Pageant is what allows the user to run the")
        logger.debug("KeyModel.stopAgent: Launcher again without having to re-enter their passphrase.")

        # The code below was presumably added so that when a new Launcher version is installed, 
        # we can avoid the warning from the Setup Wizard that a Pageant process will need to be terminated
        # and then restarted after the new version is installed.  But this mechanism of allowing the Setup
        # Wizard to terminate and restart Pageant seems to work fine in my experience - JW.
        # This is not the case for the OpenSSH / Cygwin binaries and DLLs - we definitely don't want any
        # of them to be running when we try to install a new Launcher version with the Windows Setup Wizard.

        #if self.pageant!=None:
            #pageantPid=self.pageant.pid
            #self.pageant.kill()
            #self.pageant=None
        # Do no use self.sshAgentProcess.kill() the sshAgentProcess forks the real agent and exits so the kill won't get the real process
        if self.sshAgentProcess!=None:
            try:
                os.kill(int(self.agentPid),signal.SIGTERM)
            except:
                logger.debug(traceback.format_exc())
            if 'PREVIOUS_SSH_AUTH_SOCK' in os.environ:
                os.environ['SSH_AUTH_SOCK'] = os.environ['PREVIOUS_SSH_AUTH_SOCK']
                del os.environ['PREVIOUS_SSH_AUTH_SOCK']
            else:
                del os.environ['SSH_AUTH_SOCK']
            self.sshAgentProcess=None
            if sys.platform.startswith('win'):
                if 'PREVIOUS_SSH_AUTH_SOCK_REGISTRY' in os.environ:
		    agentenv = os.environ['PREVIOUS_SSH_AUTH_SOCK_REGISTRY']
	        else:
		    agentenv = ""
                try:
                    path = 'Environment'
                    reg = ConnectRegistry(None, HKEY_CURRENT_USER)
                    key = OpenKey(reg, path, 0, KEY_ALL_ACCESS)
		    try:
			if agentenv!="":
		            SetValueEx(key,'SSH_AUTH_SOCK',0,REG_SZ,agentenv)
		        else:
			    DeleteValueEx(key,'SSH_AUTH_SOCK')
		    except Exception as e:
                        logger.debug("couldn't set the SSH_AUTH_SOCK registry entry")
		    CloseKey(key)
		    win32gui.SendMessage(win32con.HWND_BROADCAST,win32con.WM_SETTINGCHANGE,0,'Environment')
                except Exception as e:
                    logger.debug("Couldn't open the windows registry to set the SSH_AUTH_SOCK")


    def startAgent(self):

        if self.agentRunning.isSet():
            return
        if self.agentIsRunning():
            self.agentRunning.set()
            return

        self.stopAgentOnExit.set()

        if self.startedAgent.isSet() and 'SSH_AGENT_PID' in os.environ and pidIsRunning(os.environ['SSH_AGENT_PID']):
            logger.debug("KeyModel.startAgent: Bailing out, because agent is already running.")
            return
        logger.debug("KeyModel.startAgent: Didn't find existing SSH_AGENT_PID process.")

        if sys.platform.startswith('win') and not self.isTemporaryKey():
            self.start_pageant()

        # startupinfo and creationflags are used to avoid flickering Command Prompt windows on Windows OS,
        # however charade.exe doesn't seem to work reliably with these startupinfo and creationflags values.
        startupinfo = None
        creationflags = 0

        self.sshAgentProcess = subprocess.Popen(self.sshpaths.sshAgentBinary,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, universal_newlines=True,startupinfo=startupinfo, creationflags=creationflags)

        # Switching from self.sshAgentProcess.stdout.readlines() to self.sshAgentProcess.communicate(),
        # due to anecdotal evidence that it fixed a bug on Windows XP when charade.exe was slow to start up,
        # and because of the following warning from: http://docs.python.org/2/library/subprocess.html
        #
        # "Warning: Use communicate() rather than .stdin.write, .stdout.read or .stderr.read to avoid deadlocks
        # due to any of the other OS pipe buffers filling up and blocking the child process."

        timer=threading.Timer(5,self.sshAgentProcess.kill)
        timer.start()
        stdout,stderr = self.sshAgentProcess.communicate()
        timer.cancel()
        if self.sshAgentProcess.returncode!=0:
            raise Exception("""
The SSH agent failed to start properly. 
We see this occasionally on Windows computers. 
It usually seems to be fixed up rebooting, or simply trying again.
IF you have a procedure that reliably produces this bug, please tell us. We are having a hard time fixing it properly because it only 
happens occasionally.
""")

        if stderr is not None and stderr!="":
            logger.debug("KeyModel.startAgent stderr:\n" + stderr)
        for line in stdout.split("\n"):
            logger.debug("KeyModel.startAgent: line = " + line)
            if sys.platform.startswith('win'):
                match = re.search("^SSH_AUTH_SOCK=(?P<socket>.*?);.*$",line) # output from charade.exe doesn't match the regex, even though it looks the same!?
            else:
                match = re.search("^SSH_AUTH_SOCK=(?P<socket>.*?); export SSH_AUTH_SOCK;$",line)
            if match:
                agentenv = match.group('socket')
                if 'SSH_AUTH_SOCK' in os.environ:
                    os.environ['PREVIOUS_SSH_AUTH_SOCK'] = os.environ['SSH_AUTH_SOCK']
                os.environ['SSH_AUTH_SOCK'] = agentenv
                if sys.platform.startswith('win'):
                    try:
                        path = 'Environment'
                        reg = ConnectRegistry(None, HKEY_CURRENT_USER)
                        key = OpenKey(reg, path, 0, KEY_ALL_ACCESS)
                        try:
			    (value,type_id) = QueryValueEx(key,'SSH_AUTH_SOCK')
			    os.environ['PREVIOUS_SSH_AUTH_SOCK_REGISTRY']=value
			except WindowsError:
			    pass
			try:
			    SetValueEx(key,'SSH_AUTH_SOCK',0,REG_SZ,agentenv)
			except Exception as e:
                            logger.debug("couldn't set the SSH_AUTH_SOCK registry entry")
			CloseKey(key)
			win32gui.SendMessage(win32con.HWND_BROADCAST,win32con.WM_SETTINGCHANGE,0,'Environment')
                    except Exception as e:
                        logger.debug("Couldn't open the windows registry to set the SSH_AUTH_SOCK")



            match2 = re.search("^SSH_AGENT_PID=(?P<pid>[0-9]+);.*$",line)
            if match2:
                pid = match2.group('pid')
                os.environ['SSH_AGENT_PID'] = pid
                self.agentPid=pid
        if self.sshAgentProcess is None:
            raise Exception(str(stdout))
        if not pidIsRunning(os.environ['SSH_AGENT_PID']):
            agentName = ""
            if "charade" in self.sshpaths.sshAgentBinary:
                agentName="(charade.exe) "
            message = "The SSH Agent %sreported that it started a process with PID %s, but that process doesn't appear to be running:\n\n%s" % (agentName, os.environ['SSH_AGENT_PID'],stdout)
            logger.debug("KeyModel.startAgent: " + message)
            raise Exception(message)
        logger.debug("KeyModel.startAgent: Setting startedAgent.")
        if self.agentIsRunning():
            self.startedAgent.set()
            self.agentRunning.set()
        try:
            logger.debug("KeyModel.startAgent: SSH_AUTH_SOCK = " + os.environ['SSH_AUTH_SOCK'])
            logger.debug("KeyModel.startAgent: SSH_AGENT_PID = " + os.environ['SSH_AGENT_PID'])
        except:
            logger.debug(traceback.format_exc())

    def fingerprintAgent(self):
        proc = subprocess.Popen([self.sshPathsObject.sshAddBinary.strip('"'),"-l"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, startupinfo=self.startupinfo, creationflags=self.creationflags)
        stdout,stderr = proc.communicate()
        for line in stdout.splitlines(True):
            if (self.keyComment in line or self.getPrivateKeyFilePath() in line or "MassiveLauncherKey" in line):
                return line

    def privateKeyExists(self):
        return os.path.exists(self.getPrivateKeyFilePath())

    def getPrivateKeyFilePath(self):
        return self.sshPathsObject.sshKeyPath
    
    def getLauncherKeyComment(self):
        return self.keyComment
            

    def getsshBinary(self):
        return self.sshPathsObject.sshBinary
    
    def getsshKeyPath(self):
        return self.sshPathsObject.sshKeyPath

    def isTemporaryKey(self):
        return self.temporaryKey

    def generateNewKey(self, passphrase, keyCreatedSuccessfullyCallback, keyFileAlreadyExistsCallback, passphraseTooShortCallback, keyComment=None ):

        success = False

        if keyComment!=None:
            self.keyComment = keyComment
        if sys.platform.startswith('win'):
            cmdList = [self.sshPathsObject.sshKeyGenBinary, "-f", self.sshpaths.double_quote(self.getPrivateKeyFilePath()), "-C", self.sshpaths.double_quote(self.keyComment), "-N", passphrase]
            logger.debug("KeyModel.generateNewKey: " + " ".join(cmdList))
	    cmd = " ".join(cmdList)
            proc = subprocess.Popen(cmd,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    universal_newlines=True,
				    shell=True,
                                    startupinfo=self.startupinfo,
                                    creationflags=self.creationflags)
            #stdout, stderr = proc.communicate('\r\n')
            stdout, stderr = proc.communicate()

            if stdout is None or str(stdout).strip() == '':
                logger.debug("KeyModel.generateNewKey: " + '(1) Got EOF from ssh-keygen binary')
            elif "Your identification has been saved" in stdout:
                success = True
                keyCreatedSuccessfullyCallback()
            elif "passphrase too short" in stdout:
                passphraseTooShortCallback()
            elif 'already exists' in stdout:
                keyFileAlreadyExistsCallback()
            elif 'Could not open a connection to your authentication agent' in stdout:
                logger.debug("KeyModel.generateNewKey: " + "Could not open a connection to your authentication agent.")
                failedToConnectToAgentCallback()
            else:
                logger.debug("KeyModel.generateNewKey: " + 'Got unknown error from ssh-keygen binary')
                logger.debug("KeyModel.generateNewKey: " + stdout)
        else:
            # On Linux or BSD/OSX we can use pexpect to talk to ssh-keygen.

            import pexpect

            args = ["-f", self.getPrivateKeyFilePath(), "-C", self.sshpaths.double_quote(self.keyComment)]
            lp = pexpect.spawn(self.sshPathsObject.sshKeyGenBinary, args=args)
            logger.debug("KeyModel.generateNewKey: " + self.sshPathsObject.sshKeyGenBinary + " " + " ".join(args))

            idx = lp.expect(["Enter passphrase", "already exists", pexpect.EOF])

            if idx == 0:
                lp.sendline(passphrase)
                idx = lp.expect(["Enter same passphrase again"])
                lp.sendline(passphrase)
                idx = lp.expect(["Your identification has been saved", "do not match.", "passphrase too short"])
                if idx == 0:
                    success = True
                    keyCreatedSuccessfullyCallback()
                elif idx == 1:
                    # This shouldn't happen.
                    logger.debug("KeyModel.generateNewKey: " + "Passphrases do not match")
                elif idx == 2:
                    passphraseTooShortCallback()
            elif idx == 1:
                keyFileAlreadyExistsCallback()
            else:
                #logger.debug("1 returning KEY_LOCKED %s %s"%(lp.before,lp.after))
                logger.debug("KeyModel.generateNewKey: " + "Unexpected result from attempt to create new key.")
            lp.close()
        pubkeyPath=self.getPrivateKeyFilePath()+".pub"

        return success

    def changePassphrase(self, existingPassphrase, newPassphrase, 
        passphraseUpdatedSuccessfullyCallback,
        existingPassphraseIncorrectCallback,
        newPassphraseTooShortCallback,
        keyLockedCallback):

        success = False

        if sys.platform.startswith('win'):
            cmdList = [self.sshPathsObject.sshKeyGenBinary.strip('"'), "-f", self.getPrivateKeyFilePath(), 
                        "-p", "-P", existingPassphrase, "-N", newPassphrase]
            logger.debug("KeyModel.changePassphrase: " + " ".join(cmdList))
            proc = subprocess.Popen(cmdList,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    universal_newlines=True,
                                    startupinfo=self.startupinfo,
                                    creationflags=self.creationflags)
            stdout, stderr = proc.communicate(input=existingPassphrase + '\r\n')

            if stdout is None or str(stdout).strip() == '':
                logger.debug("KeyModel.changePassphrase: " + '(1) Got EOF from ssh-keygen binary')
                keyLockedCallback()
            if "Your identification has been saved" in stdout:
                success = True
                passphraseUpdatedSuccessfullyCallback()
            elif "passphrase too short" in stdout:
                newPassphraseTooShortCallback()
            elif 'Bad pass' in stdout or 'load failed' in stdout:
                logger.debug("changePassphrase %i %s: Got \"Bad pass\" from ssh-keygen binary"%(threading.currentThread().ident,threading.currentThread().name))
                if existingPassphrase == '':
                    keyLockedCallback()
                else:
                    existingPassphraseIncorrectCallback()
            else:
                logger.debug("changePassphrase %i %s: Got unknown error from ssh-keygen binary"%(threading.currentThread().ident,threading.currentThread().name))
                logger.debug("KeyModel.changePassphrase: " + stdout)
                keyLockedCallback()
        else:
            # On Linux or BSD/OSX we can use pexpect to talk to ssh-keygen.

            import pexpect

            args = ["-f", self.getPrivateKeyFilePath(), "-p"]
            lp = pexpect.spawn(self.sshPathsObject.sshKeyGenBinary, args=args)
            logger.debug("KeyModel.changePassphrase: " + self.sshPathsObject.sshKeyGenBinary + " " + " ".join(args))

            idx = lp.expect(["Enter old passphrase", "Key has comment"])

            if idx == 0:
                logger.debug("changePassphrase %i %s: sending passphrase to "%(threading.currentThread().ident,threading.currentThread().name) + self.sshPathsObject.sshKeyGenBinary + " -f " + self.getPrivateKeyFilePath() + " -p")
                lp.sendline(existingPassphrase)

            idx = lp.expect(["Enter new passphrase", "Bad pass", "load failed", pexpect.EOF])

            if idx == 0:
                lp.sendline(newPassphrase)
                idx = lp.expect(["Enter same passphrase again"])
                lp.sendline(newPassphrase)
                idx = lp.expect(["Your identification has been saved", "do not match.", "passphrase too short"])
                if idx == 0:
                    success = True
                    passphraseUpdatedSuccessfullyCallback()
                elif idx == 1:
                    # This shouldn't happen because changePassphrase 
                    # only takes one argument for newPassphrase,
                    # so repeated newPassphrase should have 
                    # already been checked before changePassphrase
                    # is called.
                    logger.debug("changePassphrase %i %s: Passphrases do not match"%(threading.currentThread().ident,threading.currentThread().name))
                elif idx == 2:
                    newPassphraseTooShortCallback()
            elif idx == 1 or idx == 2:
                existingPassphraseIncorrectCallback()
            else:
                #logger.debug("1 returning KEY_LOCKED %s %s"%(lp.before,lp.after))
                logger.debug("changePassphase %i %s: Unexpected result from attempt to change passphrase."%(threading.currentThread().ident,threading.currentThread().name))
            lp.close()
        return success

    # FIXME
    # deleteKey should probably be renamed to deleteKeyAndRemoveFromAgent
    # or we could have a boolean argument removeKeyFromAgent
    # or we could eliminate the "self.removeKeyFromAgent()" line
    # from this method and ensure that we always call
    # keyModel.removeKeyFromAgent() when calling keyModel.deleteKey().

    def deleteKey(self, removeFromAgent=True, ignoreFailureToConnectToAgent=False):
        # Delete key

        # Should we ask for the passphrase before deleting the key?

        logger.debug("KeyModel.deleteKey: self.getPrivateKeyFilePath() = " + self.getPrivateKeyFilePath())


        try:
 
            if removeFromAgent:
                try:
                    self.removeKeyFromAgent()
                except:
                    if ignoreFailureToConnectToAgent and 'Could not open a connection to your authentication agent' in traceback.format_exc():
                        logger.debug("KeyModel.deleteKey: Found 'Could not open a connection...' in removeKeyFromAgent's traceback.")
                        logger.debug("KeyModel.deleteKey: Proceeding with key deletion, even though we couldn't remove the key from the agent.")
                        logger.debug(traceback.format_exc())
                        pass
                    else:
                        logger.debug("KeyModel.deleteKey: Didn't find 'Could not open a connection...' in removeKeyFromAgent's traceback.")
                        raise

            logger.debug("KeyModel.deleteKey: Deleting private key...")
            os.unlink(self.getPrivateKeyFilePath())
            logger.debug("KeyModel.deleteKey: Deleted private key!")

            logger.debug("KeyModel.deleteKey: Looking for public key...")
            if os.path.exists(self.getPrivateKeyFilePath() + ".pub"):
                logger.debug("KeyModel.deleteKey: Found public key: " + self.getPrivateKeyFilePath() + ".pub")
                logger.debug("KeyModel.deleteKey: Deleting public key...")
                os.unlink(self.getPrivateKeyFilePath() + ".pub")
            else:
                logger.debug("KeyModel.deleteKey: Public key not found.")

        except:
            logger.debug("KeyModel.deleteKey: " + traceback.format_exc())
            return False

        return True

    def diffKeys(self,preList):
	if sys.platform.startswith("win"):
            postList = subprocess.Popen(" ".join([self.sshPathsObject.sshAddBinary,'-L']),shell=True,stdin=None,stdout=subprocess.PIPE,stderr=None,universal_newlines=True,startupinfo=self.startupinfo,creationflags=self.creationflags).communicate()
	else:
            postList = subprocess.Popen([self.sshPathsObject.sshAddBinary.strip('"'),'-L'],stdin=None,stdout=subprocess.PIPE,stderr=None,universal_newlines=True,startupinfo=self.startupinfo,creationflags=self.creationflags).communicate()
        for line in postList:
            if (not line in preList):
                match = re.search("^(?P<keytype>\S+)\ (?P<key>\S+)\ (?P<keycomment>.+)$",line)
                if match:
                    self.addedKey.append(match.group('key'))
                    
    def addKeyToAgent(self, passphrase, keyAddedSuccessfullyCallback, passphraseIncorrectCallback, privateKeyFileNotFoundCallback, failedToConnectToAgentCallback):

        success = False
        if not os.path.exists(self.sshPathsObject.sshKeyPath):
            privateKeyFileNotFoundCallback()
            return success
        try:
	    if sys.platform.startswith("win"):
                preList = subprocess.Popen(" ".join([self.sshPathsObject.sshAddBinary,'-L']),shell=True,stdin=None,stdout=subprocess.PIPE,stderr=None,universal_newlines=True,startupinfo=self.startupinfo,creationflags=self.creationflags).communicate()
            else:
                preList = subprocess.Popen([self.sshPathsObject.sshAddBinary,'-L'],shell=False,stdin=None,stdout=subprocess.PIPE,stderr=None,universal_newlines=True,startupinfo=self.startupinfo,creationflags=self.creationflags).communicate()
        except:
            failedToConnectToAgentCallback()
            return False

        if sys.platform.startswith('win'):
            # The patched OpenSSH binary on Windows/cygwin allows us
            # to send the passphrase via STDIN.
            cmdList = [self.sshPathsObject.sshAddBinary, self.sshPathsObject.double_quote(self.getPrivateKeyFilePath())]
            logger.debug("KeyModel.addKeyToAgent: " + " ".join(cmdList))
            # I think, if the agent is inaccessible, Popen will succeed, but communicate will throw an exception
            # However I only saw this while fixing a separate bug
            # We will wrap this in a try except clause just incase it offers additional robustness. CH
            try:
                proc = subprocess.Popen(" ".join(cmdList),
                                        stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        universal_newlines=True,
					shell=True,
                                        startupinfo=self.startupinfo,
                                        creationflags=self.creationflags)
                stdout, stderr = proc.communicate(input=passphrase + '\r\n')

                if stdout is None or str(stdout).strip() == '':
                    logger.debug("KeyModel.addKeyToAgent: " + '(1) Got EOF from ssh-add binary, probably because an empty passphrase was entered for a passphrase-locked key.')
                    passphraseIncorrectCallback()
                elif stdout is not None and "No such file or directory" in stdout:
                    logger.debug("KeyModel.addKeyToAgent: " + "addKeyToAgent couldn't find a private key")
                    privateKeyFileNotFoundCallback()
                    return False
                elif "Identity added" in stdout:
                    success = True
                    logger.debug("KeyModel.addKeyToAgent: " + "addKeyToAgent succesfully added a key to the agent")
                    self.diffKeys(preList)
                    keyAddedSuccessfullyCallback()
                elif 'Bad pass' in stdout:
                    logger.debug("KeyModel.addKeyToAgent: " + 'Got "Bad pass" from ssh-add binary')
                    proc.kill()
                    passphraseIncorrectCallback()
                elif 'Could not open a connection to your authentication agent' in stdout:
                    logger.debug("KeyModel.addKeyToAgent: " + "Could not open a connection to your authentication agent.")
                    failedToConnectToAgentCallback()
                else:
                    logger.debug("KeyModel.addKeyToAgent: " + 'Got unknown error from ssh-add binary')
                    logger.debug("KeyModel.addKeyToAgent: " + stdout)
            except:
                failedToConnectToAgentCallback()
                return False
        else:
            # On Linux or BSD/OSX we can use pexpect to talk to ssh-add.

            import pexpect

            args = [self.sshPathsObject.sshKeyPath]
            lp = pexpect.spawn(self.sshPathsObject.sshAddBinary, args=args)
            logger.debug("KeyModel.addKeyToAgent: " + self.sshPathsObject.sshAddBinary + " " + " ".join(args))

            idx = lp.expect(["Enter passphrase", "Identity added",'Could not open a connection to your authentication agent'])

            if idx == 1:
                success = True
                logger.debug("addKeyToAgent %i %s sucesfully added the key to the agent, calling keyAddedSuccesfullCallback"%(threading.currentThread().ident,threading.currentThread().name))
                self.diffKeys(preList)
                keyAddedSuccessfullyCallback()
            elif idx == 2:
                failedToConnectToAgentCallback()
                return False
            elif idx == 0:
                lp.sendline(passphrase)

                idx = lp.expect(["Identity added", "Bad pass",pexpect.EOF])
                if idx == 0:
                    self.diffKeys(preList)
                    success = True
                    logger.debug("addKeyToAgent %i %s sucesfully added the key to the agent, calling keyAddedSuccesfullCallback"%(threading.currentThread().ident,threading.currentThread().name))
                    keyAddedSuccessfullyCallback()
                elif idx == 1:
                    lp.kill(0)
                    logger.debug("addKeyToAgent %i %s determined the passphrase was incorrect, calling passphraseIncorrectCallback"%(threading.currentThread().ident,threading.currentThread().name))
                    passphraseIncorrectCallback()
                    success = False
                    return success
                elif idx == 2:
                    # ssh-add seems to fail silently if you don't enter a passphrase
                    # It will exit without displaying "Identity added" or "Bad passphrase".
                    lp.kill(0)
                    passphraseIncorrectCallback()
                    success = False
                    return success
            else:
                logger.debug("KeyModel.addKeyToAgent: " + "Unexpected result from attempt to add key.")
            lp.close()
        return success


    def removeKeyFromAgent(self):

        logger.debug("KeyModel.removeKeyFromAgent")
        if self.pubKey==None:
            # removeKeyFromAgent was failing when being called from InspectKeyDialog,
            # because keyModel.listKey() hadn't been called yet.
            logger.debug("KeyModel.removeKeyFromAgent: self.pubKey is None, so calling self.listKey().")
            self.listKey()
        if self.pubKey==None:
            logger.debug("KeyModel.removeKeyFromAgent: self.pubKey is still None after calling self.listKey(), so checking self.pubKeyFingerprint.")
            if self.pubKeyFingerprint==None:
                logger.debug("KeyModel.removeKeyFromAgent: self.pubKeyFingerprint is None, so calling self.getFingerprintAndKeyTypeFromPrivatKeyFile().")
                self.getFingerprintAndKeyTypeFromPrivateKeyFile()
            if self.pubKey==None and self.pubKeyFingerprint==None:
                logger.debug("KeyModel.removeKeyFromAgent: Bailing out because self.pubKey is None and self.pubKeyFingerprint is None.")
                return
        try:
            # Remove key(s) from SSH agent:

            logger.debug("Removing Launcher public key(s) from agent.")

            if self.pubKey!=None:
		if sys.platform.startswith("win"):
                    publicKeysInAgentProc = subprocess.Popen(" ".join([self.sshPathsObject.sshAddBinary,"-L"]),shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,startupinfo=self.startupinfo, creationflags=self.creationflags)
		else:
                    publicKeysInAgentProc = subprocess.Popen([self.sshPathsObject.sshAddBinary.strip('"'),"-L"],stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,startupinfo=self.startupinfo, creationflags=self.creationflags)
            elif self.pubKeyFingerprint!=None:
		if sys.platform.startswith("win"):
                    publicKeysInAgentProc = subprocess.Popen(" ",join([self.sshPathsObject.sshAddBinary,"-l"]),shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,startupinfo=self.startupinfo, creationflags=self.creationflags)
		else:
                    publicKeysInAgentProc = subprocess.Popen([self.sshPathsObject.sshAddBinary.strip('"'),"-l"],stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,startupinfo=self.startupinfo, creationflags=self.creationflags)
            else:
                logger.debug("KeyModel.removeKeyFromAgent: Bailing out because self.pubKey is None and self.pubKeyFingerprint is None.")
                return 
            publicKeysInAgent = publicKeysInAgentProc.stdout.readlines()
            for publicKeyLineFromAgent in publicKeysInAgent:
                if (self.pubKey!=None and self.pubKey in publicKeyLineFromAgent) or (self.pubKeyFingerprint!=None and self.pubKeyFingerprint in publicKeyLineFromAgent):
                    tempPublicKeyFile = tempfile.NamedTemporaryFile(delete=False)
                    tempPublicKeyFile.write(publicKeyLineFromAgent)
                    tempPublicKeyFile.close()
                    try:
			if sys.platform.startswith("win"):
                            removePublicKeyFromAgent = subprocess.Popen(" ".join([self.sshPathsObject.sshAddBinary,"-d",tempPublicKeyFile.name]),stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, startupinfo=self.startupinfo, creationflags=self.creationflags)
			else:
                            removePublicKeyFromAgent = subprocess.Popen([self.sshPathsObject.sshAddBinary.strip('"'),"-d",tempPublicKeyFile.name],stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, startupinfo=self.startupinfo, creationflags=self.creationflags)
                        logger.debug("KeyModel.removeKeyFromAgent: " + self.sshPathsObject.sshAddBinary + " -d " + tempPublicKeyFile.name)
                        stdout, stderr = removePublicKeyFromAgent.communicate()
                        if stderr is not None and len(stderr) > 0:
                            logger.debug("KeyModel.removeKeyFromAgent: " + stderr)
                        success = ("Identity removed" in stdout)
                    finally:
                        os.unlink(tempPublicKeyFile.name)
            for key in self.addedKey:
                if self.pubKey!=None and key in self.pubKey:
                    self.addedKey.remove(key)
            self.pubKey=None
            self.pubKeyFingerprint=None
        except:
            logger.debug("KeyModel.removeKeyFromAgent: " + traceback.format_exc())
            return False

        return True

    def agentIsRunning(self):
        try:
            self.listKey()
            return True
        except:
            return False

    def listKey(self):
        import re
        sshKeyListCmd = self.sshpaths.sshAddBinary + " -L "
        logger.debug("KeyModel.listKey: sshkeyListCmd = " + sshKeyListCmd)
        if 'SSH_AUTH_SOCK' in os.environ:
            logger.debug("KeyModel.listKey: SSH_AUTH_SOCK = " + os.environ['SSH_AUTH_SOCK'])
        else:
            logger.debug("KeyModel.listKey: SSH_AUTH_SOCK was not found in os.environ")
        if 'SSH_AGENT_PID' in os.environ:
            logger.debug("KeyModel.listKey: SSH_AGENT_PID = " + os.environ['SSH_AGENT_PID'])
        else:
            logger.debug("KeyModel.listKey: SSH_AGENT_PID was not found in os.environ")
        keylist = subprocess.Popen(sshKeyListCmd, stdout = subprocess.PIPE,stderr=subprocess.PIPE,shell=True,universal_newlines=True,startupinfo=self.startupinfo,creationflags=self.creationflags)
        (stdout,stderr) = keylist.communicate()
        if stderr!="":
            e = Exception(stderr)
            raise e

        lines = stdout.split('\n')
        for line in lines:
            logger.debug("KeyModel.listKey: ssh-add -L returned a line %s"%line)
            match = re.search("^(?P<keytype>\S+)\ (?P<key>\S+)\ (?P<keycomment>.+)$",line)
            if match:
                keycomment = match.group('keycomment')
                logger.debug("KeyModel.listKey: searching for the string")
                if (self.addedKey!=[]):
                    logger.debug("KeyModel.listKey: KeyModel reports that we have added a key, will attempt to match on the string %s"%self.addedKey[0])
                    if self.addedKey[0] in line:
                        keyMatch=True
                    else:
                        keyMatch=False
                    pathMatch=None
                    commentMatch=None
                    launcherMatch=None
                else:
                    keyMatch=None
                    pathMatch = re.search('.*{launchercomment}.*'.format(launchercomment=os.path.basename(self.getPrivateKeyFilePath())),keycomment)
                    commentMatch = re.search('.*{launchercomment}.*'.format(launchercomment=self.getLauncherKeyComment()),keycomment)
                    launcherMatch = re.search('Launcher',keycomment)
                if pathMatch or commentMatch or launcherMatch or keyMatch:
                    self.pubKey = line.rstrip()
                    return self.pubKey
        return None

        

def pidIsRunning(pid):
    try:
        import psutil
        p = psutil.Process(int(pid))
        if p.status == psutil.STATUS_DEAD:
            return False
        if p.status == psutil.STATUS_ZOMBIE:
            return False
        return True # Assume other status are valid
    except psutil.NoSuchProcess:
        return False
    except ImportError:
        logger.debug('KeyModel: python installation mising the psutil module')
        return True
