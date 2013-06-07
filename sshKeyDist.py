import os
import subprocess
import ssh
import wx
import wx.lib.newevent
import re
from StringIO import StringIO
import logging
from threading import *
import time
import sys
from os.path import expanduser
import subprocess
import traceback

if not sys.platform.startswith('win'):
    import pexpect

def double_quote(x):
    return '"' + x + '"'

class sshpaths():
    def ssh_binaries(self):
        """
        Locate the ssh binaries on various systems. On Windows we bundle a
        stripped-down OpenSSH build that uses Cygwin.
        """
 
        if sys.platform.startswith('win'):
            if hasattr(sys, 'frozen'):
                f = lambda x: os.path.join(os.path.dirname(sys.executable), 'openssh-cygwin-stdin-build', 'bin', x)
            else:
                f = lambda x: os.path.join(os.getcwd(), 'openssh-cygwin-stdin-build', 'bin', x)
 
            sshBinary        = f('ssh.exe')
            sshKeyGenBinary  = f('ssh-keygen.exe')
            sshKeyScanBinary = f('ssh-keyscan.exe')
            sshAgentBinary   = f('ssh-agent.exe')
            sshAddBinary     = f('ssh-add.exe')
            chownBinary      = f('chown.exe')
            chmodBinary      = f('chmod.exe')
        elif sys.platform.startswith('darwin'):
            sshBinary        = '/usr/bin/ssh'
            sshKeyGenBinary  = '/usr/bin/ssh-keygen'
            sshKeyScanBinary = '/usr/bin/ssh-keyscan'
            sshAgentBinary   = '/usr/bin/ssh-agent'
            sshAddBinary     = '/usr/bin/ssh-add'
            chownBinary      = '/usr/sbin/chown'
            chmodBinary      = '/bin/chmod'
        else:
            sshBinary        = '/usr/bin/ssh'
            sshKeyGenBinary  = '/usr/bin/ssh-keygen'
            sshKeyScanBinary = '/usr/bin/ssh-keyscan'
            sshAgentBinary   = '/usr/bin/ssh-agent'
            sshAddBinary     = '/usr/bin/ssh-add'
            chownBinary      = '/bin/chown'
            chmodBinary      = '/bin/chmod'
 
        return (sshBinary, sshKeyGenBinary, sshAgentBinary, sshAddBinary, sshKeyScanBinary, chownBinary, chmodBinary,)
    
    def ssh_files(self):
        known_hosts_file = os.path.join(expanduser('~'), '.ssh', 'known_hosts')
        sshKeyPath = os.path.join(expanduser('~'), '.ssh', 'MassiveLauncherKey')
        return (sshKeyPath,known_hosts_file,)

    def __init__(self):
        (sshBinary, sshKeyGenBinary, sshAgentBinary, sshAddBinary, sshKeyScanBinary,chownBinary, chmodBinary,) = self.ssh_binaries()
        (sshKeyPath,sshKnownHosts,) = self.ssh_files()
        self.sshBinary = sshBinary
        self.sshKeyGenBinary = sshKeyGenBinary
        self.sshAgentBinary = sshAgentBinary
        self.sshAddBinary = sshAddBinary
        self.sshKeyScanBinary = sshKeyScanBinary
        self.chownBinary = chownBinary
        self.chmodBinary = chmodBinary

        self.sshKeyPath = sshKeyPath
        self.sshKnownHosts = sshKnownHosts

class KeyDist():

    def complete(self):
        self.completedLock.acquire()
        returnval = self.completed
        self.completedLock.release()
        return returnval

    class passphraseDialog(wx.Dialog):

        def __init__(self, parent, id, title, text, okString, cancelString):
            wx.Dialog.__init__(self, parent, id, title, style=wx.DEFAULT_FRAME_STYLE ^ wx.RESIZE_BORDER | wx.STAY_ON_TOP)
            self.SetTitle(title)
            self.panel = wx.Panel(self,-1)
            self.label = wx.StaticText(self.panel, -1, text)
            self.PassphraseField = wx.TextCtrl(self.panel, wx.ID_ANY, style=wx.TE_PASSWORD ^ wx.TE_PROCESS_ENTER)
            self.PassphraseField.SetFocus()
            self.Cancel = wx.Button(self.panel,-1,label=cancelString)
            self.OK = wx.Button(self.panel,-1,label=okString)

            self.sizer = wx.FlexGridSizer(2, 2, 5, 5)
            self.sizer.Add(self.label)
            self.sizer.Add(self.PassphraseField)
            self.sizer.Add(self.Cancel)
            self.sizer.Add(self.OK)

            self.PassphraseField.Bind(wx.EVT_TEXT_ENTER,self.onEnter)
            self.OK.Bind(wx.EVT_BUTTON,self.onEnter)
            self.Cancel.Bind(wx.EVT_BUTTON,self.onEnter)

            self.border = wx.BoxSizer()
            self.border.Add(self.sizer, 0, wx.ALL, 15)
            self.panel.SetSizerAndFit(self.border)
            self.Fit()
            self.password = None

        def onEnter(self,e):
            if (e.GetId() == self.Cancel.GetId()):
                self.canceled = True
                self.password = None
            else:
                self.canceled = False
                self.password = self.PassphraseField.GetValue()
            self.Close()
            self.Destroy()


        def getPassword(self):
            val = self.ShowModal()
            return self.password

    class startAgentThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject

        def run(self):
            print 'startAgentThread: run()'
            agentenv = None
            try:
                agentenv = os.environ['SSH_AUTH_SOCK']
                print 'startAgentThread: found SSH_AUTH_SOCK environment variable: ' + agentenv
            except:
                print 'startAgentThread: did not find SSH_AUTH_SOCK environment variable; trying to start ssh-agent'
                try:
                    agent = subprocess.Popen(self.keydistObject.sshpaths.sshAgentBinary,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
                    stdout = agent.stdout.readlines()
                    print 'startagent stdout:', str(stdout)
                    for line in stdout:
                        match = re.search("^SSH_AUTH_SOCK=(?P<socket>.*); export SSH_AUTH_SOCK;$",line)
                        if match:
                            agentenv = match.group('socket')
                            os.environ['SSH_AUTH_SOCK'] = agentenv
                            print 'startAgentThread: started ssh-agent; SSH_AUTH_SOCK = ' + agentenv
                    if agent is None:
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_CANCEL, self, str(stdout))
                        print 'startAgentThread: failed to start ssh-agent: ' + str(str(stdout))
                except Exception as e:
                    string = "%s"%e
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_CANCEL,self,string)
                    print 'startAgentThread: failed to start ssh-agent: ' + str(e)

            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_GETPUBKEY,self.keydistObject)
            wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
            print 'startAgentThread: exiting run()'

    class genkeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject

        def run(self):
            print 'genkeyThread: run()'
            cmd = '{sshkeygen} -q -f "{keyfilename}" -C "{keycomment}" -N {password}'.format(sshkeygen=self.keydistObject.sshpaths.sshKeyGenBinary,
                                                                                                 keyfilename=self.keydistObject.sshpaths.sshKeyPath,
                                                                                                 keycomment=self.keydistObject.launcherKeyComment,
                                                                                                 password=self.keydistObject.password)
            print "spawning keygenproc"
            keygen_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
            print "waiting on keygenproc"
            keygen_proc.wait()
            print "keygen returned"

            try:
                with open(self.keydistObject.sshpaths.sshKeyPath,'r'): pass
                print "key was created, generate load key and pass"
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LOADKEY,self.keydistObject) # Auth hasn't really failed but this event will trigger loading the key
            except Exception as e:
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_CANCEL,self.keydistObject,"error generating key")
            wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),event)

    class getPubKeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject

        def run(self):
            sshKeyListCmd = self.keydistObject.sshpaths.sshAddBinary + " -L "
            keylist = subprocess.Popen(sshKeyListCmd, stdout = subprocess.PIPE,stderr=subprocess.STDOUT,shell=True,universal_newlines=True)
            keylist.wait()
            stdout = keylist.stdout.readlines()
            self.keydistObject.pubkeylock.acquire()
            for line in stdout:
                match = re.search("^(?P<keytype>\S+)\ (?P<key>\S+)\ (?P<keycomment>.+)$",line)
                if match:
                    keycomment = match.group('keycomment')
                    correctKey = re.search('.*{launchercomment}.*'.format(launchercomment=self.keydistObject.launcherKeyComment),keycomment)
                    if correctKey:
                        self.keydistObject.keyloaded = True
                        self.keydistObject.pubkey = line.rstrip()
            if (self.keydistObject.keyloaded):
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_TESTAUTH,self.keydistObject)
            else:
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LOADKEY,self.keydistObject)
            self.keydistObject.pubkeylock.release()
            wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)

    class scanHostKeysThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject
            self.ssh_keygen_cmd = '{sshkeygen} -F {host} -f {known_hosts_file}'.format(sshkeygen=self.keydistObject.sshpaths.sshKeyGenBinary,host=self.keydistObject.host,known_hosts_file=self.keydistObject.sshpaths.sshKnownHosts)
            self.ssh_keyscan_cmd = '{sshscan} -H {host}'.format(sshscan=self.keydistObject.sshpaths.sshKeyScanBinary,host=self.keydistObject.host)

        def getKnownHostKeys(self):
            keygen = subprocess.Popen(self.ssh_keygen_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True,universal_newlines=True)
            stdout,stderr = keygen.communicate()
            keygen.wait()
            hostkeys=[]
            for line in stdout.split('\n'):
                print line
                if (not (line.find('#')==0 or line == '')):
                    hostkeys.append(line)
            return hostkeys
                    
        def appendKey(self,key):
            with open(self.keydistObject.sshpaths.sshKnownHosts,'a+') as known_hosts:
                known_hosts.write(key)
                known_hosts.write('\n')
            

        def scanHost(self):
            scan = subprocess.Popen(self.ssh_keyscan_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True,universal_newlines=True)
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
            wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
                        
            

    class testAuthThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject

        def run(self):

            ssh_cmd = '{sshbinary} -o PasswordAuthentication=no -o PubkeyAuthentication=yes -o StrictHostKeyChecking=no -l {login} {host} echo "success_testauth"'.format(sshbinary=self.keydistObject.sshpaths.sshBinary,
                                                                                                                                                                          login=self.keydistObject.username,
                                                                                                                                                                          host=self.keydistObject.host)
            ssh = subprocess.Popen(ssh_cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,shell=True,universal_newlines=True)
            stdout, stderr = ssh.communicate()
            ssh.wait()
            if 'success_testauth' in stdout:
                print 'testAuthThread: run(): got success_testauth in stdout :)'
                self.keydistObject.authentication_success = True
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHSUCCESS,self.keydistObject)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
            else:
                print 'testAuthThread: run(): did NOT see success_testauth in stdout :('
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHFAIL,self.keydistObject)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)


    class loadKeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject


        def loadKey(self):
            try:
                f = open(self.keydistObject.sshpaths.sshKeyPath,'r')
                f.close()
            except IOError as e: # The key file didn't exist, so we should generate a new one.
                print "in load key, key does not exist, requesting a new password"
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEWPASS_REQ,self.keydistObject)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
                return

            if (self.keydistObject.password != None and len(self.keydistObject.password) > 0):
                print 'getPubkeyThread: loadKey(): got passphrase from keydistObject'
                passphrase = self.keydistObject.password
            else:
                print 'getPubkeyThread: loadKey(): using empty passphrase'
                passphrase = ''

            if sys.platform.startswith('win'):
                print 'boo'
                # The patched OpenSSH binary on Windows/cygwin allows us
                # to send the password via stdin.
                cmd = self.keydistObject.sshpaths.sshAddBinary + ' ' + double_quote(self.keydistObject.sshpaths.sshKeyPath)
                print 'on Windows, so running: ' + cmd
                stdout, stderr = subprocess.Popen(cmd,
                                                  stdin=subprocess.PIPE,
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT,
                                                  shell=True,
                                                  universal_newlines=True).communicate(input=passphrase + '\r\n')

                print 'boo2'
                print 'stdout from ssh-add:', str(stdout)
                print 'stderr from ssh-add:', str(stderr)

                if stdout is None or str(stdout).strip() == '':
                    # Got EOF from ssh-add binary
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED, self.keydistObject)
                elif 'Identity added' in stdout:
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_GETPUBKEY, self.keydistObject)
                elif 'Bad pass' in stdout:
                    if passphrase == '':
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED, self.keydistObject)
                    else:
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_WRONGPASS, self.keydistObject)
                else:
                    # unknown error
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED,self.keydistObject)
            else:
                # On Linux or BSD/OSX we can use pexpect to talk to ssh-add.

                args = [self.keydistObject.sshpaths.sshKeyPath]
                print 'getPubkeyThread: loadKey(): running %s with args %s' % (str(self.keydistObject.sshpaths.sshAddBinary), str(args),)
                lp = pexpect.spawn(self.keydistObject.sshpaths.sshAddBinary, args=args)

                idx = lp.expect(["Identity added", ".*pass.*"])

                if idx == 1:
                    print 'getPubkeyThread: loadKey(): sending passphrase to ssh-agent'
                    lp.sendline(passphrase)

                    idx = lp.expect(["Identity added", "Bad pass", pexpect.EOF])

                    if idx == 0:
                        print 'getPubkeyThread: loadKey(): got "Identity added"; posting the EVT_KEYDIST_GETPUBKEY event'
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_GETPUBKEY, self.keydistObject)
                    elif idx == 1:
                        print 'getPubkeyThread: loadKey(): got "Bad pass"'
                        if passphrase == '':
                            print 'getPubkeyThread: loadKey(): empty passphrase,  so posting the EVT_KEYDIST_KEY_LOCKED event'
                            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED, self.keydistObject)
                        else:
                            print 'getPubkeyThread: loadKey(): non-empty passphrase,  so posting the EVT_KEYDIST_KEY_WRONGPASS event'
                            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_WRONGPASS, self.keydistObject)
                    else:
                        print 'getPubkeyThread: loadKey(): got EOF (?) from ssh-add,  so posting the EVT_KEYDIST_KEY_LOCKED event'
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED, self.keydistObject)
                else:
                    print 'getPubkeyThread: loadKey(): got "Identity added" from ssh-add, so sending the EVT_KEYDIST_KEY_LOCKED event'
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED, self.keydistObject)
                lp.close()

            wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(), newevent)
            print 'getPubkeyThread: loadKey(): exiting'


        def run(self):
            self.loadKey()


    class CopyIDThread(Thread):
        def __init__(self,keydist):
            Thread.__init__(self)
            self.keydistObject = keydist

        def run(self):
            sshClient = ssh.SSHClient()
            sshClient.set_missing_host_key_policy(ssh.AutoAddPolicy())
            try:
                sshClient.connect(hostname=self.keydistObject.host,username=self.keydistObject.username,password=self.keydistObject.password,allow_agent=False,look_for_keys=False)
                sshClient.exec_command("module load massive")
                sshClient.exec_command("/bin/mkdir -p ~/.ssh")
                sshClient.exec_command("/bin/chmod 700 ~/.ssh")
                sshClient.exec_command("/bin/touch ~/.ssh/authorized_keys")
                sshClient.exec_command("/bin/chmod 600 ~/.ssh/authorized_keys")
                sshClient.exec_command("/bin/echo \"%s\" >> ~/.ssh/authorized_keys"%self.keydistObject.pubkey)
                sshClient.close()
                self.keydistObject.keycopiedLock.acquire()
                self.keydistObject.keycopied=True
                self.keydistObject.keycopiedLock.release()
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_TESTAUTH,self.keydistObject)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),event)
            except ssh.AuthenticationException as e:
                string = "%s"%e
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_COPYID_NEEDPASS,self.keydistObject,string)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),event)
            except ssh.SSHException as e:
                string = "%s"%e
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_CANCEL,self.keydistObject,string)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),event)



    class sshKeyDistEvent(wx.PyCommandEvent):
        def __init__(self,id,keydist,string=""):
            wx.PyCommandEvent.__init__(self,KeyDist.myEVT_CUSTOM_SSHKEYDIST,id)
            self.keydist = keydist
            self.string = string

        def newkey(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEWPASS_REQ):
                wx.CallAfter(event.keydist.getNewPassphrase_stage1,event.string)
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEWPASS_RPT):
                wx.CallAfter(event.keydist.getNewPassphrase_stage2)
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEWPASS_COMPLETE):
                try:
                    if (event.keydist.workThread != None):
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                event.keydist.workThread = KeyDist.genkeyThread(event.keydist)
                event.keydist.workThread.start()
            event.Skip()

        def copyid(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_COPYID_NEEDPASS):
                wx.CallAfter(event.keydist.getLoginPassword,event.string)
            if (event.GetId() == KeyDist.EVT_KEYDIST_COPYID):
                try:
                    if (event.keydist.workThread != None):
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                event.keydist.workThread = KeyDist.CopyIDThread(event.keydist)
                event.keydist.workThread.start()
            event.Skip()

        def scanhostkeys(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_SCANHOSTKEYS):
                try:
                    if (event.keydist.workThread != None):
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                print "creating scanHostKeys Thread"
                event.keydist.workThread = KeyDist.scanHostKeysThread(event.keydist)
                event.keydist.workThread.start()
            event.Skip()

        def cancel(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_CANCEL):
                if (len(event.string)>0):
                    print event.string
                try:
                    if (event.keydist.workThread != None):
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                event.keydist.completed=True
            event.Skip()

        def success(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_AUTHSUCCESS):
                event.keydist.completed=True
            event.Skip()


        def needagent(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEEDAGENT):
                try:
                    if (event.keydist.workThread != None):
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                event.keydist.workThread = KeyDist.startAgentThread(event.keydist)
                event.keydist.workThread.start()
            else:
                event.Skip()

        def listpubkeys(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_GETPUBKEY):
                try:
                    if (event.keydist.workThread != None):
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                event.keydist.workThread = KeyDist.getPubKeyThread(event.keydist)
                event.keydist.workThread.start()
            else:
                event.Skip()

        def testauth(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_TESTAUTH):
                try:
                    if (event.keydist.workThread != None):
                        print "waiting for previous thread to join"
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                event.keydist.workThread = KeyDist.testAuthThread(event.keydist)
                event.keydist.workThread.start()
            else:
                event.Skip()

        def keylocked(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_KEY_LOCKED):
                wx.CallAfter(event.keydist.GetKeyPassword)
            if (event.GetId() == KeyDist.EVT_KEYDIST_KEY_WRONGPASS):
                wx.CallAfter(event.keydist.GetKeyPassword,"Sorry that password was incorrect. ")
            event.Skip()

        def loadkey(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_LOADKEY):
                print "recieved EVT_KEYDIST_LOADKEY"
                try:
                    if (event.keydist.workThread != None):
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                event.keydist.workThread = KeyDist.loadKeyThread(event.keydist)
                event.keydist.workThread.start()
            else:
                event.Skip()

        def authfail(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_AUTHFAIL):
                event.keydist.pubkeylock.acquire()
                keyloaded = event.keydist.keyloaded
                event.keydist.pubkeylock.release()
                if(not keyloaded):
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LOADKEY,event.keydist)
                    wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
                else:
                    # if they key is loaded into the ssh agent, then authentication failed because the public key isn't on the server.
                    # *****TODO*****
                    # actually this might not be strictly true. gnome keychain (and possibly others) will report a key loaded even if its still locked
                    # we probably need a button that says "I can't remember my old keys password, please generate a new keypair"
                    event.keydist.keycopiedLock.acquire()
                    keycopied=event.keydist.keycopied
                    event.keydist.keycopiedLock.release()
                    if (keycopied):
                        print "auth failed but key copied, retry auth"
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_TESTAUTH,event.keydist)
                        wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
                    else:
                        print "autfail event, key is loaded, but we can't log copy the id"
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_COPYID_NEEDPASS,event.keydist)
                        wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
            else:
                event.Skip()


        def startevent(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_START):
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_SCANHOSTKEYS,event.keydist)
                wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
            else:
                event.Skip()

    myEVT_CUSTOM_SSHKEYDIST=None
    EVT_CUSTOM_SSHKEYDIST=None
    def __init__(self,username,host,notifywindow,sshPaths):
        KeyDist.myEVT_CUSTOM_SSHKEYDIST=wx.NewEventType()
        KeyDist.EVT_CUSTOM_SSHKEYDIST=wx.PyEventBinder(self.myEVT_CUSTOM_SSHKEYDIST,1)
        KeyDist.EVT_KEYDIST_START = wx.NewId()
        KeyDist.EVT_KEYDIST_CANCEL = wx.NewId()
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
        KeyDist.EVT_KEYDIST_COPYID_NEEDPASS = wx.NewId()
        KeyDist.EVT_KEYDIST_KEY_LOCKED = wx.NewId()
        KeyDist.EVT_KEYDIST_KEY_WRONGPASS = wx.NewId()
        KeyDist.EVT_KEYDIST_SCANHOSTKEYS = wx.NewId()
        KeyDist.EVT_KEYDIST_LOADKEY = wx.NewId()

        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.cancel)
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

        self.completed=False
        self.username = username
        self.host = host
        self.notifywindow = notifywindow
        self.sshKeyPath = ""
        self.workThread = None
        self.pubkeyfp = None
        self.keyloaded = False
        self.password = None
        self.pubkeylock = Lock()
        self.completedLock = Lock()
        self.keycopiedLock=Lock()
        self.keycopied=False
        self.sshpaths=sshPaths
        self.launcherKeyComment=os.path.basename(self.sshpaths.sshKeyPath)
        self.authentication_success = False

    def GetKeyPassword(self,prepend=""):
        ppd = KeyDist.passphraseDialog(None,wx.ID_ANY,'Unlock Key',prepend+"Please enter the passphrase for the key","OK","Cancel")
        password = ppd.getPassword()
        if (password == None):
            event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_CANCEL,self)
        else:
            self.password = password
            print "Get Key Password, generating AUTHFAIL"
            event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHFAIL,self)
        wx.PostEvent(self.notifywindow.GetEventHandler(),event)

    def getLoginPassword(self,prepend=""):
        print "get login password"
        ppd = KeyDist.passphraseDialog(None,wx.ID_ANY,'Login Passphrase',prepend+"Please enter your login password for username %s at %s"%(self.username,self.host),"OK","Cancel")
        password = ppd.getPassword()
        self.password = password
        event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_COPYID,self)
        wx.PostEvent(self.notifywindow.GetEventHandler(),event)

    def getNewPassphrase_stage1(self,prepend=""):
        ppd = KeyDist.passphraseDialog(None,wx.ID_ANY,'New Passphrase',prepend+"Please enter a new passphrase","OK","Cancel")
        password = ppd.getPassword()
        if (len(password) < 6 and len(password)>0):
            event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEWPASS_REQ,self,"The password was too short. ")
        else:
            self.password = password
            event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEWPASS_RPT,self)
        wx.PostEvent(self.notifywindow.GetEventHandler(),event)

    def getNewPassphrase_stage2(self):
        ppd = KeyDist.passphraseDialog(None,wx.ID_ANY,'New Passphrase',"Please repeat the new passphrase","OK","Cancel")
        phrase = ppd.getPassword()
        if (phrase == None):
            phrase = ""
        if (phrase == self.password):
            event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEWPASS_COMPLETE,self)
        else:
            event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEWPASS_REQ,self,"The passwords didn't match. ")
        wx.PostEvent(self.notifywindow.GetEventHandler(),event)


    def distributeKey(self):
        event = KeyDist.sshKeyDistEvent(self.EVT_KEYDIST_START, self)
        wx.PostEvent(self.notifywindow.GetEventHandler(), event)
