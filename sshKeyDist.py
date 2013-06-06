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

if sys.platform.startswith('win'):
    import wexpect as expect
    newline = '\r\n'
else:
    import pexpect as expect
    newline = '\n'

def double_quote(x):
    return '"' + x + '"'

def ssh_binaries():
    """
    Locate the ssh binaries on various systems. On Windows we bundle a
    stripped-down OpenSSH build that uses Cygwin.
    """

    if sys.platform.startswith('win'):
        if hasattr(sys, 'frozen'):
            f = lambda x: os.path.join(os.path.dirname(sys.executable), 'openssh-cygwin-stdin-build', 'bin', x)
        else:
            f = lambda x: os.path.join(os.getcwd(), 'openssh-cygwin-stdin-build', 'bin', x)

        sshBinary       = f('ssh.exe')
        sshKeyGenBinary = f('ssh-keygen.exe')
        sshAgentBinary  = f('ssh-agent.exe')
        sshAddBinary    = f('ssh-add.exe')
        chownBinary     = f('chown.exe')
        chmodBinary     = f('chmod.exe')
    elif sys.platform.startswith('darwin'):
        sshBinary       = '/usr/bin/ssh'
        sshKeyGenBinary = '/usr/bin/ssh-keygen'
        sshAgentBinary  = '/usr/bin/ssh-agent'
        sshAddBinary    = '/usr/bin/ssh-add'
        chownBinary     = '/usr/sbin/chown'
        chmodBinary     = '/bin/chmod'
    else:
        sshBinary       = '/usr/bin/ssh'
        sshKeyGenBinary = '/usr/bin/ssh-keygen'
        sshAgentBinary  = '/usr/bin/ssh-agent'
        sshAddBinary    = '/usr/bin/ssh-add'
        chownBinary     = '/bin/chown'
        chmodBinary     = '/bin/chmod'

    return (sshBinary, sshKeyGenBinary, sshAgentBinary, sshAddBinary, chownBinary, chmodBinary,)


(sshBinary, sshKeyGenBinary, sshAgentBinary, sshAddBinary, chownBinary, chmodBinary,) = ssh_binaries()

sshKeyPath = os.path.join(expanduser('~'), '.ssh', 'MassiveLauncherKey')

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
                    agent = subprocess.Popen(sshAgentBinary,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
                    stdout = agent.stdout.readlines()
                    for line in stdout:
                        match = re.search("^SSH_AUTH_SOCK=(?P<socket>.*); export SSH_AUTH_SOCK;$",line)
                        if match:
                            agentenv = match.group('socket')
                            os.environ['SSH_AUTH_SOCK']=agentenv
                            print 'startAgentThread: started ssh-agent; SSH_AUTH_SOCK = ' + agentenv
                except Exception as e:
                    string = "%s"%e
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_CANCEL,self,string)
                    print 'startAgentThread: failed to start ssh-agent: ' + str(e)

            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LISTFINGERPRINTS,self.keydistObject)
            wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
            print 'startAgentThread: exiting run()'

    class genkeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject

        def run(self):
            print 'genkeyThread: run()'
            cmd = '{sshkeygen} -q -f "{keyfilename}" -C "MASSIVE Launcher" -N {password}'.format(sshkeygen=sshKeyGenBinary,
                                                                                                 keyfilename=self.keydistObject.sshKeyPath,
                                                                                                 password=self.keydistObject.password)

            print 'genkeyThread: running command: ' + cmd

            keygen_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
            keygen_proc.wait()

            try:
                with open(self.keydistObject.sshKeyPath+".pub",'r'): pass
                print 'genkeyThread: able to open public key file; posting the EVT_KEYDIST_AUTHFAIL event to trigger loading of the key'
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHFAIL,self.keydistObject) # Auth hasn't really failed but this event will trigger loading the key
            except Exception as e:
                print 'genkeyThread: some other error while generating the key: ' + str(e)
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_CANCEL,self.keydistObject,"error generating key")
 
            print 'genkeyThread: posting self.keydistObject.notifywindow.GetEventHandler()'
            wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),event)
            print 'genkeyThread: exiting run()'

    class listFingerprintsThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject

        def run(self):
            print 'listFingerprintsThread: run()'
            sshKeyListCmd = sshAddBinary + " -l "
            print 'listFingerprintsThread: running command: ' + sshKeyListCmd
            keylist = subprocess.Popen(sshKeyListCmd, stdout = subprocess.PIPE,stderr=subprocess.STDOUT,shell=True,universal_newlines=True)
            keylist.wait()
            stdout = keylist.stdout.readlines()

            print 'listFingerprintsThread: stdout: ' + str(stdout)

            self.keydistObject.fplock.acquire()
            self.keydistObject.fingerprints = []
            for line in stdout:
                match = re.search("^[0-9]+\ (\S*)\ (.+)$",line)
                if match:
                    self.keydistObject.fingerprints.append(match.group(1))
            if (self.keydistObject.pubkeyfp in self.keydistObject.fingerprints):
                self.keydistObject.pubkeyloaded = True
            self.keydistObject.fplock.release()
            if (len(self.keydistObject.fingerprints) > 0):
                print 'listFingerprintsThread: found the fingerprint; posting the EVT_KEYDIST_TESTAUTH event'
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_TESTAUTH,self.keydistObject)
            else:
                print 'listFingerprintsThread: did not find the fingerprint; posting the EVT_KEYDIST_AUTHFAIL event'
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHFAIL,self.keydistObject)
            wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
            print 'listFingerprintsThread: leaving run()'

    class testAuthThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject

        def run(self):
            print 'testAuthThread: run()'

            ssh_cmd = '{sshbinary} -o PasswordAuthentication=no -o PubkeyAuthentication=yes -o StrictHostKeyChecking=no -l {login} {host} echo "success_testauth"'.format(sshbinary=sshBinary,
                                                                                                                                                                          login=self.keydistObject.username,
                                                                                                                                                                          host=self.keydistObject.host)

            print 'testAuthThread: run(): executing: ' + ssh_cmd

            ssh = subprocess.Popen(ssh_cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,shell=True,universal_newlines=True)
            stdout, stderr = ssh.communicate()
            ssh.wait()

            print 'testAuthThread: run(): stdout: ' + str(stdout)

            if 'success_testauth' in stdout:
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHSUCCESS,self.keydistObject)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
            else:
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_AUTHFAIL,self.keydistObject)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)


    class getPubkeyThread(Thread):
        def __init__(self,keydistObject):
            Thread.__init__(self)
            self.keydistObject = keydistObject

        def fingerprint(self):
            sshKeyGenCmd = sshKeyGenBinary + " -l -f " + double_quote(self.keydistObject.sshKeyPath) + ".pub"
            fp = subprocess.Popen(sshKeyGenCmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,shell=True,universal_newlines=True)
            stdout = fp.stdout.readlines()
            fp.wait()
            for line in stdout:
                match = re.search("^[0-9]+\ (\S*)\ (.+)$",line)
                if match:
                    fp = match.group(1)
                    comment = match.group(2)
            return fp,comment

        def loadKey(self):
            print 'getPubkeyThread: loadKey():'

            nr_attempts = 1
            while True:
                print 'loadKey(): nr_attempts:', nr_attempts

                try:
                    args = [self.keydistObject.sshKeyPath]
                    print 'getPubkeyThread: loadKey(): running %s with args %s' % (str(sshAddBinary), str(args),)
                    lp = expect.spawn(sshAddBinary, args=args)

                    if (self.keydistObject.password != None and len(self.keydistObject.password) > 0):
                        print 'getPubkeyThread: loadKey(): got passphrase from keydistObject'
                        passphrase = self.keydistObject.password
                    else:
                        print 'getPubkeyThread: loadKey(): using empty passphrase'
                        passphrase = ''
                    idx = lp.expect(["Identity added",".*pass.*"])

                    if (idx == 1):
                        print 'getPubkeyThread: loadKey(): sending passphrase to ssh-agent'
                        lp.send(passphrase + newline)

                        idx = lp.expect(["Identity added","Bad pass",expect.EOF])

                        if (idx == 0):
                            print 'getPubkeyThread: loadKey(): got "Identity added"; posting the EVT_KEYDIST_LISTFINGERPRINTS event'
                            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LISTFINGERPRINTS,self.keydistObject)
                        elif (idx == 1):
                            print 'getPubkeyThread: loadKey(): got "Bad pass"'
                            if (passphrase == ""):
                                print 'getPubkeyThread: loadKey(): empty passphrase, so posting the EVT_KEYDIST_KEY_LOCKED event'
                                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED,self.keydistObject)
                            else:
                                print 'getPubkeyThread: loadKey(): non-empty passphrase, so posting the EVT_KEYDIST_KEY_WRONGPASS event'
                                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_WRONGPASS,self.keydistObject)
                        else:
                            print 'getPubkeyThread: loadKey(): got EOF (?) from ssh-add, so posting the EVT_KEYDIST_KEY_LOCKED event'
                            newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED,self.keydistObject)
                    else:
                        print 'getPubkeyThread: loadKey(): got "Identity added" from ssh-add, so sending the EVT_KEYDIST_KEY_LOCKED event'
                        newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_KEY_LOCKED,self.keydistObject)

                    wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
                    lp.close()
                    print 'getPubkeyThread: loadKey(): exiting'
                    break
                except Exception as e:
                    print 'loadKey(): exception: ' + str(e)
                    nr_attempts += 1

        def run(self):
            try:
                f = open(sshKeyPath+".pub",'r')
                f.close()
                self.keydistObject.sshKeyPath = sshKeyPath
                fp,comment = self.fingerprint()
                self.keydistObject.pubkeyfp = fp
                self.keydistObject.pubkeyComment = comment
                self.keydistObject.fplock.acquire()
                if (fp not in self.keydistObject.fingerprints):
                    self.loadKey()
                else:
                    newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_LISTFINGERPRINTS,self.keydistObject)
                    wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)
                self.keydistObject.fplock.release()

            except IOError:
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEWPASS_REQ,self.keydistObject)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),newevent)


    class CopyIDThread(Thread):
        def __init__(self,keydist):
            Thread.__init__(self)
            self.keydistObject = keydist

        def run(self):
            sshClient = ssh.SSHClient()
            sshClient.set_missing_host_key_policy(ssh.AutoAddPolicy())
            try:
                sshClient.connect(hostname=self.keydistObject.host,username=self.keydistObject.username,password=self.keydistObject.password,allow_agent=False,look_for_keys=False)
                stdin,stdout,stderr = sshClient.exec_command("mktemp")
                tmpfile = stdout.read()
                tmpfile = tmpfile.rstrip()
                if (stderr.read() != ""):
                    raise Exception
                sftp = sshClient.open_sftp()
                sftp.put(self.keydistObject.sshKeyPath+".pub",tmpfile)
                sftp.close()

                sshClient.exec_command("module load massive")
                sshClient.exec_command("/bin/mkdir -p ~/.ssh")
                sshClient.exec_command("/bin/chmod 700 ~/.ssh")
                sshClient.exec_command("/bin/touch ~/.ssh/authorized_keys")
                sshClient.exec_command("/bin/chmod 600 ~/.ssh/authorized_keys")
                sshClient.exec_command("/bin/cat %s >> ~/.ssh/authorized_keys"%tmpfile)
                sshClient.exec_command("/bin/rm -f %s"%tmpfile)
                sshClient.close()
                print "copy id generating test auth afer success"
                self.keydistObject.keycopiedLock.acquire()
                self.keydistObject.keycopied=True
                self.keydistObject.keycopiedLock.release()
                event = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_TESTAUTH,self.keydistObject)
                wx.PostEvent(self.keydistObject.notifywindow.GetEventHandler(),event)
            except ssh.AuthenticationException as e:
                string = "%s"%e
                print "copy id thread, NEEDPASS"
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
        def copyid_complete(event):
            if (event.GetId() == KeyDist.EVT_COPYID_COMPLETE):
                event.keydist.completedLock.acquire()
                event.keydist.completed = True
                event.keydist.completedLock.release()
            event.Skip()

        def copyid_fail(event):
            if (event.GetId() == KeyDist.EVT_COPYID_FAIL):
                event.keydist.copyid(event.string)
            event.Skip()

        def test_authorised(event):
            if (event.GetId() == KeyDist.EVT_NOTAUTHORISED):
                event.keydist.copyid()
            event.Skip()

        def loadkey(event):
            if (event.GetId() == KeyDist.EVT_LOADKEY_REQ):
                event.keydist.loadKey()
            else:
                event.Skip()


        def newkey(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEWPASS_REQ):
                wx.CallAfter(event.keydist.getNewPassphrase_stage1,event.string)
            if (event.GetId() == KeyDist.EVT_KEYDIST_NEWPASS_RPT):
                print "received NEWPASS_RPT"
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
                print "creating CopyID Thread"
                event.keydist.workThread = KeyDist.CopyIDThread(event.keydist)
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

        def listfingerprints(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_LISTFINGERPRINTS):
                try:
                    if (event.keydist.workThread != None):
                        event.keydist.workThread.join()
                except RuntimeError:
                    pass
                event.keydist.workThread = KeyDist.listFingerprintsThread(event.keydist)
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


        def authfail(event):
            if (event.GetId() == KeyDist.EVT_KEYDIST_AUTHFAIL):
                if(not event.keydist.pubkeyloaded):
                    try:
                        if (event.keydist.workThread != None):
                            event.keydist.workThread.join()
                    except RuntimeError:
                        pass
                    event.keydist.workThread = KeyDist.getPubkeyThread(event.keydist)
                    event.keydist.workThread.start()
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
                newevent = KeyDist.sshKeyDistEvent(KeyDist.EVT_KEYDIST_NEEDAGENT,event.keydist)
                wx.PostEvent(event.keydist.notifywindow.GetEventHandler(),newevent)
            else:
                event.Skip()

    myEVT_CUSTOM_SSHKEYDIST=None
    EVT_CUSTOM_SSHKEYDIST=None
    def __init__(self,username,host,notifywindow):
        KeyDist.myEVT_CUSTOM_SSHKEYDIST=wx.NewEventType()
        KeyDist.EVT_CUSTOM_SSHKEYDIST=wx.PyEventBinder(self.myEVT_CUSTOM_SSHKEYDIST,1)
        KeyDist.EVT_KEYDIST_START = wx.NewId()
        KeyDist.EVT_KEYDIST_CANCEL = wx.NewId()
        KeyDist.EVT_KEYDIST_SUCCESS = wx.NewId()
        KeyDist.EVT_KEYDIST_NEEDAGENT = wx.NewId()
        KeyDist.EVT_KEYDIST_NEEDKEYS = wx.NewId()
        KeyDist.EVT_KEYDIST_LISTFINGERPRINTS = wx.NewId()
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

        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.cancel)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.success)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.needagent)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.listfingerprints)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.testauth)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.authfail)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.startevent)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.newkey)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.copyid)
        notifywindow.Bind(self.EVT_CUSTOM_SSHKEYDIST, KeyDist.sshKeyDistEvent.keylocked)

        self.completed=False
        self.username = username
        self.host = host
        self.notifywindow = notifywindow
        self.sshKeyPath = ""
        self.workThread = None
        self.pubkey = None
        self.pubkeyfp = None
        self.pubkeyloaded = False
        self.password = None
        self.fplock = Lock()
        self.completedLock = Lock()
        self.keycopiedLock=Lock()
        self.keycopied=False


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
        self.sshKeyPath = sshKeyPath
        event = KeyDist.sshKeyDistEvent(self.EVT_KEYDIST_START, self)
        wx.PostEvent(self.notifywindow.GetEventHandler(), event)
