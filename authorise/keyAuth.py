import wx
class keyAuth(object):

    def __init__(self,displayStrings,parent,progressDialog,keydistObject,authorizedKeysFile=None,onFirstLogin=None,*args,**kwargs):
        self.displayStrings=displayStrings
        self.pubkey=None
        self.username=None
        self.host=None
        self.parent=parent
        self.progressDialog=progressDialog
        self.authorizedKeysFile=authorizedKeysFile
        self.keydistObject=keydistObject
        self.onFirstLogin=onFirstLogin
        if self.authorizedKeysFile==None:
            self.authorizedKeysFile="~/.ssh/authorized_keys"

    def informUser(self,queue,keyModel):

        if keyModel.temporaryKey:
            pubkey = keyModel.getPubKey()
            infoText = "Connecting to " + self.host + " with SSH failed.\n" + \
                              "A temporary SSH-keypair has been generated, which is not known to " + self.host +",yet.\n" + \
                              "Please add the following public key to '~/.ssh/authorized_keys'  on " + self.host + ":\n\n" + \
                               repr(pubkey) + "\n\n"
        else:
            infoText = "Connecting to " + self.host + " with SSH failed.\n" + \
                              "Three major reasons can cause this error:\n\n" + \
                              "a) No SSH agent is running on your local machine:\n" + \
                              "Check 'ssh-add -l' on Linux/OSX or check if Putty's Pagent is running on Windows.\n\n" + \
                              "b) You have no SSH-keypair loaded in your SSH agent:\n" + \
                              "Check 'ssh-add -l' on Linux/OSX or check SSH-keypairs loaded by Putty's Pagent on Windows.\n\n" + \
                              "c) No SSH-keypair loaded by SSH agent is known on " +  self.host + ":\n" + \
                              "Check if the public key of any loaded SSH-keypair can be found in '~/.ssh/authorized_keys'  on " + self.host + ".\n\n" + \
                              "Make sure you can login to " + self.host +" with the username '" + self.username + "' without being asked for any passphrase or password. " 

        dlg = wx.MessageDialog(None, infoText +
                                                 "You may also have a SSH-keypair manager running, which might add keypairs just in this moment.\n\n"  + \
                                                 "Shall we retry to connect again?",                                          
                                                 "Failed to connect to " + self.host,  wx.YES_NO | wx.NO_DEFAULT | wx.ICON_INFORMATION);
        if self.progressDialog is not None:
            self.progressDialog.Hide()
        retval=dlg.ShowModal()
        if self.progressDialog is not None:
            self.progressDialog.Show()
        if retval==wx.ID_YES:
            queue.put('try again')
        else:
            queue.put(None)
        dlg.Destroy()

    def copyID(self,keyModel,username=None,host=None):
        from logger.Logger import logger
        logger.debug("in key auth, copyID")
        if username!=None:
            self.username=username
        if host!=None:
            self.host=host
        if self.username==None:
            raise Exception("I don't know what username you are trying to log in with")
        import sys
        self.keyModel=keyModel
        self.pubkey=self.keyModel.getPubKey()

        import paramiko as ssh
        import Queue
        logger.debug("in key auth, copyID, creating ssh client")
        sshClient = ssh.SSHClient()
        sshClient.set_missing_host_key_policy(ssh.AutoAddPolicy())
        notConnected=True
        while notConnected:
            queue=Queue.Queue()
            try:
                sshClient.connect(hostname=self.host,timeout=10,username=self.username,password=None,allow_agent=True,look_for_keys=True)
                notConnected=False
                
                logger.debug("in key auth, copyID, Authentication Exception")
                wx.CallAfter(self.informUser,queue,self.keyModel)
                answ=queue.get()
                if answ==None:
                    raise Exception("Login Canceled")                
                
            except ssh.AuthenticationException:
                logger.debug("in key auth, copyID, Authentication Exception")
                wx.CallAfter(self.informUser,queue,self.keyModel)
                answ=queue.get()
                if answ==None:
                    raise Exception("Login Canceled")
            except Exception as e:
                import traceback
                raise e

        logger.debug("in key auth, copyID, connected")

        if self.onFirstLogin!=None:
            (stdin,stdout,stderr)=sshClient.exec_command(self.onFirstLogin)
            err=stderr.readlines()
            if err!=[]:
                logger.debug("copy id saw the error message %s"%err)
                raise Exception(self.displayStrings.onFirstLoginFailure)


        # SSH keys won't work if the user's home directory is writeable by other users.
        writeableDirectoryErrorMessage = "" + \
            "Your home directory is writeable by users other than yourself. " + \
            "As a result, you won't be able to authenticate with SSH keys, so you can't use the Launcher. " + \
            "Please correct the permissions on your home directory, e.g.\n\n" + \
            "chmod 700 ~"
        (stdin,stdout,stderr)=sshClient.exec_command('ls -ld ~ | grep -q "^d....w" && echo HOME_DIRECTORY_WRITEABLE_BY_OTHER_USERS')
        err=stdout.readlines()
        if err!=[]:
            raise Exception(writeableDirectoryErrorMessage)
        (stdin,stdout,stderr)=sshClient.exec_command('ls -ld ~ | grep -q "^d.......w" && echo HOME_DIRECTORY_WRITEABLE_BY_OTHER_USERS')
        err=stdout.readlines()
        if err!=[]:
            raise Exception(writeableDirectoryErrorMessage)

        err=stderr.readlines()
        if err!=[]:
            pass
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/mkdir -p ~/.ssh")
        err=stderr.readlines()
        if err!=[]:
            pass
            #raise Exception(err)
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/chmod 700 ~/.ssh")
        err=stderr.readlines()
        if err!=[]:
            pass
            #raise Exception
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/touch %s"%(self.authorizedKeysFile))
        err=stderr.readlines()
        if err!=[]:
            pass
            #raise Exception
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/chmod 600 %s"%(self.authorizedKeysFile))
        err=stderr.readlines()
        if err!=[]:
            pass
            #raise Exception
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/echo \"%s\" >> %s"%(self.pubkey.strip(),self.authorizedKeysFile))
        err=stderr.readlines()
        if err!=[]:
            pass
            raise Exception('The program was unable to write a file in your home directory. This might be because you have exceeded your disk quota. You should log in manually and clean up some files if this is the case')
        sshClient.close()


    def deleteRemoteKey(self):
        from logger.Logger import logger
        import traceback
        if self.pubkey!=None:

            try:
                key=self.pubkey.split(' ')[1]
            except:
                key=self.pubkey

            import paramiko as ssh
            sshClient = ssh.SSHClient()
            sshClient.set_missing_host_key_policy(ssh.AutoAddPolicy())
            try:
                sshClient.connect(hostname=self.host,timeout=10,username=self.username,password=None,allow_agent=True,look_for_keys=False)
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

    def testAuth(self,keyModel,username=None,host=None,timeout=10):
        if username!=None:
            self.username=username
        if host!=None:
            self.host=host
        if self.username==None:
            raise Exception("I don't know what username you are trying to login with")
        from logger.Logger import logger
        logger.debug("in keyAuth.testAuth")
        import tempfile
        import sys
        from logger.Logger import logger
        import subprocess
        fd=tempfile.NamedTemporaryFile(delete=True)
        path=fd.name
        fd.close()

        auth=False
        try:
        
            ssh_cmd = ['{sshbinary}','-o','ConnectTimeout=%s'%timeout,'-o','IdentityFile="{nonexistantpath}"','-o','PasswordAuthentication=no','-o','ChallengeResponseAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','PubkeyAuthentication=yes','-o','StrictHostKeyChecking=no','-l','{login}','{host}','echo','"success_testauth"']
            cmd=[]
            for s in ssh_cmd:
                cmd.append(s.format(sshbinary=self.keydistObject.keyModel.sshpaths.sshBinary,login=self.username, host=self.host, nonexistantpath=path))
            logger.debug('testAuthThread: attempting: %s'%cmd)
            if sys.platform.startswith("win"):
                ssh = subprocess.Popen(" ".join(cmd),shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True, startupinfo=self.keydistObject.startupinfo, creationflags=self.keydistObject.creationflags)
            else:
                ssh = subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True, startupinfo=self.keydistObject.startupinfo, creationflags=self.keydistObject.creationflags)
            stdout, stderr = ssh.communicate()
            ssh.wait()

            logger.debug("keyAuth.testAuth: stdout of ssh command: " + str(stdout))
            logger.debug("keyAuth.testAuth: stderr of ssh command: " + str(stderr))


            if 'Could not resolve hostname' in stdout:
                logger.debug('Network error.')
                auth=False
            elif 'success_testauth' in stdout:
                logger.debug("keyAuth.testAuth: got success_testauth in stdout :)")
                auth=True
            elif 'Agent admitted' in stdout:
                logger.debug("keyAuth.testAuth: the ssh agent has an error. Try rebooting the computer")
                self.keydistObject.cancel("Sorry, there is a problem with the SSH agent.\nThis sort of thing usually occurs if you delete your key and create a new one.\nThe easiest solution is to reboot your computer and try again.")
                return
            else:
                logger.debug("keyAuth.testAuth: did not see success_testauth in stdout, posting EVT_KEYDIST_AUTHFAIL event")
                auth=False
        except Exception as e:
            import traceback
            logger.debug("keyAuth.testAuth raised an exception %s"%e)
            logger.debug(traceback.format_exc())
            raise e

        return auth
