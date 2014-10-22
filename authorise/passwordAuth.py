import wx
class passwordAuth():

    def __init__(self,displayStrings,parent,progressDialog,keydistObject,authorizedKeysFile=None,*args,**kwargs):
        self.displayStrings=displayStrings
        self.pubkey=None
        self.username=None
        self.host=None
        self.parent=parent
        self.progressDialog=progressDialog
        self.authorizedKeysFile=authorizedKeysFile
        self.keydistObject=keydistObject
        if self.authorizedKeysFile==None:
            self.authorizedKeysFile="~/.ssh/authorized_keys"

    def getPass(self,queue):
        dlg=wx.PasswordEntryDialog(self.parent,self.displayStrings.passwdPrompt)
        if self.progressDialog is not None:
            self.progressDialog.Hide()
        retval=dlg.ShowModal()
        if self.progressDialog is not None:
            self.progressDialog.Show()
        if retval==wx.ID_OK:
            queue.put(dlg.GetValue())
        else:
            queue.put(None)
        dlg.Destroy()

    def copyID(self,keyModel,username=None,host=None):
        if username!=None:
            self.username=username
        if host!=None:
            self.host=host
        if self.username==None:
            raise Exception("I don't know what username you are trying to log in with")
        import sys
        self.keyModel=keyModel
        self.pubkey=self.keyModel.getPubKey()

        try:
            import ssh
        except:
            import paramiko as ssh
        import Queue
        sshClient = ssh.SSHClient()
        sshClient.set_missing_host_key_policy(ssh.AutoAddPolicy())
        passwd=""
        notConnected=True
        while notConnected:
            queue=Queue.Queue()
            try:
                sshClient.connect(hostname=self.host,timeout=10,username=self.username,password=passwd,allow_agent=False,look_for_keys=False)
                notConnected=False
            except ssh.AuthenticationException:
                wx.CallAfter(self.getPass,queue)
                passwd=queue.get()
                if passwd==None:
                    raise Exception("Login Canceled")
            except Exception as e:
                import traceback
                raise e


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

        (stdin,stdout,stderr)=sshClient.exec_command("module load massive")
        err=stderr.readlines()
        if err!=[]:
            pass
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/mkdir -p ~/.ssh")
        err=stderr.readlines()
        if err!=[]:
            raise Exception
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/chmod 700 ~/.ssh")
        err=stderr.readlines()
        if err!=[]:
            raise Exception
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/touch %s"%(self.authorizedKeysFile))
        err=stderr.readlines()
        if err!=[]:
            raise Exception
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/chmod 600 %s"%(self.authorizedKeysFile))
        err=stderr.readlines()
        if err!=[]:
            raise Exception
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/echo \"%s\" >> %s"%(self.pubkey.strip(),self.authorizedKeysFile))
        err=stderr.readlines()
        if err!=[]:
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

            try:
                import ssh
            except:
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

    def testAuth(self,keyModel,username=None,host=None):
        if username!=None:
            self.username=username
        if host!=None:
            self.host=host
        if self.username==None:
            raise Exception("I don't know what username you are tring to login with")
        from logger.Logger import logger
        logger.debug("in passwordAuth.textAuth")
        import tempfile
        import sys
        from logger.Logger import logger
        import subprocess
        fd=tempfile.NamedTemporaryFile(delete=True)
        path=fd.name
        fd.close()

        auth=False
        try:
        
            ssh_cmd = ['{sshbinary}','-o','ConnectTimeout=10','-o','IdentityFile="{nonexistantpath}"','-o','PasswordAuthentication=no','-o','ChallengeResponseAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','PubkeyAuthentication=yes','-o','StrictHostKeyChecking=no','-l','{login}','{host}','echo','"success_testauth"']
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

            logger.debug("passwordAuth.testAuth: stdout of ssh command: " + str(stdout))
            logger.debug("passwordAuth.testAuth: stderr of ssh command: " + str(stderr))


            if 'Could not resolve hostname' in stdout:
                logger.debug('Network error.')
                auth=False
            elif 'success_testauth' in stdout:
                logger.debug("passwordAuth.testAuth: got success_testauth in stdout :)")
                auth=True
            elif 'Agent admitted' in stdout:
                logger.debug("passwordAuth.testAuth: the ssh agent has an error. Try rebooting the computer")
                self.keydistObject.cancel("Sorry, there is a problem with the SSH agent.\nThis sort of thing usually occurs if you delete your key and create a new one.\nThe easiest solution is to reboot your computer and try again.")
                return
            else:
                logger.debug("passwordAuth.testAuth: did not see success_testauth in stdout, posting EVT_KEYDIST_AUTHFAIL event")
                auth=False
        except Exception as e:
            import traceback
            logger.debug("passwordAuth.testAuth raised an exception %s"%e)
            logger.debug(traceback.format_exc())
            raise e

        return auth
