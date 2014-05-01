import wx
class genericCopyID():

    def __init__(self,pubkey,username,host,displayStrings,parent,progressDialog,authorizedKeysFile=None,*args,**kwargs):
        self.username=username
        self.host=host
        self.displayStrings=displayStrings
        self.pubkey=pubkey
        self.parent=parent
        self.progressDialog=progressDialog
        self.authorizedKeysFile=authorizedKeysFile
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

    def copyID(self):

        import ssh
        import Queue
        sshClient = ssh.SSHClient()
        sshClient.set_missing_host_key_policy(ssh.AutoAddPolicy())
        password=""
        notConnected=True
        while notConnected:
            queue=Queue.Queue()
            try:
                sshClient.connect(hostname=self.host,timeout=10,username=self.username,password=password,allow_agent=False,look_for_keys=False)
                notConnected=False
            except ssh.AuthenticationException:
                wx.CallAfter(self.getPass,queue)
                password=queue.get()
                if password==None:
                    raise Exception("Login Canceled")

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
        (stdin,stdout,stderr)=sshClient.exec_command("/bin/echo \"%s\" >> %s"%(self.pubkey,self.authorizedKeysFile))
        err=stderr.readlines()
        if err!=[]:
            raise Exception('The program was unable to write a file in your home directory. This might be because you have exceeded your disk quota. You should log in manually and clean up some files if this is the case')
        sshClient.close()


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
