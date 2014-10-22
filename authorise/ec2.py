import wx
class ec2():

    def __init__(self,displayStrings,parent,progressDialog,ec2_access_key,ec2_connection,*args,**kwargs):
        self.displayStrings=displayStrings
        self.pubkey=None
        self.parent=parent
        self.progressDialog=progressDialog
        self.ec2_access_key=ec2_access_key
        self.ec2_connection=ec2_connection
        

    def copyID(self,keyModel=None,username=None):
        self.keyModel=keyModel
        keyname="MassiveLauncherKey_%s"%self.ec2_connection.access_key
        fp=self.keyModel.getFingerprint()
        if fp==None:
            raise Exception("copyID was called before the keyModel loaded the key (the fingerprint was None). Look for a bug in sshKeyDist")
        keypairs=self.ec2_connection.get_all_key_pairs()
        for k in keypairs:
            if k.name==keyname:
                self.ec2_connection.delete_key_pair(k.name)
        pubkey=self.keyModel.getPubKey()
        self.ec2_connection.import_key_pair(keyname,pubkey)



    def deleteRemoteKey(self):
        from logger.Logger import logger
        import traceback
        keyname="MassiveLauncherKey_%s"%self.ec2_connection.access_key
        self.ec2_connection.delete_key_pair(keyname)
        logger.debug("deleting keys from the ec2 api is not implemented")

    def testAuth(self,keyModel,username=None):
        
            if self.keyModel==None:
                self.keyModel=keyModel
            fp=self.keyModel.getFingerprint()
            if fp==None: # This probably indicates we are attempting to testAuth before loading the key into the sshAgent
                         # This occurs for regular hosts because the first thing we ever do is see if we can log in without passwords
                         # only if we can't login without passwords do we start creating and loading keys
                return False

            keypairs=self.ec2_connection.get_all_key_pairs()
            for k in keypairs:
                if k.fingerprint==fp:
                    return True
            return False
