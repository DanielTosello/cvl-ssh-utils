import passwordAuth
import aaf
import sftpAuth
import boto
class authorise(object):
    def factory(copymethod,*args,**kwargs):
        if copymethod=='passwordAuth':
            return passwordAuth.passwordAuth(*args,**kwargs)
        if copymethod=='aaf':
            return aaf.aaf(*args,**kwargs)
        if copymethod=='ec2':
            return ec2.ec2(*args,**kwargs)
        if copymethod=='sftpAuth':
            return sftpAuth.passwordAuth(*args,**kwargs)
    factory=staticmethod(factory)

