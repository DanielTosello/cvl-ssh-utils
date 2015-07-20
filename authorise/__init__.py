import passwordAuth
import aaf
import sftpAuth
import boto
import ASyncAuthorise
import ec2
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
        if copymethod=='ASyncAuth':
            return ASyncAuthorise.ASyncAuthorise(*args,**kwargs)
    factory=staticmethod(factory)

