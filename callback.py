from twisted.internet import reactor
from twisted.internet import protocol
from twisted.python import syslog
from twisted.python.log import msg
from twisted.python.log import err

# For CallBack commands encoding/decoding
import simplejson

class IpportCallback(protocol.Protocol):
	def dataReceived(self, data):
		msg('CallBack received: %s' % data)
		d = threads.deferToThread(self.process, data)
		d.addErrback(self.processFailed)
		d.addCallback(self.processDone)

	def connect(self, data):
		Cmd = {}
		try:
			# process data
			Cmd = json.loads(data)
			# create CallController
		except:
			pass
		pass

	def processFailed(self, error):
		# return error
		self.transport.write(error)
		self.transport.loseConnection()

	def processDone(self, result):
		# return Call-ID
		self.transport.write(result)
		self.transport.loseConnection()

if __name__ == '__main__':
	syslog.startLogging('callback')

	factory = protocol.ServerFactory()
	factory.protocol = IpportCallback
	reactor.listenTCP(8000,factory)

	reactor.run(installSignalHandlers = 0)
