from twisted.internet import task
from twisted.internet import threads
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.python import syslog
from twisted.python.log import msg
from twisted.python.log import err

# For CallBack commands encoding/decoding
import simplejson

from sippy.UA import UA

# generation CallID
import string
from random import choice

global_config = {}

class IpportCallback(protocol.Protocol):
	def dataReceived(self, data):
		msg("[IpportCallback:dataReceived] received: %s" % data)
		d = threads.deferToThread(self.process, data)
		d.addErrback(self.processFailed)
		d.addCallback(self.processDone)

	def process(self, data):
		# process data
		msg("[IpportCallback:process]")
		Cmd = json.loads(data)
		CallController(self, Cmd)

	def processFailed(self, error):
		# return error
		msg("processFailed: %s" % str(error))
		self.transport.write("error")
		self.transport.loseConnection()

	def processDone(self, result):
		# return Call-ID
		msg("processDone")
		self.transport.write("result")
		self.transport.loseConnection()

class CallController:
	ua0 = None
	ua1 = None
	user = None
	number0 = None
	number1 = None
	callid = None
	sdp = ""
	auth = None
	parent = None

	def __init__(self, _parent, cmd):
		msg('CallController::__init__')
		self.user = cmd['id']
		self.number0 = cmd['number']
		self.number1 = cmd['callbacknumber']
		self.parent = _parent

		# Generate unique Call-ID
		chars = string.letters + string.digits
		for i in range(64):
			self.callid += choice(chars)

		self.ua0 = UA(
				global_config,
				event_cb = self.recvEvent,
				conn_cbs = (self.recvConnect,),
				disc_cbs = (self.recvDisconnect,),
				fail_cbs = (self.recvDisconnect,),
				dead_cbs = (self.recvDead,),
				nh_address = (global_config['proxy_address'], global_config['proxy_port'])
			)
		self.ua0.recvEvent(CCEventTry((self.callid + "-leg0", "cGIUD", self.user, self.number0, self.sdp, self.auth, "Callback")))

	def recvConnect(self, ua, rtime, origin):
		if ua == self.ua0:
			# Fix SDP here
			self.ua1 = UA(
					global_config,
					event_cb = self.recvEvent,
					conn_cbs = (self.recvConnect,),
					disc_cbs = (self.recvDisconnect,),
					fail_cbs = (self.recvDisconnect,),
					dead_cbs = (self.recvDead,),
					nh_address = (global_config['proxy_address'], global_config['proxy_port'])
				)
			self.ua1.recvEvent(CCEventTry((self.callid + "-leg1", "cGIUD", self.user, self.number1, self.sdp, self.auth, "Callback")))
		else:
			# Both parties are connected NOW - we must notify self.parent here
			pass

	def recvDisconnect(self, ua, rtime, origin, result = 0):
		pass

	def recvDead(self, ua):
		# Failure - we must notify self.parent here and clean up stuff
		pass

	def recvEvent(self, event, ua):
		# Don't think that they need to incerconnect at all, however we should notify parent
		pass

def recvRequest(req):
	# Empty
	pass

if __name__ == '__main__':
	syslog.startLogging('callback')

	global_config['proxy_address'] = "213.248.23.169"
	global_config['proxy_port'] = 5060
	global_config['sip_address'] = "213.248.12.116"
	global_config['sip_port'] = 5070
	global_config['sip_tm'] = SipTransactionManager(global_config, recvRequest)

	factory = protocol.ServerFactory()
	factory.protocol = IpportCallback
	reactor.listenTCP(8000,factory)

	reactor.run(installSignalHandlers = 0)
