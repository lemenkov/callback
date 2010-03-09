from twisted.internet import task
from twisted.internet import threads
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.python import syslog
from twisted.python.log import msg
from twisted.python.log import err

# For CallBack commands encoding/decoding
import simplejson

from sippy.CCEvents import *
from sippy.UA import UA
from sippy.SipAuthorization import SipAuthorization
from sippy.SipCallId import SipCallId
from sippy.SipFrom import SipFrom
from sippy.SipTo import SipTo
from sippy.SipTransactionManager import SipTransactionManager
from sippy.MsgBody import MsgBody
from sippy.SipURL import SipURL
from sippy.SipContact import SipContact
from sippy.UacStateTrying import UacStateTrying
from sippy.CCEvents import *

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
		Cmd = simplejson.loads(data)
		cc = CallController(self, Cmd)
		Cmd['result'] = "ok"
		Cmd['callid'] = cc.callid
		return simplejson.dumps(Cmd)

	def processFailed(self, error):
		# return error
		msg("processFailed: %s" % str(error))
		self.transport.write("error")
		self.transport.loseConnection()

	def processDone(self, result):
		# return Call-ID
		msg("processDone: %s" % str(result) )
		self.transport.write(result)
		self.transport.loseConnection()

class CallController:
	ua0 = None
	ua1 = None
	user = None
	numbers = ()
	callid = None
	sdp = None
	auth = None
	parent = None

	def __init__(self, _parent, cmd):
		msg('CallController::__init__')

		self.numbers = cmd['callbacknumber'], cmd['number']
		self.parent = _parent

		# Generate unique Call-ID
		self.callid = str(SipCallId())

		# Generate constant From address
		self.user = SipFrom(body = "\"Callback\" <sip:" + cmd['id'] + "@" + global_config['proxy_address'] + ">")
		self.user.parse()
		self.user.genTag()

		# Generate SDP (should be updated after first call will be established
		# Fixme autogenerate SDP instead of hardcoding it
		self.sdp = MsgBody("v=0\r\no=sippy 401810075 652132971 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 18012 RTP/AVP 8 0 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\n")

		# FIXME add auth
#		self.auth = SipAuthorization()

		self.ua0 = UA(
				global_config,
				event_cb = self.recvEvent,
				conn_cbs = (self.recvConnect,),
				disc_cbs = (self.recvDisconnect,),
				fail_cbs = (self.recvDisconnect,),
				dead_cbs = (self.recvDead,),
				nh_address = (global_config['proxy_address'], global_config['proxy_port'])
			)
		self.ua0.rTarget = SipURL(url = "sip:" + self.numbers[0] + "@" + global_config['proxy_address'])
		self.ua0.rUri = SipTo(body = "<sip:" + self.numbers[0] + "@" + global_config['proxy_address'] + ">")
		self.ua0.lUri = self.user
		self.ua0.lContact = SipContact(body = "<sip:callback@" + global_config['proxy_address'] + ">")
		self.ua0.routes = ()
		self.ua0.lCSeq = 1
		self.ua0.rCSeq = 1
		self.ua0.cId = SipCallId(self.callid + "_cb_0")
		req = self.ua0.genRequest("INVITE", self.sdp)
		self.ua0.changeState((UacStateTrying,))
		global_config['sip_tm'].regConsumer(self.ua0, str(self.ua0.cId))
		msg("REQ0: %s" % str(req))
		self.ua0.tr = global_config['sip_tm'].newTransaction(req, self.ua0.recvResponse)
		print "TRAN0 ==", self.ua0.tr, self.ua0.recvResponse

	def recvConnect(self, ua, rtime, origin):
		msg("recvConnect")
		if ua == self.ua0:
			self.sdp = MsgBody(str(self.ua0.rSDP) + "a=nortpproxy:yes\r\n")
			# FIXME we should notify parent about 1st leg connected
			self.ua1 = UA(
					global_config,
					event_cb = self.recvEvent,
					conn_cbs = (self.recvConnect,),
					disc_cbs = (self.recvDisconnect,),
					fail_cbs = (self.recvDisconnect,),
					dead_cbs = (self.recvDead,),
					nh_address = (global_config['proxy_address'], global_config['proxy_port'])
				)
			self.ua1.rTarget = SipURL(url = "sip:" + self.numbers[1] + "@" + global_config['proxy_address'])
			self.ua1.rUri = SipTo(body = "<sip:" + self.numbers[1] + "@" + global_config['proxy_address'] + ">")
			self.ua1.lUri = self.user
			self.ua1.lContact = SipContact(body = "<sip:callback@" + global_config['proxy_address'] + ">")
			self.ua1.routes = ()
			self.ua1.lCSeq = 1
			self.ua1.rCSeq = 1
			self.ua1.cId = SipCallId(self.callid + "_cb_1")
			req = self.ua1.genRequest("INVITE", self.sdp)
			self.ua1.changeState((UacStateTrying,))
			global_config['sip_tm'].regConsumer(self.ua1, str(self.ua1.cId))
			msg("REQ1: %s" % str(req))
			self.ua1.tr = global_config['sip_tm'].newTransaction(req, self.ua1.recvResponse)
			print "TRAN1 ==", self.ua1.tr, self.ua0.recvResponse
		else:
			# FIXME we should notify parent about 1st and 2nd leg connected
			pass

	def recvDisconnect(self, ua, rtime, origin, result = 0):
		msg("recvDisconnect")
		if ua == self.ua0:
			self.ua0 = None
			if self.ua1 != None:
				self.ua1.lCSeq += 1
				self.ua1.rCSeq += 1
				self.ua1.recvEvent(CCEventDisconnect())
		if ua == self.ua1:
			self.ua1 = None
			if self.ua0 != None:
				self.ua0.lCSeq += 1
				self.ua0.rCSeq += 1
				self.ua0.recvEvent(CCEventDisconnect())
		pass

	def recvDead(self, ua):
		msg("recvDead")
		# Failure - we must notify self.parent here and clean up stuff
		pass

	def recvEvent(self, event, ua):
		msg("recvEvent")
		# Don't think that they need to incerconnect at all, however we should notify parent
		pass

def recvRequest(req):
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
