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

from application.configuration import *

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
		cc = CallController(Cmd)
		Cmd['result'] = "ok"
		Cmd['callid'] = cc.callid + "_cb_0_b2b_0"
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
	ua = [None, None]
	user = None
	numbers = None
	callid = None
	sdp = None
	auth = None

	def __init__(self, cmd):
		msg('CallController::__init__')

		self.numbers = cmd['callbacknumber'], cmd['number']

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
		self.ua_gen_invite(0)

	def ua_gen_invite(self, num):
		self.ua[num] = UA(
				global_config,
				event_cb = self.recvEvent,
				conn_cbs = (self.recvConnect,),
				disc_cbs = (self.recvDisconnect,),
				fail_cbs = (self.recvDisconnect,),
				dead_cbs = (self.recvDead,),
				nh_address = (global_config['proxy_address'], global_config['proxy_port'])
			)
		self.ua[num].rTarget = SipURL(url = "sip:" + self.numbers[num] + "@" + global_config['proxy_address'])
		self.ua[num].rUri = SipTo(body = "<sip:" + self.numbers[num] + "@" + global_config['proxy_address'] + ">")
		self.ua[num].lUri = self.user
		self.ua[num].lContact = SipContact(body = "<sip:callback@" + global_config['proxy_address'] + ">")
		self.ua[num].routes = ()
		self.ua[num].lCSeq = 1
		self.ua[num].rCSeq = 1
		self.ua[num].cId = SipCallId(self.callid + "_cb_%d" % num)
		req = self.ua[num].genRequest("INVITE", self.sdp)
		self.ua[num].changeState((UacStateTrying,))
		global_config['sip_tm'].regConsumer(self.ua[num], str(self.ua[num].cId))
		self.ua[num].tr = global_config['sip_tm'].newTransaction(req, self.ua[num].recvResponse)

	def recvConnect(self, ua, rtime, origin):
		msg("recvConnect")
		if ua == self.ua[0]:
			self.sdp = MsgBody(str(self.ua[0].rSDP) + "a=nortpproxy:yes\r\n")
			self.ua_gen_invite(1)

	def recvDisconnect(self, ua, rtime, origin, result = 0):
		Ret = (lambda x: ((x == self.ua[0]) and (0,1)) or ((x == self.ua[1]) and (1,0)))(ua)
		if Ret:
			msg("recvDisconnect from %d" % Ret[0])
			self.ua[Ret[0]] = None
			if self.ua[Ret[1]] != None:
				self.ua[Ret[1]].lCSeq += 1
				self.ua[Ret[1]].rCSeq += 1
				self.ua[Ret[1]].recvEvent(CCEventDisconnect())

	def recvDead(self, ua):
		msg("recvDead")
		# Failure - clean up stuff here
		ua.event_cb = None
		ua.conn_cbs = None
		ua.disc_cbs = None
		ua.fail_cbs = None
		ua.dead_cbs = None

	def recvEvent(self, event, ua):
		msg("recvEvent")
		# Don't think that they need to incerconnect at all
		pass

def recvRequest(req):
	pass

if __name__ == '__main__':
	syslog.startLogging('callback')

	# Get config file
	configuration = ConfigFile('/etc/callback/config.ini')

	global_config['proxy_address'] = configuration.get_setting('General', 'paddr', default='127.0.0.1', type=str)
	global_config['proxy_port'] = configuration.get_setting('General', 'pport', default=5060, type=int)
	global_config['sip_address'] = configuration.get_setting('General', 'laddr', default='127.0.0.1', type=str)
	global_config['sip_port'] = configuration.get_setting('General', 'lport', default=5060, type=int)
	global_config['sip_username'] = configuration.get_setting('General', 'username', default='username', type=str)
	global_config['sip_password'] = configuration.get_setting('General', 'password', default='password', type=str)
	global_config['sip_tm'] = SipTransactionManager(global_config, recvRequest)

	factory = protocol.ServerFactory()
	factory.protocol = IpportCallback
	reactor.listenTCP(8000,factory)

	reactor.run(installSignalHandlers = 0)
