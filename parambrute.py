# This little Scanner extender plugin attempts to discover input parameters with a dictionary-based guessing
# especially useful when dealing with unknown pages discovered with active content discovery/dir listing

## TODO

## interesting cases with multiple parameters involved (or a 302,302,302,200,302,302 case, when 200 should have definitely brought our attention)
## interchange detection (in a draft, in the beginning it will be manual - can be included anytime)
## optimum request size detection (HTTP/1.1 414 Request-URI Too Long, 400 Bad request, or 4xx and 5xx in general) - in a draft, in the beginning will be manual
## blind param fuzzing (=1,=a,=')
## COOKIE support
## error detection
## automatic adjustment of preferred response comparison method (tagmap vs size)

try:
    import re
    import string
    import copy
    import os.path
    from string import Template
    from cgi import escape
    from javax.swing import JOptionPane
    from javax.swing import JPanel

    from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, IScanIssue
    import jarray
except ImportError:
    print "Failed to load dependencies."

FORCE_POST = False
MAX_URI = 8178
HIT_DETECTION='LEN' # change to 'TAG' for the tagmap instead of size - useful for pages returning content with different size (dynamic) - could be automated to detect this automatically; would be even better to port the response comparison mechanism from the Backslash-powered Scanner, much more reliable
DEBUG = True
VERSION = "0.1"

params_file='params.to.brute.txt'
base_resp_string=''
base_resp_print=''
callbacks = None
helpers = None
last_base_resp = None
first_run = True
brute_params = []
params_number=0
panel = JPanel()

def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''
    return helpers.bytesToString(bytes)

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers, params_number, brute_params, params_file, VERSION, panel
        callbacks = this_callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName("parambrute")

        callbacks.registerScannerCheck(ScannerChecks())
	if os.path.isfile(params_file) :
		with open(params_file) as f:
		    content = f.readlines()
		brute_params = [x.strip() for x in content] 

	params_number=len(brute_params)
	if params_number == 0:
		err_msg("Error: 0 params loaded! Probably the "+params_file+" does not exist or is empty! Aborting!")
	else:
	        print "Successfully loaded parambrute v" + VERSION
        return


class ScannerChecks(IScannerCheck):
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)
    def doActiveScan(self, basePair, insertionPoint):
	global first_run, base_resp_string, base_resp_print, last_base_resp
        base_resp_string = safe_bytes_to_string(basePair.getResponse())
        base_resp_print = tagmap(base_resp_string)
	issues = []
	if first_run == True or last_base_resp!=base_resp_string:
		if params_number>0:
			issues = self.doParamGuessScan(basePair, base_resp_string, base_resp_print)
			first_run = False
	last_base_resp=base_resp_string
        return issues
    def doPassiveScan(self, basePair):
        return []

    def doParamGuessScan(self, basePair, base_resp_string, base_resp_print):
	global HIT_DETECTION
        issues = []
        rawHeaders = helpers.analyzeRequest(basePair.getRequest()).getHeaders()

        # Parse the headers into a dictionary
        headers = dict((header.split(': ')[0].upper(), header.split(': ', 1)[1]) for header in rawHeaders[1:])

	# get cookies from cookie jar and update the Cookie header:
	cookies=callbacks.getCookieJarContents()
	domain = re.search('Host: (.+)', rawHeaders[1]).group(1)
	#print "Domain: "+domain
	scoped_cookies=[] # this will miss parent-domain scoped cookies
	for cookie in cookies:
		if cookie.domain==domain or (domain.endswith(cookie.domain) and cookie.domain.startswith('.')):
			#print domain+" cookie found:"
			#print cookie.name+"="+cookie.value
			if cookie.value.strip()!="":	# ignore empty cookies
				scoped_cookies.append(cookie.name+"="+cookie.value)
	for header in rawHeaders:
		if header.startswith('Cookie:'):
			cookie_header=';'.join(scoped_cookies)
			#print "Overwrote the header: "+cookie_header
			header="Cookie: "+cookie_header

        # prepare the attack
        request = safe_bytes_to_string(basePair.getRequest())
	request_type=''

	if rawHeaders[0].startswith('GET'):
		request_type='GET'

	if request_type=='GET' and FORCE_POST:		
		request=self._get2post(rawHeaders)
		request_type='POST'		

        request = request.replace('$', '${EVIL_DOLLAR_SIGN}')

	uri_length=len(rawHeaders[0])-9 # 9 is len( HTTP/1.1)
        if request_type == 'GET':
		uri_length-=4
	        if ('?' in request[0:request.index('\n')]):
	            request = re.sub('(?i)([a-z]+ [^ ]+)', r'\1&${paramguess}', request, 1)
	        else:
	            request = re.sub('(?i)([a-z]+ [^ ]+)', r'\1?${paramguess}', request, 1)
		## in this case we also need to optimize the request size
	else:
		uri_length-=5
		post_lines=request.split("\n\r")
		post_lines[-1]=post_lines[-1]+"&${paramguess}"
		request="\r\n".join(post_lines)

	# First, we need two requests with diffent random params of the same length
	# to find out if the page is stable	
        request_template = Template(request)	
	(attack, resp) = self._attack(basePair, 'xahesf=kahf31', request_template)
	if hit(resp, base_resp_string):
		print "Page is not stable, trying another comparison method"
		if HIT_DETECTION=="TAG":
			HIT_DETECTION="LEN"
		else:
		  	HIT_DETECTION="TAG"
		if hit(resp, base_resp_string):
			err_msg("None of the response comparison methods works, page is not stable, aborting")
			return issues
		else:
			print "OK, comparison method switched to "+HIT_DETECTION



	#print "Params number: "+str(params_number)
	#print "URI length: "+str(uri_length)

	uri_size_with_params=(params_number*9)+uri_length
	chunk_size=0
	number_of_chunks=1
	print "URI size with params: "+str(uri_size_with_params)
	if uri_size_with_params>MAX_URI:
		number_of_chunks=(uri_size_with_params/MAX_URI)+2 #+2 instead of 1, so we get some safety margin in case of chunks with params a bit longer than 8 bytes
		chunk_size=(params_number/number_of_chunks)
		#print "Number of chunks: "+str(number_of_chunks)
		#print "Safe max chunk size: "+str(chunk_size)+" params per initial request"
		#print "Real max chunk size: "+str(float(params_number/(uri_size_with_params/MAX_URI)))
		#print "\n\n"

	# ITERATE OVER CHUNKS AND PERFORM PARAM SEARCH ON EACH OF THEM
	for chunk_number in range(0,number_of_chunks):
		brute_params_half=[]
		param_found = None
		if chunk_number+1==number_of_chunks: # we are at the last chunk
			start=chunk_number*chunk_size
			brute_params_half = brute_params[start:]
		else:				     # we are not at the last chunk
			start=chunk_number*chunk_size
			stop=start+chunk_size
			brute_params_half = brute_params[start:stop]
		print "Current chunk number: "+str(chunk_number)

		length=len(brute_params_half)
	        half_length=length/2

		# Then we issue the actual request
		(attack2, resp2) = self._attack(basePair, '&'.join(brute_params_half), request_template)
	        if hit(resp2, base_resp_string):
		# OK, we got a different response, now let's track the parameter down
	            print "We got a hit (current chunk range: "+str(start)+","+str(stop)+")."
		    params_hit=[]
		    attack_hit=attack
		    while True:			
			    half_left = brute_params_half[0:half_length]
			    half_right = brute_params_half[half_length:length]

			    (attack, resp2) = self._attack(basePair, '&'.join(half_left), request_template)
			    ## error detection would be nice here
			    if hit(resp2,base_resp_string):
				# We hit something, so we follow the left half
				brute_params_half = half_left
				attack_hit=attack
	                    else:
				# We missed, so it must be in the right half
				brute_params_half = half_right
			    # if brute_params_half!=params_hit, we set param_found to the param present in params_hit and not present in brute_params_half
			    #print "Our magic param should be in: "
			    #print brute_params_half
			    length=len(brute_params_half)
			    if length == 1:
				param_found=brute_params_half[0]
				issues.append(self._raise(basePair, attack_hit, 'param_detected', param_found))
				break
			    half_length=length/2
		else:	
			if chunk_number+1==number_of_chunks:
				print "The response does not differ from the base, no paramters discovered"
				return issues
	return issues

    def _raise(self, basePair, attack, issue_type, param):
        service = attack.getHttpService()
        url = helpers.analyzeRequest(attack).getUrl()
	
	if issue_type == 'param_detected':
	        title = 'Input parameter detected'
        	sev = 'Medium'
        	conf = 'Certain'
        	desc = """The page appears to take input parameter """+param+""" <br/><br/>"""
        	issue = CustomScanIssue(service, url, [basePair, attack], title, desc, conf, sev)
	        return issue
	else:
		title = 'GET and POST are interchangeable'
        	sev = 'Medium'
        	conf = 'Certain'
        	desc = """The page appears not to distinguish GET and POST params <br/><br/>"""
        	issue = CustomScanIssue(service, url, [basePair, attack], title, desc, conf, sev)
	        return issue

    def _attack(self,basePair, param_brute,  request_template):
        proto = helpers.analyzeRequest(basePair).getUrl().getProtocol() + '://'

        request = request_template.substitute({'paramguess':param_brute,'EVIL_DOLLAR_SIGN':'$'})

        attack = callbacks.makeHttpRequest(basePair.getHttpService(), request)

        response = safe_bytes_to_string(attack.getResponse())

        return attack, response

    def _get2post(self,headers):
	# Replace GET with POST
	# Add content-type: application/x-www-urlencoded header
	# Add content-length header
	# Move the query string to the body
	headers[0]=headers[0].replace('GET','POST',1)
	querystring=''

	try:
	    querystring = re.search('\?(.+) HTTP', headers[0]).group(1)
	    headers[0]=headers[0].replace('?'+querystring,'')
	except AttributeError:
	    # not found in the original string
	    querystring = '' # no query string
		
	for header in headers:
		if header.startswith('Content-Type:'):
			header='Content-Type: application/x-www-urlencoded'	
#	headers.append('Content-Length: '+str(len(querystring)))
	requeststring="\n\r".join(headers)+"\n\r\n\r"+querystring

	return requeststring


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail
        self.Severity = severity
        self.Confidence = confidence
        #print "Reported: " + name + " on " + str(url)
        return

    def getUrl(self):
        return self.Url

    def getIssueName(self):
        return self.Name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.Severity

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.Detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService


# misc utility methods


def tagmap(resp):
    tags = ''.join(re.findall("(?im)(<[a-z]+)", resp))
    return tags


def randstr(length=12, allow_digits=True):
    candidates = string.ascii_lowercase
    if allow_digits:
        candidates += string.digits
    return ''.join(random.choice(candidates) for x in range(length))


def hit(resp, baseprint):
    if HIT_DETECTION=='LEN':
	return len(baseprint)!=len(resp)
    return (tagmap(baseprint) != tagmap(resp))

# currently unused as .getUrl() ignores the query string
def issuesMatch(existingIssue, newIssue):
    if (existingIssue.getUrl() == newIssue.getUrl() and existingIssue.getIssueName() == newIssue.getIssueName()):
        return -1
    else:
        return 0


def getIssues(name):
    prev_reported = filter(lambda i: i.getIssueName() == name, callbacks.getScanIssues(''))
    return (map(lambda i: i.getUrl(), prev_reported))


def request(basePair, insertionPoint, attack):
    req = insertionPoint.buildRequest(attack)
    return callbacks.makeHttpRequest(basePair.getHttpService(), req)

def is_same_issue(existingIssue, newIssue):
    if existingIssue.getIssueName() == newIssue.getIssueName():
        return -1
    else:
        return 0

def msg(message):
	JOptionPane.showMessageDialog(self.panel, message, "Information", JOptionPane.INFORMATION_MESSAGE)

def err_msg(message):
	JOptionPane.showMessageDialog(panel, message, "Error", JOptionPane.ERROR_MESSAGE)
