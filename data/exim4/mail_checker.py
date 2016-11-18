#!/usr/bin/env python
#base on https://github.com/xme/mime2vt/blob/master/mime2vt.py

import sys
import traceback
import email
import pyzmail
import mimetypes
import zipfile
import json
import hashlib
import re
import tempfile
import StringIO
import yara
import magic
from datetime import datetime

log = "/var/log/exim4/files.log"
yara_rules = "/etc/exim4/compiled_yara"

def parseMailheaders(data):
    if data:
	msg=pyzmail.PyzMessage.factory(data)

	mailheaders = { "subject": msg.get_subject(),
			"from": msg.get_address('from')[1],
			"to": map(lambda x: x[1], msg.get_addresses('to')),
			"cc": map(lambda x: x[1], msg.get_addresses('cc')),
			"x-mailer": msg.get('x-mailer', ''),
			"date": msg.get('date', ''),
			"message-id": msg.get('message-id', ''),
			"user-agent": msg.get('user-agent',''),
			"x-virus-scanned": msg.get('x-virus-scanned','')
			}

	received = msg.get('received','')
	if received:
	    ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', received )
	    if ip:
		mailheaders["ip"] = ip
	return mailheaders
    else:
	return None

def getMailHeader(header_text, default="ascii"): #http://blog.magiksys.net/parsing-email-using-python-content
    """Decode header_text if needed"""
    try:
        headers=email.Header.decode_header(header_text)
    except email.Errors.HeaderParseError:
        # This already append in email.base64mime.decode()
        # instead return a sanitized ascii string
        # this faile '=?UTF-8?B?15HXmdeh15jXqNeVINeY15DXpteUINeTJ9eV16jXlSDXkdeg15XXldeUINem15PXpywg15TXptei16bXldei15nXnSDXqdecINek15zXmdeZ?==?UTF-8?B?157XldeR15nXnCwg157Xldek16Ig157Xl9eV15wg15HXodeV15bXnyDXk9ec15DXnCDXldeh15gg157Xl9eR16rXldeqINep15wg15HXmdeQ?==?UTF-8?B?15zXmNeZ?='
        return header_text.encode('ascii', 'replace').decode('ascii')
    else:
        for i, (text, charset) in enumerate(headers):
            try:
                headers[i]=unicode(text, charset or default, errors='replace')
            except LookupError:
                # if the charset is unknown, force default 
                headers[i]=unicode(text, default, errors='replace')
        return u"".join(headers)


def getFileName(part): #http://blog.magiksys.net/parsing-email-using-python-content
    """Many mail user agents send attachments with the filename in 
    the 'name' parameter of the 'content-type' header instead 
    of in the 'filename' parameter of the 'content-disposition' header.
    """
    filename=part.get_param('filename', None, 'content-disposition')
    if not filename:
        filename=part.get_param('name', None) # default is 'content-type'
        
    if filename:
        # RFC 2231 must be used to encode parameters inside MIME header
        filename=email.Utils.collapse_rfc2231_value(filename).strip()
    if filename and isinstance(filename, str):
        # But a lot of MUA erroneously use RFC 2047 instead of RFC 2231
        # in fact anybody miss use RFC2047 here !!!
        filename=getMailHeader(filename)
    return filename

def checkYara(data): 
    rules = yara.load(yara_rules)
    try:
	matches = rules.match(data = data, timeout=30)
	result = {}
	result["yara_matches"] = map(lambda x: x.rule, matches)
	result["yara_check_date"] = datetime.utcnow().isoformat()
	return result
    except:
	#print "Exception in yara check!"
        #print sys.exc_info()[1]
        #print sys.exc_info()[0]
	#print sys.exc_info()[2]
        #tb_string = traceback.format_tb(sys.exc_info()[2])
        #print tb_string
	return None

def checkFileType(data, mime = False):
    result = {}
    if mime:
	mime_type = magic.from_buffer(data, mime = True)
	result["mime_type"] = mime_type
    file_type = magic.from_buffer(data)
    result["file_type"] = file_type
    return result

if __name__ == '__main__':
    files = []
    excludetypes = ["image/png", "image/gif", "image/jpeg", "text/plain", "text/html"]
    data = "" . join(sys.stdin)
    mailheaders = parseMailheaders(data)
    msg = email.message_from_string(data)
    for part in msg.walk():
	contenttype = part.get_content_type()
	filename = getFileName(part)
	try:
	    fname, fextension = os.path.splitext(filename)
	except:
	    fextension = "none"
	data = part.get_payload(None, True)
	if data:
	    size = len(data)
	    md5 = hashlib.md5(data).hexdigest().upper()
	    if contenttype in [ 'text/html', 'text/plain' ]:
		urls = []
	    if contenttype not in excludetypes or fextension == '.js':
		if not filename: filename = md5
		f_entry = {"file_name": filename,
		     "file_size": size,
		     "MD5": md5,
		     "mime_type": contenttype
		    }
		checkResult = checkYara(data)
		if checkResult is not None:
		    f_entry.update(checkResult)
		if mailheaders:
		    f_entry.update(mailheaders)
		f_entry.update(checkFileType(data, mime=False)) #We already have mime_type from mail headers
		files.append(json.dumps(f_entry))

	    #add rar and 7zip support
	    if contenttype in ['application/zip', 'application/x-zip-compressed']: #add max archive size limitation and nested archives support
		source_md5 = md5
		
	    	zf = zipfile.ZipFile(StringIO.StringIO(data))
		for f in zf.namelist():
		    try:
			if f.endswith('/'): continue #Skip directory
			data = zf.read(f)
		    except RuntimeError as e:
			if 'encrypted' in str(e):
			    updateEntry = json.loads(files[-1])
			    updateEntry['tags'] = ["password_protected_archive"]
			    files[-1] = json.dumps(updateEntry)
			break
		    md5 = hashlib.md5(data).hexdigest().upper()
		    size = len(data)
		    
		    #for cyrillic file names - http://vostryakov.ru/blog/24-russkie-imena-fajlov-v-zip-arhive-i-python/
		    try:
        		unicode_name = f.decode('UTF-8').encode('UTF-8')
    		    except:
        		unicode_name = f.decode('cp866').encode('UTF-8')
		    f_entry = { "file_name": (filename + "/").encode('UTF-8') + unicode_name,
				"file_size": size,
				"source_arch_md5": source_md5,
		    		"MD5": md5
			}
		    checkResult = checkYara(data)
		    if checkResult:
			f_entry.update(checkResult)
		    if mailheaders:
			f_entry.update(mailheaders)
		    f_entry.update(checkFileType(data, mime=True))
		    files.append(json.dumps(f_entry))

#    print files
    with open(log, 'a') as file_log:
	file_log.write('\n'.join(files) + '\n')
