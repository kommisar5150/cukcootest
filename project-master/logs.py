import json
import collections
import xmltodict
from io import open
#from json import dumps
#import sys
import io
import sys
from xml.parsers.expat import ExpatError

#opens the sysmonout.xml file listed in config and converts it to a json file for analysis and places the json file in the config folder.
def import_log(origin, new_log):
	try:
		with open(origin, "r", encoding='utf-8', errors='ignore') as fp, open(new_log, 'w') as event_json:
			doc = xmltodict.parse(fp.read())
			event_json.write(unicode(json.dumps(doc, ensure_ascii=False)))
		#	print "done"
	#		log = log_to_json(event_json)
	#		return log
		#	print "done"
	#	with open(new_log) as x:
		#	log = json.load(new_log)
		#	print "done again"
		#	return log
	except ExpatError:
		print "Error: Format error in the Log"
		sys.exit(1)

#def log_to_json(f):
	#try:
	#	log = json.load(f)
	#	return log
	#except:
	#	print "Error in event log json file. Try removing the event_json.json."
	#	sys.exit(1)

# reduces the json logs into only the data that we need.. d will be the log imported as a commandline argument
def flattened(event):
        items = []
        for k, v in event.items():
                if isinstance(v, collections.MutableMapping):
                        items.extend(flattened(v).items())
                else:
                        items.append((k, v))
        return dict(items)


# Creates a flattened event log which has labeled events which can be iterated through like a dictionary. log is the
# eventlog json imported at the top.
def create_event_dict(log):
        event_dict = {}
        for k, v in log.iteritems():
                y = flattened(v)

        count = 0
        for k, v in y.iteritems():
                for item in v:
                        event_dict['Event_' + str(count)] = item
                        count = count + 1
        return event_dict


# re-inserts the Data that was removed for formatting. Data needs to be removed before calling the method and is 'data'. 'dic' is the event..
def update_dict(dic):
        tempdict = {}
        data = dic['Data']

        for item in data:
                key = 0
                value = 0
                for k, v in item.iteritems():
                        if k == '#text':
                                value = v
                        elif k == '@Name':
                                key = v
                        else:
                                print "Error in Data Section: Formatting"
                                break
                        if (key != 0) and (value != 0):
                                tempdict.update({key:value})

        del dic['Data']

        for k, v in tempdict.iteritems():
                dic.update({k:v})
        return dic

