import fnmatch
# import sys
# import collections
from signatures import *

# matches the items in the indicator to the event... iterates through the sections and if theres a list it iterates
# through that. Uses checkpair to see if the items in the list/dictionary match items in the eventlog. event should be
# the eventlog and indi is the indicator
def find_matches(event, indi):
        flag = False
        if isinstance(indi, dict):
                for k, v in indi.iteritems():
                        if isinstance(v, list):
                                for item in v:
                                        if not checkpair(event, k, item):
                                                flag = False
                                        else:
                                                flag = True
                                                break

                        else:
                                if not checkpair(event, k, v):
                                        return False

                                else:
                                        flag = True
        else:
                if isinstance(indi, list):
                        for item in indi:
                                if isinstance(item, dict):
                                        for ik, iv in item.iteritems():
                                                if not checkpair(event, ik, iv):
                                                        flag = False
                                                else:
                                                        flag = True
        return flag


# basic matching by calling find_matches and returning True if find_matches is true. event is the event and x is the
# data from the indicator- usually gotten using get_data
def match_basic(event, x):
        if find_matches(event, x):
                return True
        else:
                return False


# matches for the '1 of them' condition by iterating through all of the sections in detection and as long as the section
# isnt condition it will perform a find_matches on it. Once one hits as true, its done. Event is the event and v is the
# dictionary containing detection
def match_1_of_them(event, v):
        y = v['detection']
        for a, b in y.iteritems():
                if a != 'condition':
                        z = v['detection'][str(a)]
                        find_matches(event,z)
                        if find_matches(event, z):
                                return True
        		else:
				return False


# matches for the 'selection and one of combination' condition. first performs find_matches on the selection section of
# detection and if it returns true, it iterates through all of the other sections which arent selection and performs
#  find matches on each section. once one returns True is is done
def sel_and_oneof(event, v, name):
        if isinstance(v, dict):
                if match_basic(event, get_data(v, 'selection')) == True:
                        sections = v['detection']
                        for item in sections:
                                if (item != 'selection') and (item != 'condition'):
                                        z = v['detection'][str(item)]
                                        find_matches(event, z)
                                        if find_matches(event, z):
                                                return True

                                        else:
                                                return False
                else:
                        return False
	else:
		print "Error in Formatting: No dictionary found: " + str(name)
			#ERROR IN FORMATTING

# Performs a match for the condition 'methregistry or ( methprocess and not filterprocess )' by calling to match_basic
#  for methregistry and then again for the sections in the brackets
def meth_match(event, v, name):
        if isinstance(v, dict):
                if match_basic(event, v['detection']['methregistry']):
                        return True
                elif match_basic(event, v['detection']['methprocess']) and not match_basic(event, v['detection']['filterprocess']):
                        return True
                else:
                        return False
	else:
		print "Error in Formatting: No dictionary found: " + str(name)
		return False
		#ERROR IN FORMATTING

#iterates through all of the sections and performs find matches on each one. Breaks if one returns False
def all_of_them(event, v, name):
        if isinstance(v, dict):
                sections = v['detection']
                for item in sections:
                        z = v['detection'][str(item)]
                        find_matches(event, z)
                        if find_matches(event, z) == True:
                                return True
                        else:
                                return False
	else:
		print "Error in Formatting: No dictionary found: " + str(name)
		return False
		#ERROR IN FORMATTING


# Extracts the condition from each indicator in the indicator log and calls the appropriate match method against the indicator and the event. If matches, adds alert to the alert_log list for iteration in script.py and adds the indicator and indicator information into the alert log document. Event is a single event from the eventlog, ind_name is the name of the indicator, indicator is the complete indicator dictionary, alert_log is a list of indicator names which have been hit on, doc is the alert log.
def analyze(event, ind_name, indicator, alert_log, doc):
#ALERT LOG LIST COULD BE CHANGED TO A HITS VARIABLE OR SOMETHING LESS COMPLEX
        if isinstance(indicator, dict):
                if get_condition(indicator, ind_name) == 'selection':
                        if match_basic(event, get_data(indicator, 'selection')) and str(ind_name) not in alert_log:
                                alert_log.append(str(ind_name))
				write_alert(str(ind_name), doc)
				write_info(indicator, doc)
                elif get_condition(indicator, ind_name) == 'selection and not filter':
                        if match_basic(event, get_data(indicator, 'selection')) and match_basic(event, get_data(indicator, 'filter')) and str(ind_name) not in alert_log:
                                alert_log.append(str(ind_name))
				write_alert(str(ind_name), doc)
				write_info(indicator, doc)
                elif get_condition(indicator, ind_name) == 'selection and not exclusion':
                        if match_basic(event, get_data(indicator, 'selection')) and match_basic(event, get_data(indicator, 'exclusion')) and str(ind_name) not in alert_log:
                                alert_log.append(str(ind_name))
				write_alert(str(ind_name), doc)
				write_info(indicator, doc)
                elif get_condition(indicator, ind_name) == "selection and not falsepositive":
                        if match_basic(event, get_data(indicator, 'selection')) and match_basic(event, get_data(indicator, 'falsepositive')) and str(ind_name) not in alert_log:
                                alert_log.append(str(ind_name))
				write_alert(str(ind_name), doc)
				write_info(indicator, doc)
                elif get_condition(indicator, ind_name) == '1 of them':
                        if match_1_of_them(event, indicator) and str(ind_name) not in alert_log:
                                alert_log.append(str(ind_name))
				write_alert(str(ind_name), doc)
				write_info(indicator, doc)
                elif get_condition(indicator, ind_name) == "selection and 1 of combination*":
                        if sel_and_oneof(event, indicator, ind_name) and str(ind_name) not in alert_log:
                                alert_log.append(str(ind_name))
				write_alert(str(ind_name), doc)
				write_info(indicator, doc)
                elif get_condition(indicator, ind_name) == 'methregistry or ( methprocess and not filterprocess )':
                        if meth_match(event, indicator, ind_name) and str(ind_name) not in alert_log:
                                alert_log.append(str(ind_name))
				write_alert(str(ind_name), doc)
				write_info(indicator, doc)
                elif get_condition(indicator, ind_name) == 'all of them':
                        if all_of_them(event, indicator, ind_name) and str(ind_name) not in alert_log:
                                alert_log.append(str(ind_name))
				write_alert(str(ind_name), doc)
				write_info(indicator, doc)

		#else:
		return alert_log
		

# checks to see if a given key and value from the indicator are also in the event. dic is the event
def checkpair(self, key, value):
        if key in self:
                if '*' in str(value):
                        return fnmatch.fnmatch(self[key], value)
                elif self[key] == str(value):
                        return True
                else:
                        return False

        else:
                return False

#Writes the string to the alert documents 'doc'
def write_alert(string, doc):
	with open(doc, 'a+') as f:
		f.write(string)
		f.write('\n')

#Turns the event info into a list to be outputted to the alert log. info is the detction section of the event, event is an empty list
def list_event(info, event):
	for k,v in info.iteritems():
		if isinstance(v, dict):
			list_event(v, event)
		else:
			key = "{0} : {1}".format(k,v)
			event.append(str(key))
	return event

#Writes the listed info from list_event method called on indicator into the alert log (doc)
def write_info(indicator, doc):
	event = []
	info = get_info(indicator)
	info_list = list_event(info, event)
	for item in event:
		write_alert(item, doc)
	write_alert('\n', doc)
 



