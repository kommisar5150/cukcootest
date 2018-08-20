from io import open
from xml.parsers.expat import ExpatError

import sys
import json
import collections
import xmltodict


def import_log(origin, new_log):
    """
    opens the sysmonout.xml file listed in config and converts it to a json file for analysis and places the json file
    in the config folder.
    :param origin:
    :param new_log:
    :return:
    """

    try:
        with open(new_log, 'w') as event_json:
            doc = xmltodict.parse(origin)
            event_json.write(unicode(json.dumps(doc, ensure_ascii=False)))
    except ExpatError:
        print "Error: Format error in the Log"
        sys.exit(1)


def flattened(event):
    """
    reduces the json logs into only the data that we need.. d will be the log imported as a commandline argument
    :param event:
    :return:
    """

    items = []

    for k, v in event.iteritems():
        if isinstance(v, collections.MutableMapping):
            items.extend(flattened(v).iteritems())
        else:
            items.append((k, v))

    return dict(items)


def create_event_dict(log):
    """
    Creates a flattened event log which has labeled events which can be iterated through like a dictionary. log is the
    eventlog json imported at the top.
    :param log:
    :return:
    """

    count = 0
    y = {}
    event_dict = {}

    for k, v in log.iteritems():
        y = flattened(v)

    for k, v in y.iteritems():
        for item in v:
            event_dict['Event_' + str(count)] = item
            count = count + 1

    return event_dict


def update_dict(dic):
    """
    re-inserts the Data that was removed for formatting. Data needs to be removed before calling the method and is
    'data'. 'dic' is the event..
    :param dic:
    :return:
    """

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
                tempdict.update({key: value})

    del dic['Data']

    for k, v in tempdict.iteritems():
        dic.update({k: v})

    return dic
