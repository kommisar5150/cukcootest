from al_services.alsvc_beachcomber.config import indicator_dir, \
                                                 alert_document, \
                                                 eventlog_empty, \
                                                 yaml_path, \
                                                 json_path

import signatures
import json
import logs
import matching
import sys


def run_script(xml_in):
    """
    Initializes the script which will generates any alerts for a given xml sysmon log
    :param xml_in: file, xml file which is our sysmon log
    :return:
    """

    logs.import_log(xml_in, eventlog_empty)

    try:
        with open(eventlog_empty) as x:
            log = json.load(x)
    except OSError:
        print "Error with event_json.json."
        sys.exit(1)

    signatures.import_ind(indicator_dir, yaml_path)
    ind = signatures.create_json(yaml_path, json_path)
    alert_log = []
    event_dict = logs.create_event_dict(log)
    count = 0

    for k, v in event_dict.iteritems():
        b = logs.flattened(v)
        c = logs.update_dict(b)
        for ik, iv in ind.iteritems():
            alert_log = matching.analyze(c, ik, iv, alert_log, alert_document)
        count = count + 1
