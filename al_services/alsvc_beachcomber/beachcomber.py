from al_services.alsvc_beachcomber import script
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, Classification, SCORE
from io import open
from xml.parsers.expat import ExpatError

import os
import sys


class XmlResultObject(ResultSection):
    """
    XmlResultObject is used to populate a ResultSectioln object. Here, the object is initialized with given values
    relating to Sigma indicator matches found in the sysmon log.
    """

    def __init__(self, yml_reference_name, description, score):
        """
        Initializes the object by populating the relevant fields. These fields are used when Assemblyline returns a
        result section. We indicate the name of the indicator as the result's title, the description as the body of
        the result, and the score is also managed here. This object is returned to the Result object in the
        Beachcomber class' parse_alerts method to allow the service to return results. The score is a placeholder for
        now, and any matches will yield a score of 500 (SCORE.VHIGH).
        :param yml_reference_name: str, name of the threat found
        :param description: str, description of the sysmon log match in the Sigma yaml indicators
        :param score: int, points given to determine the threat level of a match in the sysmon log
        """

        title = 'Indicator match for: %s' % yml_reference_name
        body = "Description: \n%s " % description
        super(XmlResultObject, self).__init__(
            title_text=title,
            score=score,
            body=body,
            classification=Classification.UNRESTRICTED
        )


class Beachcomber(ServiceBase):
    """
    Service object that initializes the matching process between a sysmon log and yaml indicators.
    """
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'code/xml'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'CORE'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 256

    def __init__(self, cfg=None):
        super(Beachcomber, self).__init__(cfg)

    def start(self):
        self.log.debug("Beachcomber service started")

    def execute(self, request):
        """
        Execute method required by Assemblyline. This initializes the service's script that parses the sysmon log and
        finds matches in Sigma yaml indicators.
        :param request:
        :return:
        """

        local_filename = request.download()

        try:
            with open(local_filename, "r", encoding='utf-8', errors='ignore') as file_content:
                xml = file_content.read()
        except ExpatError:
            print("Error: Format error in the log")
            sys.exit(1)

        script.run_script(xml)

        # The script populates an alerts text file that contains any threats found by matching yaml indicators to the
        # sysmon log. It's safe to assume that these results may each yield a potential threat.
        with open("opt/al/pkg/al_services/alsvc_beachcomber/alerts_generated.txt", "r") as alerts:
            output = alerts.readlines()

        result = self.parse_alerts(output)
        request.result = result

        try:
            # We remove each file to have a fresh start.
            os.remove("opt/al/pkg/al_services/alsvc_beachcomber/alerts_generated.txt")
            os.remove("opt/al/pkg/al_services/alsvc_beachcomber/event_json.json")
            os.remove("opt/al/pkg/al_services/alsvc_beachcomber/indicators.json")
            os.remove("opt/al/pkg/al_services/alsvc_beachcomber/indicators.yaml")
        except OSError:
            # If the files don't exist, we may not necessarily need to raise an error.
            pass

    def parse_alerts(self, alerts):
        """
        This method parses the results of the Beachcomber scan. The alerts_generated.txt file contains each potential
        threat found in the sysmon log, and from there we can parse the results which will be returned to the
        Assemblyline UI to display results.
        :param alerts: str, the alerts_generated.txt file containing all our results from the Beachcomber scan.
        :return:
        """

        res = Result()
        line_count = 0
        newline_count = 0
        content = ""
        yml_indicator = ""
        xml_hits = ResultSection(title_text='Sigma Indicator Match')

        try:
            if os.stat("/opt/al/pkg/al_services/alsvc_beachcomber/alerts_generated.txt").st_size == 0:
                # Result file is empty, nothing to report
                return res
        except OSError:
            raise OSError("File alerts_generated.txt was not created. An error has happened within the service.")

        for line in alerts:
            # Otherwise we iterate through each line to read the required information
            if line != "\n":
                line_count += 1
                if line_count == 1:
                    yml_indicator = line
                else:
                    content += line

            elif line_count == 0:
                # Here we read a newline char. Each result is separated by two empty lines, so we verify that both have
                # been read before proceeding to the next result.
                newline_count += 1

            else:
                # Here we read the second new line, meaning we're ready to read the next result. We populate the
                # ResultSection object with our parsed information, add a section, and reset the results.
                newline_count = 0
                xml_hits.add_section(XmlResultObject(yml_indicator, content, SCORE.VHIGH))
                content = ""
                line_count = 0

        res.add_result(xml_hits)
        return res

