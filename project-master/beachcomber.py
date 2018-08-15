from al_services.alsvc_beachcomber import script
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, Classification, SCORE
from io import open
import os
import sys
from xml.parsers.expat import ExpatError


class XmlResultObject(ResultSection):
    def __init__(self, yml_reference_name, description, score):
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
    Service verifies a sysmon xml log by matching potential threats
    """
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'document/xml'
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
        local_filename = request.download()
        try:
            with open(local_filename, "r", encoding='utf-8', errors='ignore') as file_content:
                xml = file_content.read()
        except ExpatError:
            print("Error: Format error in the log")
            sys.exit(1)

        script.run_script(xml)

        with open("alerts_generated.txt", "r") as alerts:
            output = alerts.readlines()

        result = self.parse_alerts(output)
        request.result = result

    def parse_alerts(self, alerts):
        res = Result()
        line_count = 0
        newline_count = 0
        content = ""
        yml_indicator = ""
        # xml_hits = ResultSection(title_text='xml Malware Indicator Match')

        if os.stat("file").st_size == 0:
            # Result file is empty, nothing to report
            return res

        for line in alerts:
            # Otherwise we iterate through each line to read the required information
            if line != "\n":
                line_count += 1
                if line_count == 1:
                    yml_indicator = line
                else:
                    content += line + "\n"
            elif line_count == 0:
                newline_count += 1
            else:
                newline_count = 0
                section = ResultSection(SCORE.VHIGH, yml_indicator)
                section.add_line(content)
                res.add_section(section)
                # res.add_result(xml_hits)
                content = []
                line_count = 0

        return res

