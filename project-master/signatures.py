import os
import yaml
import json
import os.path


def import_ind(dir_name, yaml_file):
    """
    Populates a list containing the path names of each yml file, then contents of each .yml files are then read and
    written to a .yml file (indicators.yml) in their entirety.
    :param dir_name: str, path containing sysmon yml files.
    :param yaml_file: file, the indicators.yml file created with information pulled from sysmon .yml files.
    :return:
    """

    file_list = []

    try:
        indicator_file = open(yaml_file, 'w')
    except OSError:
        raise OSError("Error in Formatting of Indicators: Verify your yaml documents")

    # Read name of each file in directory and populate list
    file_list = [os.path.join(dir_name, filename) for filename in os.listdir(dir_name) if
                 os.path.isfile(os.path.join(dir_name, filename)) and filename not in file_list]

    # Read the contents of each file and writes to indicator file
    for file_name in file_list:

        indicator_file.write("---\n")
        try:
            indicator_file.write(open(file_name).read())
        except OSError:
            raise OSError("Couldn't open file: {}".format(file_name))
        indicator_file.write("...\n")

    try:
        indicator_file.close()
    except OSError:
        raise OSError("Couldn't close yaml indicator file properly.")


def create_json(yaml_file, json_file):
    """
    Takes a yml file containing the information for each sysmon yaml file, extracts their title and detection fields
    and populates a dict that will be our json file. In this case, the title will become the key for the dict entry
    while the detection field will be its value. These dicts contain the titles of a thread, as well as information
    regarding its detection.
    :param yaml_file: file, our yaml file containing our indicators, read from all the sysmon yaml files.
    :param json_file: file, our newly created json file where we write the dict populated from the yaml files' info.
    :return: dict, the dictionary variable containing the title and detection fields from the yaml files.
    """

    newdict = {}

    # Open the yaml indicator file to read from, and open our json file we'll be creating and writing to
    try:
        yaml_in = open(yaml_file, "r")
        json_out = open(json_file, "w")
    except OSError:
        raise OSError("Couldn't open yaml file")

    # We then load the information contained in each yaml file from our sysmon folder
    try:
        loadyaml = yaml.safe_load_all(yaml_in)
    except yaml.YAMLError:
        raise yaml.YAMLError("Error in JSON-ing of Indicators: Verify for yaml documents")

    # A yaml file is itself a dict once loaded, so we can simply access the appropriate indices for our information
    for item in loadyaml:

        try:
            key = item["title"]
            newdict[key] = {"detection": item["detection"]}
        except (TypeError, KeyError):
            pass

    # Once all yaml files are populated in newdict, we can simply write it to our json file
    json.dump(newdict, json_out)

    try:
        json_out.close()
        yaml_in.close()
    except OSError:
        raise OSError("Couldn't close json/yaml file")

    return newdict


def get_title(indicator_dict):
    """
    Gets the title of the indicator for the result alert_log.
    :param indicator_dict: dict, our dictionary containing the indicator info from sysmon .yml files.
    :return:
    """

    return indicator_dict['title']


def get_condition(indicator_dict, condition):
    """
    Gets the condition string from the indicator for analyze.
    :param indicator_dict: dict, our dictionary containing the indicator info from sysmon .yml files.
    :param condition: Condition we wish to analyze .
    :return: str, the condition for the indicator, returned as a string.
    """

    try:
        return indicator_dict['detection']['condition']
    except KeyError:
        print "Error: No Condition Found: " + str(condition)
        return "none"


def get_info(indicator_dict):
    """
    Returns the detection section of the indicator that will be turned into a list and written into the alerts log.
    :param indicator_dict: dict, our dictionary containing the indicator info from sysmon .yml files.
    :return: dict, sub-dict of values in the indicator dict's detection key field.
    """

    return indicator_dict['detection']


def get_data(indicator_dict, key):
    """
    pulls out the data from a specific section in detection.
    :param indicator_dict: dict, our dictionary containing the indicator info from sysmon .yml files.
    :param key: str, name of field we wish to extract info from within the detection field of the indicator dict.
    :return: dict, sub-dict of selected info from given field.
    """

    return indicator_dict['detection'][str(key)]
