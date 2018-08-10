# import json
import os
import yaml
import json
import sys

def import_ind(dir_name, fn):
	try:
		fileList = []
		for file in os.listdir(dir_name):
        		dirfile = os.path.join(dir_name, file)
        		if os.path.isfile(dirfile) and str(dirfile) not in fileList:
                		fileList.append(dirfile)
		with open(fn, 'w') as f:
        		for file in fileList:
                		f.write("---\n")
                		f.write(open(file).read())
                		f.write("...\n")
	except:
		print "Error in Formatting of Indicators: Verify your yaml documents"
		sys.exit(1)

def create_json(yaml_file, json_file):
	try:
		newdict = {}
		with open(yaml_file, 'r') as yaml_in:
        		loadyaml = yaml.safe_load_all(yaml_in)
   			for item in loadyaml:
         			tempdict = {}
				if isinstance(item, dict):
         				for k, v in item.iteritems():
             					if k == 'title':
                 					tempkey = v
             					elif k == 'detection':
                 					tempdict[k] = v
         				newdict[tempkey] = tempdict
		return newdict
	except yaml.YAMLError as exc:
		print "Error in JSON-ing of Indicators: Verify for yaml documents"
		sys.exit(1)

# gets the title of the indicator for the result alert_log. ind is the indicator
def get_title(ind):
	return ind['title']


# gets the condition string from the indicator for analyze. v is the dictionary which contains detection
def get_condition(v, name):
	try:
		return v['detection']['condition']
	except KeyError:
		print "Error: No Condition Found: " + str(name)
		return "none"

#Returns the detection section of the indicator which will be turned into a list and outputted into the alerts log
def get_info(v):
	return v['detection']

# pulls out the data from a specific section in detection. v is the dictionary which contains detection and key is the
# title of the section you want to get the data from (string)
def get_data(v, key):
    return v['detection'][str(key)]

