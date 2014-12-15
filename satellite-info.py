#!/usr/bin/python
## Satellite-info - script for getting various reports from RHN Satellite server or Spacewalk server. It uses Satellite 5.5 API (https://access.redhat.com/documentation/en-US/Red_Hat_Network_Satellite/5.5/html/API_Overview/index.html). Please write any feedback to Vasily.Angapov.GDC@ts.fujitsu.com.
## Version 0.1
## Written by Angapov Vasily
import xmlrpclib
import argparse
import os
import getpass
from operator import itemgetter, attrgetter

#Parse arguments from command line
parser = argparse.ArgumentParser(description='Script to get various custom reports from RHN Satellite Server (provides more functionality than standard spacewalk-report tool). Username and password can be provided through command line parameters, interactively or by enviroment variables SATELLITE_USER and SATELLITE_PASSWORD')
parser.add_argument('system', action='store', nargs='?', default='', help='System name (must be exactly like in Satellite server interface)')
parser.add_argument('-u',  '--user', action='store', nargs='?', dest='user', default=os.environ.get('SATELLITE_USER'), help="Satellite user name", metavar='')
parser.add_argument('-p',  '--password', action='store', nargs='?', dest='password', default=os.environ.get('SATELLITE_PASSWORD'), help='User password', metavar='')
parser.add_argument('-s',  '--server', action='store', nargs='?', dest='server', default='defrlpsat01.mle.mazdaeur.com', help='Satellite server name or IP', metavar='')
parser.add_argument('-ip', '--ip', action='store', nargs='?', dest='ip', default='', help='Find systems with that IP address')
parser.add_argument('-ls', '--list-systems', action='store_true', dest='list', help='List systems available to user')
parser.add_argument('-lp', '--list-packages', action='store_true', dest='list_packages', help='List packages installed on system')
parser.add_argument('-lu', '--list-upgradable', action='store_true', dest='list_upgradable', help='List packages on system that can be upgraded')
parser.add_argument('-cf', '--list-config-channels', action='store_true', dest='conf_channels', help='List configuration channels system is subscribed to')
parser.add_argument('-ch', '--list-channels', action='store_true', dest='list_channels', help='List channels system is subscribed to')
parser.add_argument('-er', '--list-errata', action='store_true', dest='list_errata', help='List errata relevant to system')
parser.add_argument('-ps', '--package-search', action='store', nargs='?', dest='package_search', default='', help='Search packages globally on server or in given channel (--with-channel option). Uses advanced Lucene query engine. Query Example: "name:kernel AND version:2.6.18 AND -description:devel"', metavar='Package')
parser.add_argument('-pd', '--package-download', action='store', nargs='?', dest='package_download', default='', help='Get package URL for download. Uses package ID (can be obtained with -ps or -lp commands', metavar='Package_ID')
parser.add_argument('--with-channel', action='store', nargs='?', dest='with_channel', default='', help='Package search within given channel (to be used with -ps option)', metavar='Channel')
parser.add_argument('--with-epoch', action='store_true', dest='with_epoch', default='', help='Display epoch in packages names (with -ps or -lp options)')
parser.add_argument('-fr', '--full-report', action='store_true', dest='full_report', help='Generate full Satellite report (no other options required). Takes some time to work.')
parser.add_argument('-ms', '--memory-and-swap', action='store', nargs='?', dest='memswap', help='Show total memory and swap for all servers')
args = parser.parse_args()

#Getting SAtellite URL and credentials 
SATELLITE_URL = 'https://' + args.server + '/rpc/api'
SERVER_NAME = args.system
if args.user is not None and args.password is not None:
	SATELLITE_LOGIN = args.user
	SATELLITE_PASSWORD = args.password 
else:
	SATELLITE_LOGIN = raw_input("Satellite user: ")
	SATELLITE_PASSWORD = getpass.getpass("Password: ")

#Login to Satellite
spacewalk = xmlrpclib.Server(SATELLITE_URL)
key = spacewalk.auth.login(SATELLITE_LOGIN, SATELLITE_PASSWORD)

#Getting system's base channel
def BASE_CHANNEL(key, system_id):
	return [base_channel['label'] for base_channel in spacewalk.system.listSubscribableBaseChannels(key, system_id) if base_channel['current_base'] == 1][0]

#Package list printing function 
def PRINT_PACKAGE(name, version, release, arch, epoch, id):
	if args.with_epoch is True and epoch.isdigit():
		print '{0: <60}'.format(epoch + ":" + name + "-" + version + "-" + release + "." + arch) + str(id) 
	else:	
		print '{0: <60}'.format(name + "-" + version + "-" + release + "." + arch) + str(id)
def PRINT_PACKAGE_RAW(name, version, release, arch, epoch):
    if epoch.isdigit():
        return epoch + ":" + name + "-" + version + "-" + release + "." + arch
    else:
        return name + "-" + version + "-" + release + "." + arch
	
#Two functions to find ugradable packages. Detects duplicated packages like kernel-0.1 -> kernel-1.0,kernel-0.2 -> kernel-1.0. Only one record will be displayed in main list, others in duplicates. Only one record will be displayed in main list, others in duplicates 
def FIND_UPGRADABLE_PACKAGES(key, system_id):
	installed_pkgs = spacewalk.system.listPackages(key, system_id)
	upgradable_pkgs = spacewalk.system.listLatestUpgradablePackages(key, system_id)
	package_list=[]
	duplicates_list=[]
	for package in upgradable_pkgs:
		latest = spacewalk.system.listLatestAvailablePackage(key, system_id, package['name'])[0]['package']
		if package['to_version'] == latest['version'] and package['to_release'] == latest['release']:
			new = {}
			new['name'] = package['name']
			new['from_version'] = package['from_version'] + "-" + package['from_release'] + "." + package['arch']
			new['to_version']= package['to_version'] + "-" + package['to_release'] + "." + package['arch']
			package_list.append(new)
		for x in package_list:
			for y in package_list:
				if x !=y and x['name'] == y['name'] and x['from_version'] < y['from_version']:
					duplicates_list.append(y)
					package_list.remove(y)
	return (package_list, duplicates_list)

def LIST_UPGRADABLE_PACKAGES(key, SERVER_NAME):
	systems = spacewalk.system.getId(key, SERVER_NAME)
	system_id = systems[0]['id']		
	installed_pkgs = spacewalk.system.listPackages(key, system_id)
	upgradable_pkgs = spacewalk.system.listLatestUpgradablePackages(key, system_id)
	package_list, duplicates_list = FIND_UPGRADABLE_PACKAGES(key, system_id)
	print '{0:-^120}'.format('')
	print "     Server: " + SERVER_NAME.upper() + "\t\t Upgradable/Installed packages: " + str(package_list.__len__()) + "/" + str(installed_pkgs.__len__())
	print '{0:-^120}'.format('')
	print "     List of upgradable packages:"
	print '{0:-^38}'.format('')
	i =1
	for pkg in sorted(package_list, key=lambda k: k['name']):
		print '{0: <5}'.format(str(i)) + '{0: <50}'.format(pkg['name'] + "-" +pkg['from_version']) + "\t---->\t" + pkg['name'] + "-" +pkg['to_version']
		i += 1
	print "\nDuplicate packages: "
	if duplicates_list == []: print "None"
	for pkgs in sorted(duplicates_list, key=lambda k: k['name']):
		print '{0: <5}'.format(str(i)) + '{0: <50}'.format(pkgs['name'] + "-" +pkgs['from_version']) + "\t---->\t" + pkgs['name'] + "-" +pkgs['to_version']
		i += 1
	return (package_list, duplicates_list)
	spacewalk.auth.logout(key)
	raise SystemExit(0)

# List errata applicable to system
def LIST_ERRATA(key, SERVER_NAME):
	system = spacewalk.system.getId(key, SERVER_NAME)[0]
        errata = spacewalk.system.getRelevantErrata(key, system['id'])
        i = 1
        print "%".join( [ "#","Advisory name","Type","Synopsis","Severity","Date","Related CVE","Related packages" ] )
        for erratum in errata:
			CVE_list = spacewalk.errata.listCves(key, erratum['advisory_name'])
			if erratum['advisory_type'] == "Security Advisory":
				synopsis = erratum['advisory_synopsis'].split(":",1)
				synopsis[0], synopsis[1] = synopsis[1].strip(), synopsis[0].strip()
			else:
				synopsis = [ erratum['advisory_synopsis'], " " ]
			packages = spacewalk.errata.listPackages(key, erratum['advisory_name'])
			package_list = []
			for pkg in packages:
				package_list.append(PRINT_PACKAGE_RAW(pkg['name'],pkg['version'],pkg['release'],pkg['arch_label'],pkg['epoch']))
			print "%".join( [ (str(i)),erratum['advisory_name'],erratum['advisory_type'],"%".join(synopsis),erratum['update_date']," ".join(CVE_list)," ".join(package_list) ] )
			i += 1

# Lists channels that system is subscribed to
def LIST_CHANNELS(key, SERVER_NAME):
	system = spacewalk.system.getId(key, SERVER_NAME)[0]
	base_channel = BASE_CHANNEL(key, system['id']) 
	child_channels = [child['label'] for child in spacewalk.system.listSubscribedChildChannels(key, system['id'])]
	print base_channel
	for channel in child_channels: print "|--" + channel

# Lists configuration channels that system is subscribed to. Also lists configuration files within each channel.
def LIST_CONF_CHANNELS(key, SERVER_NAME):
	system = spacewalk.system.getId(key, SERVER_NAME)[0]
	channels = spacewalk.system.config.listChannels(key, system['id'])
	for channel in channels: 
		files = [file['path'] for file in spacewalk.configchannel.listFiles(key, channel['label'])]
		print channel['name']
		for file in files: print "|--" + file
		
#Finds systems with given IP address
def FIND_BY_IP(key, ip):
	found_systems=[]
	systems_list = spacewalk.system.search.ip(key, ip)
	for system in systems_list:
		found_systems.append(system['name'])
	if found_systems==[]:
		print "No systems found with this IP"
	else:
		for system in found_systems:
			print system
	spacewalk.auth.logout(key)
	raise SystemExit(0)

# List packages installed on system (at least packages known to Satellite)
def LIST_PACKAGES(key, SERVER_NAME):
	systems = spacewalk.system.getId(key, SERVER_NAME)
	system = systems[0]
	installed_pkgs = spacewalk.system.listPackages(key, system['id'])
	for package in installed_pkgs:
		PRINT_PACKAGE(package['name'],package['version'],package['release'],package['arch'],package['epoch'],package['id'])
	spacewalk.auth.logout(key)
	raise SystemExit(0)

# Lists all systems available to user
def LIST_SYSTEMS(key):
	systems_list = spacewalk.system.listSystems(key)
	for system in systems_list:
		print '{0: <40}'.format(system['name']) + "\t" + str(system['id'])
	spacewalk.auth.logout(key)
	raise SystemExit(0)

# Package search 
def PACKAGE_SEARCH(key, query):
	if args.with_channel is '':
		packages = spacewalk.packages.search.advanced(key, query)
		for package in packages: 
			PRINT_PACKAGE(package['name'],package['version'],package['release'],package['arch'],package['epoch'],package['id'])
	if args.with_channel is not '':
		packages = spacewalk.packages.search.advancedWithChannel(key, query, args.with_channel)
		for package in packages: PRINT_PACKAGE(package['name'],package['version'],package['release'],package['arch'],package['epoch'],package['id'])	

# Get package download URL by package ID
def GET_PACKAGE_URL(key, package_id):
	package_url = spacewalk.packages.getPackageUrl(key, int(package_id))
	print package_url

# Full Satellite report
def FULL_REPORT(key):
	systems_list = spacewalk.system.listSystems(key)
	print '{0: <45}'.format("")            + '{0: <13}'.format("Upgradable") + '{0: <13}'.format("Installed") + '{0: <13}'.format("Relevant") + '{0: <13}'.format("Config")   + '{0: <30}'.format("Running") + '{0: <20}'.format("Base") 
	print '{0: <45}'.format("System name") + '{0: <13}'.format("packages")   + '{0: <13}'.format("packages")  + '{0: <13}'.format("errata")   + '{0: <13}'.format("channels") + '{0: <30}'.format("kernel")  + '{0: <20}'.format("channel") 
	for system in systems_list:
		installed_pkgs = str(spacewalk.system.listPackages(key, system['id']).__len__())
		relevant_errata = str(spacewalk.system.getRelevantErrata(key, system['id']).__len__())
		config_channels = str(spacewalk.system.config.listChannels(key, system['id']).__len__())
		upgradables, duplicates = FIND_UPGRADABLE_PACKAGES(key, system['id'])
		base_channel = BASE_CHANNEL(key, system['id'])
		kernel = spacewalk.system.getRunningKernel(key, system['id'])
		print '{0: <45}'.format(system['name']) + '{0: <13}'.format(str(upgradables.__len__())) + '{0: <13}'.format(installed_pkgs) + '{0: <13}'.format(relevant_errata) + '{0: <13}'.format(config_channels) + '{0: <30}'.format(kernel) + '{0: <20}'.format(base_channel)

## Script logic between options and taken actions is placed here
if SERVER_NAME is not '' and args.list_errata is True     :	LIST_ERRATA(key, SERVER_NAME)
if SERVER_NAME is not '' and args.list_channels is True   :	LIST_CHANNELS(key, SERVER_NAME)
if SERVER_NAME is not '' and args.conf_channels is True   :	LIST_CONF_CHANNELS(key, SERVER_NAME)
if SERVER_NAME is 	  '' and args.ip is not ''			  :	FIND_BY_IP(key, args.ip)
if SERVER_NAME is not '' and args.list_packages is True   :	LIST_PACKAGES(key, SERVER_NAME)
if SERVER_NAME=='' 		 and args.list is True			  :	LIST_SYSTEMS(key)
if SERVER_NAME!=''		 and args.list_upgradable is True :	LIST_UPGRADABLE_PACKAGES(key, SERVER_NAME)
if SERVER_NAME is '' 	 and args.full_report is True	  :	FULL_REPORT(key)
if SERVER_NAME is '' 	 and args.package_search is not '':	PACKAGE_SEARCH(key, args.package_search)
if SERVER_NAME is '' 	 and args.package_download is not '': GET_PACKAGE_URL(key, args.package_download)
if SERVER_NAME is not '' and args.list is True:
	print "ERROR: Defining system name and --list option together is not expected!"
	spacewalk.auth.logout(key)
	raise SystemExit(1)

spacewalk.auth.logout(key)
