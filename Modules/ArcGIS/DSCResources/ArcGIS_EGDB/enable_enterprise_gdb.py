"""
Name: enable_enterprise_gdb.py
Description: Creates a connection file to a SQL Server or PostgreSQL database as the input user credentials and enables an enterprise geodatabase.
Type enable_enterprise_gdb.py -h or enable_enterprise_gdb.py --help for usage
Author: Esri
"""

# Import system modules
import arcpy, os, sys #, optparse

from optparse import OptionParser

parser = OptionParser()

# Define usage and versionparser = optparse.OptionParser(usage = "usage: %prog [Options]", version="%prog 1.0 for " + arcpy.GetInstallInfo()['Version'] )

#Define help and options
parser.add_option ("--DBMS", dest="Database_type", type="choice", choices=['SQLSERVER', 'POSTGRESQL',''], default="", help="Type of enterprise DBMS:  SQLSERVER OR POSTGRESQL.")
parser.add_option ("-s", dest="Server", type="string", default="", help="Geodatabase  Server Name")
parser.add_option ("-d", dest="Database", type="string", default="", help="Geodatabase  name")
parser.add_option ("-u", dest="UserName", type="string", default="", help="Geodatabase  administrator username")
parser.add_option ("-p", dest="Password", type="string", default="", help="Geodatabase  administrator password")
parser.add_option ("-l", dest="Authorization_file", type="string", default="", help="Full path and name of authorization file")


# Check if value entered for option
try:
	(options, args) = parser.parse_args()

	
	#Check if no system arguments (options) entered
	if len(sys.argv) == 1:
		print "%s: error: %s\n" % (sys.argv[0], "No command options given")
		parser.print_help()
		sys.exit(3)
	

	#Usage parameters for spatial database connection
	database_type = options.Database_type.upper()
	instance = options.Server
	account_authentication = 'DATABASE_AUTH'
	username = options.UserName.lower() 
	password = options.Password	
	database = options.Database.lower() 
	license = options.Authorization_file
	
	if( database_type ==""):	
		print(" \n%s: error: \n%s\n" % (sys.argv[0], "DBMS type (--DBMS) must be specified."))
		parser.print_help()
		sys.exit(3)		

	if (license == ""):
		print " \n%s: error: \n%s\n" % (sys.argv[0], "Authorization file (-l) must be specified.")
		parser.print_help()
		sys.exit(3)
		
	if (database_type == "SQLSERVER"):
		database_type = "SQL_SERVER"

	# Get the current product license
	product_license=arcpy.ProductInfo()
	
	if (license == ""):
		print " \n%s: error: %s\n" % (sys.argv[0], "Authorization file (-l) must be specified.")
		parser.print_help()
		sys.exit(3)
	
	# Local variables
	instance_temp = instance.replace("\\","_")
	instance_temp = instance_temp.replace("/","_")
	instance_temp = instance_temp.replace(":","_")
	Conn_File_NameT = instance_temp + "_" + database + "_" + username    
	
	if os.environ.get("TEMP") == None:
		temp = "c:\\temp"	
	else:
		temp = os.environ.get("TEMP")
	
	Connection_File_Name = Conn_File_NameT + ".sde"
	Connection_File_Name_full_path = temp + os.sep + Conn_File_NameT + ".sde"
	print Connection_File_Name_full_path

	# Check for the egdb .sde file and delete it if present
	arcpy.env.overwriteOutput=True
	if os.path.exists(Connection_File_Name_full_path):
		os.remove(Connection_File_Name_full_path)

	print "Creating egdb Database Connection File..."	
	# Process: Create egdb Database Connection File...
	# Usage:  out_file_location, out_file_name, DBMS_TYPE, instance, database, account_authentication, username, password, save_username_password(must be true)
	arcpy.CreateDatabaseConnection_management(out_folder_path=temp, out_name=Connection_File_Name, database_platform=database_type, instance=instance, database=database, account_authentication=account_authentication, username=username, password=password, save_user_pass="TRUE")
        for i in range(arcpy.GetMessageCount()):
		if "000565" in arcpy.GetMessage(i):   #Check if database connection was successful
			arcpy.AddReturnMessage(i)			
			arcpy.AddMessage("Exiting!!")
			sys.exit(3)            
		else:
			arcpy.AddReturnMessage(i)			
	
	# Process: Enable geodatabase egdb...
	try:
		print "Enabling Enterprise Geodatabase egdb..."
		print Connection_File_Name_full_path
		print license
		arcpy.EnableEnterpriseGeodatabase_management(input_database=Connection_File_Name_full_path, authorization_file=license)
		for i in range(arcpy.GetMessageCount()):
			arcpy.AddReturnMessage(i)		
	except:
		for i in range(arcpy.GetMessageCount()):
			arcpy.AddReturnMessage(i)
			
	if os.path.exists(Connection_File_Name_full_path):
		 os.remove(Connection_File_Name_full_path)
	
#Check if no value entered for option	
except SystemExit as e:
	if e.code == 2:
		parser.usage = ""
		print "\n"
		parser.print_help() 
		parser.exit(2)
