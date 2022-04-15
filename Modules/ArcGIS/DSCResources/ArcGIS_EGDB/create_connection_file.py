"""
Name: create_connection_file.py
Description: Creates a connection file to a SQL Server or PostgreSQL database as the input user credentials.
Type create_connection_file.py -h or create_connection_file.py --help for usage
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
parser.add_option ("-o", dest="OutputFolder", type="string", default="", help="Full path for the output connection file")
parser.add_option ("-f", dest="OutputFile", type="string", default="", help="File Name for the output connection file")

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
	username = options.UserName
	password = options.Password	
	database = options.Database	
	opfolder = options.OutputFolder
	opfile   = options.OutputFile

	if( database_type ==""):	
		print(" \n%s: error: \n%s\n" % (sys.argv[0], "DBMS type (--DBMS) must be specified."))
		parser.print_help()
		sys.exit(3)	

	if (database_type == "SQLSERVER"):
		database_type = "SQL_SERVER"

	Connection_File_Out_Folder  = opfolder
	Connection_File_Name		= opfile
	Connection_File_Name_full_path = Connection_File_Out_Folder + os.sep + Connection_File_Name
	print Connection_File_Out_Folder
	print Connection_File_Name

	# Check for the egdb .sde file and delete it if present
	arcpy.env.overwriteOutput=True
	if os.path.exists(Connection_File_Name_full_path):
		os.remove(Connection_File_Name_full_path)

	print "Creating egdb Database Connection File..."	
	# Process: Create egdb Database Connection File...
	# Usage:  out_file_location, out_file_name, DBMS_TYPE, instance, database, account_authentication, username, password, save_username_password(must be true)
	arcpy.CreateDatabaseConnection_management(out_folder_path=Connection_File_Out_Folder, out_name=Connection_File_Name, database_platform=database_type, instance=instance, database=database, account_authentication=account_authentication, username=username, password=password, save_user_pass="TRUE")
        for i in range(arcpy.GetMessageCount()):
		if "000565" in arcpy.GetMessage(i):   #Check if database connection was successful
			arcpy.AddReturnMessage(i)			
			arcpy.AddMessage("Exiting!!")
			sys.exit(3)            
		else:
			arcpy.AddReturnMessage(i)			
	
#Check if no value entered for option	
except SystemExit as e:
	if e.code == 2:
		parser.usage = ""
		print "\n"
		parser.print_help() 
		parser.exit(2)
