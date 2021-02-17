#!/usr/bin/python3

import csv

def ImportImpactScore():
	Impacts = []
	with open('/root/Desktop/MITRE/ImpactScores.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Impacts.append(row)
	return Impacts		


def ImportRelationships():
	Relationships = []
	with open('/root/Desktop/MITRE/technique-mitigation.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Relationships.append(row)
	return Relationships	

def ImportCoverage():
	Coverage = []
	with open('/root/Desktop/MITRE/mitigation-coverage.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Coverage.append(row)
	return Coverage	
		

def CalculateLikelihood(i,comp,OPMODE):
	"""
	The commented code sections belong to an algorithm to accomodate the architectural effects on the likelihood (similar to the Modified score in CVSS).
	But, a decision was to ignore it at this stage since the affect is captured in the calculation of the Detectability score. 
	"""
	#reachability = 0.0

	
	#if OPMODE == "Mode 1":
	#	Reachability_Index	= 6
	#	User_Interaction_Index	= 7
	#if OPMODE == "Mode 2":
	#	Reachability_Index	= 8
	#	User_Interaction_Index	= 9			

	#if comp[Reachability_Index] == "N":
	#	reachability = 0.85
	#elif comp[Reachability_Index] == "A":
	#	reachability = 0.62
	#elif comp[Reachability_Index] == "P":
	#	reachability = 0.2
	#else:
	#	reachability = 0.55
	
	#if comp[User_Interaction_Index] == "P":
	#	if comp[Reachability_Index] == "N":
	#		return float(i[6].replace(",", "."))		
	#	elif comp[Reachability_Index] == "A":
	#		if i[10] in ['0,62','0,55','0,2']:
	#			return float(i[6].replace(",", "."))
	#		elif i[10] == "0,85":
	#			return 8.22 * float(i[7].replace(",", ".")) * float(i[8].replace(",", ".")) * float(i[9].replace(",", ".")) * reachability 
	#		else:
	#			return 0 
	#	elif comp[Reachability_Index] == "P":
	#		if i[10] in ['0,2','0,55']:
	#			return float(i[6].replace(",", "."))
	#		elif i[10] in ['0,85','0,62']:
	#			return 8.22 * float(i[7].replace(",", ".")) * float(i[8].replace(",", ".")) * float(i[9].replace(",", ".")) * reachability 
	#		else:
	#			return 0 
	#	else:
	#		return -1
	#elif comp[User_Interaction_Index] == "NP":
	#	if comp[Reachability_Index] == "N" :
	#		return float(i[6].replace(",", "."))
	#	elif comp[Reachability_Index] == "A":
	#		if i[10] in ['0,62','0,55','0,2']:
	#			return float(i[6].replace(",", "."))
	#		elif i[10] == "0,85":
	#			return 8.22 * float(i[7].replace(",", ".")) * float(i[8].replace(",", ".")) * float(i[9].replace(",", ".")) * reachability
	#		else:
	#			return 0
	#	elif comp[Reachability_Index] == "P":
	#		if i[10] in ['0,2','0,55']:
	#			return float(i[6].replace(",", "."))
	#		elif i[10] in ['0,85','0,62']:
	#			return 8.22 * float(i[7].replace(",", ".")) * float(i[8].replace(",", ".")) * float(i[9].replace(",", ".")) * reachability 
	#		else:
	#			return 0
	#	else:
	#		return 0
	#else:
	#	return 0
	return float(i[6].replace(",", "."))	


def CalculateImpact(i,comp,OPMODE,ImpactScores,Matrix):
	"""
	Technique name : i[1]
	Tactics: i[2]

	Component name  comp[1]:

	OPMode : from function call

	ImpactScore Headers
	0	1		2	3	4	5	6	7	8	9	10	11	12		
	OPmode	Comp_name	IPC	SC	FC1	FC2	LIC	CC	ODC	C2CF	C2MF	Zero	OCC
	
	"""
	Safety_Factor = 1
	Impact_Sub_Score = 0
	Safety_Index = 11
	Safety_Factor = 1
	Operational_Index = 11
	Operational_Factor = 1
	Financial_Index = 11
	Financial_Factor = 1
	Privacy_Index1 = 11
	Privacy_Index2 = 11
	Privacy_Factor = 1
	ODC_Index = 11
	ODC_Factor = 1
	if Matrix == "ICS" and "impact" in i[2] and i[1] == "Damage to Property":	
		Operational_Index=7
		Safety_Index=3
		Privacy_Index1=11
		Privacy_Index2=2
		Financial_Index=5
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and "impact-ics" in i[2] and i[1]== "Loss of Availability":
		Operational_Index=7
		Safety_Index=3 
		Privacy_Index1=11
		Privacy_Index2=2
		Financial_Index=5
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "impact" in i[2] and i[1]== "Data Encrypted for Impact":
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index = 2
		Privacy_Index1=11
		ODC_Index = 8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Enterprise" and "impact" in i[2] and (i[1]== "Data Encrypted for Impact" or i[1]==  "Defacement" or i[1]=="Internal Defacement" or i[1]=="External Defacement"):
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 2	
		Privacy_Index1=11
		ODC_Index = 8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Enterprise" and "impact" in i[2] and (i[1]== "Data Destruction" or i[1]== "Data Manipulation" or  i[1]== "Disk Wipe" or i[1]== "Disk Content Wipe" or i[1]== "Disk Structure Wipe" or i[1]== "Runtime Data Manipulation" or i[1]== "Stored Data Manipulation" or i[1]== "Runtime Data Manipulation"  or i[1]=="Transmitted Data Manipulation"):
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 2
		Privacy_Index1=11
		ODC_Index = 11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "network-effects" in i[2] and i[1]== "Manipulate Device Communication":
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 2
		Privacy_Index1=11
		ODC_Index = 11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "remote-service-effects" in i[2] and i[1]== "Remotely Wipe Data Without Authorization":
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 2
		Privacy_Index1=11
		ODC_Index = 11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and "execution-ics" in i[2]:
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2= 11
		Privacy_Index1=11
		ODC_Index = 8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1	
	elif Matrix=="Enterprise" and "impact" in i[2] and (i[1]== "Account Access Removal" or i[1]==  "Resource Hijacking"):
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 11
		Privacy_Index1=11
		ODC_Index = 8	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and "impact-ics" in i[2] and (i[1]== "Loss of Productivity and Revenue" or i[1]=="Loss of Safety"):
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 11
		Privacy_Index1=11
		ODC_Index = 11		

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1	
	elif Matrix=="Enterprise" and "impact" in i[2] and (i[1]== "Endpoint Denial of Service" or  i[1]== "Firmware Corruption" or i[1]==  "Inhibit System Recovery" or  i[1]== "Network Denial of Service" or i[1]=="Service Stop" or i[1]=="System Shutdown/Reboot" or i[1]== "Direct Network Flood" or i[1]=="Reflection Amplification" or i[1]=="OS Exhaustion Flood" or i[1]=="Service Exhaustion Flood" or i[1]=="Application Exhaustion Flood" or i[1]=="Application or System Exploitation" ):
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 11
		Privacy_Index1=11
		ODC_Index = 11	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and "inhibit-response-function" in i[2]:
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2=11
		Privacy_Index1=11
		ODC_Index = 11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1			
	elif Matrix=="Mobile" and "network-effects" in i[2] and i[1]== "Jamming or Denial of Service":
		Safety_Index = 11
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 11
		Privacy_Index1=11
		ODC_Index = 11	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "impact" in i[2] and i[1]== "Delete Device Data":
		Safety_Index = 3
		Operational_Index = 7
		Financial_Index = 5
		Privacy_Index2 = 2
		Privacy_Index1=11
		ODC_Index = 11	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1		
	elif Matrix=="Mobile" and "network-effects" in i[2] and i[1]== "Downgrade to Insecure Protocols":
		Operational_Index=7
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "execution" in i[2]:
		Operational_Index=7
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=5
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Enterprise" and "execution" in i[2]:
		Operational_Index=7
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=5
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1		
	elif Matrix=="Mobile" and "network-effects" in i[2] and (i[1]== "Rogue Cellular Base Station" or i[1]=="Rogue Wi-Fi Access Points"):
		Operational_Index=7
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=8	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "impact" in i[2] and i[1]== "SMS Control":
		Operational_Index=7
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=8	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1	
	elif Matrix=="Mobile" and "network-effects" in i[2] and i[1]== "SIM Card Swap":
		Operational_Index=7
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "impact" in i[2] and (i[1]== "Clipboard Modification" or i[1]==  "Device Lockout" or i[1]==  "Input Injection" or i[1]==  "Modify System Partition"):
		Operational_Index=7
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "network-effects" in i[2] and i[1]== "Exploit SS7 to Redirect Phone Calls/SMS":
		Operational_Index=7
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=11	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1	
	elif Matrix=="ICS" and "impact-ics" in i[2] and i[1]== "Manipulation of Control":
		Operational_Index=9
		Safety_Index=3
		privacy_Index1=11
		privacy_Index2=11
		Financial_Index=5
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and "impair-process-control" in i[2]:
		Operational_Index=9
		Safety_Index=3
		privacy_Index1=11
		privacy_Index2=11
		Financial_Index=5
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1		
	elif Matrix=="ICS" and "impact-ics" in i[2] and (i[1]== "Denial of Control" or  i[1]== "Loss of Control"):
		Operational_Index=9
		Safety_Index=3
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and "impact-ics" in i[2] and (i[1]== "Denial of View" or i[1]==  "Loss of View" or i[1]== "Manipulation of View"):
		Operational_Index=10
		Safety_Index=3
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=5
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and "collection" in i[2]:
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=6
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "collection" in i[2]:
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=6
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=11	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1	
	elif Matrix=="Enterprise" and "collection" in i[2]:
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=6
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "network-effects" in i[2] and i[1]== "Exploit SS7 to Track Device Location":
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=6
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "remote-service-effects" in i[2] and i[1]== "Remotely Track Device Without Authorization":
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=6
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Enterprise" and "exfiltration" in i[2]:
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and "impact-ics" in i[2] and i[1]== "Theft of Operational Information":
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "exfiltration" in i[2]:
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "network-effects" in i[2] and i[1]== "Eavesdrop on Insecure Network Communication":
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "remote-service-effects" in i[2] and i[1]== "Obtain Device Cloud Backups":
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=2
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "impact" in i[2] and i[1]== "Carrier Billing Fraud":
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=4
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif (Matrix=="Enterprise" or Matrix=="Mobile")  and (("defense-evasion" in i[2]) or ("persistence" in i[2]) or ("privilege-escalation" in i[2])):
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=12

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif (Matrix=="Enterprise" or Matrix=="Mobile")  and (("command-and-control" in i[2]) or ("credential-access" in i[2]) or ("discovery" in i[2]) or ("initial-access" in i[2]) or ("lateral-movement" in i[2])):
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and (("command-and-control-ics" in i[2]) or ("discovery-ics" in i[2]) or ("initial-access" in i[2]) or ("lateral-movement-ics" in i[2])):
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=8

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="ICS" and (("evasion-ics" in i[2]) or ("persistence-ics" in i[2])):
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=12

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	elif Matrix=="Mobile" and "impact" in i[2] and (i[1]== "Generate Fraudulent Advertising Revenue" or i[1]==  "Manipulate App Store Rankings or Ratings"):
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=11

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1
	else:
		Operational_Index=11
		Safety_Index=11
		Privacy_Index1=11
		Privacy_Index2=11
		Financial_Index=11
		ODC_Index=11	

		Safety_Factor = 1
		Financial_Factor = 1
		Privacy_Factor = 1
		ODC_Factor = 1
		Operational_Factor = 1	
		print("something went wrong")
	
	for Index in ImpactScores:
		if comp[1] == Index[1] and OPMODE == Index[0]: 
			# Importance of location privacy			
			Privacy1_Factor = 0
			# Importance of Information and Process confidentiality
			Privacy2_Factor = 1
			CombindPrivacy= (Privacy1_Factor*float(Index[Privacy_Index1].replace(",", "."))) + (Privacy2_Factor*float(Index[Privacy_Index2].replace(",", "."))) 
			Scaled = CombindPrivacy/(Privacy1_Factor+Privacy2_Factor)
			Impact_Sub_Score = float(Index[Operational_Index].replace(",", ".")) + (Safety_Factor*float(Index[Safety_Index].replace(",", "."))) + Privacy_Factor*Scaled + (Financial_Factor*float(Index[Financial_Index].replace(",", "."))) + (ODC_Factor*float(Index[ODC_Index].replace(",", ".")))
		#print("Component and Operational Mode Found")
	return Impact_Sub_Score		

def GetTechniqueMitigations(i,TechMitRelationships, Matrix):
	Mitigations = []
	for relationship in TechMitRelationships:
		if i[1] == relationship[2] and Matrix == relationship[1]:
			Mitigations.append(relationship[3])
	Mitigations = list(set(Mitigations))
	#print("Mitigations for "+i[1]+" = "+str(Mitigations))
	return Mitigations

def GetMitigationsCoverage(comp,MitigationCoverage,Mitigations):
	Coverage = 0
	for each in Mitigations:
		for mitigation in MitigationCoverage:
			if each == mitigation[0]:
				if mitigation[int(comp[10])] == "1":				
					Coverage = Coverage + 1
	#print("Coverage for component "+comp[1]+" = "+str(Coverage))
	return Coverage

def CalculateDetectability(i,comp,Mode,TechMitRelationships, MitigationCoverage,Matrix):
	Detectability = 0
	TechniqueMitigations = GetTechniqueMitigations(i,TechMitRelationships, Matrix)	
	MitigationsCoverage = GetMitigationsCoverage(comp,MitigationCoverage,TechniqueMitigations)
	if MitigationsCoverage > 0:
		Detectability = 0.5
	else:
		Detectability = 1
	return Detectability

def GetRiskRating(Risk):

	Low_Threshold = 4.85880347
	Medium_Threshold = 9.71760694
	High_Threshold = 14.57641041
	Critical_Threshold = 19.43521388
	if 0 <= Risk <= Low_Threshold:
		return "Low"
	elif Low_Threshold < Risk <= Medium_Threshold:
		return "Medium" 
	elif Medium_Threshold < Risk <= High_Threshold:
		return "High"
	elif High_Threshold < Risk <= Critical_Threshold:
		return "Critical"	
	else:
		return "N/A"
	
def MatchwithMobileTechniques(comp):	
	"""
	CSV Header
	0	1	2			3	4		5		6		7	8	9	10
	number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V
	"""
	x = 1
	MobileTechnieques = []
	with open('/root/Desktop/MITRE/Techniques/mobile.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			temp2 = []
			if comp[5] in row[5] and comp[4] in row[4]:
				temp2 = row[2].split(",")			
				for tactic in temp2:
					temp = []
					temp = row
					temp[2] = tactic.replace("[","").replace("]","").replace(" ","").replace("'","").replace('"','')
					MobileTechnieques.append(list(temp))
					#x = x + 1 
					#print("Saved-"+str(x))
					#print(MobileTechnieques[-1])
	return MobileTechnieques

def MatchwithICSTechniques(comp):	
	"""
	CSV Header
	0	1	2			3	4		5		6		7	8	9	10
	number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V
	"""
	ICSTechnieques = []
	with open('/root/Desktop/MITRE/Techniques/ics.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			temp2 = []
			if comp[2] in row[3]:
				temp2 = row[2].split(",")
				for tactic in temp2:
					temp = []
					temp = row
					temp[2] = tactic.replace("[","").replace("]","").replace(" ","").replace("'","").replace('"','')
					ICSTechnieques.append(list(temp))
	return ICSTechnieques

def MatchwithEnterpriseTechniques(comp):	
	"""
	CSV Header
	0	1	2			3	4		5		6		7	8	9	10
	number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V	
	"""

	EnterpriseTechnieques = []
	temp = []
	with open('/root/Desktop/MITRE/Techniques/enterprise_capec.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			temp2 = []
			if comp[3] in row[3]:
				temp2 = row[2].split(",")
				for tactic in temp2:
					temp = []
					temp = row
					#print("before")
					#print(row)
					temp[2] = tactic.replace("[","").replace("]","").replace(" ","").replace("'","").replace('"','')
					#print("after")
					#print(temp)
					EnterpriseTechnieques.append(list(temp))
					#print("Saved")
					#print(EnterpriseTechnieques[-1])
	return EnterpriseTechnieques		

def LoadComponents():	
	"""
	CSV Header
	0	1	2	3		4		5		6			7	8			9	10
	class	name	type	platform	technology	Additions	ReachabilityMode1	UIMode1	ReachabilityMode2	UIMode2	Index
	"""
	Components = []
	with open('components.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Components.append(row)
		return Components

#	Loading impact file
ImpactScores = ImportImpactScore()
#	Loading Techiques-Mitigations Relationships file
TechMitRelationships = ImportRelationships()
#	Loading Mitigations Coverage file
MitigationCoverage = ImportCoverage()

print("Opmode; comp.;tech_ID;tech_name;tactic;platforms;CVSS_Exp;Impact;Detectability;Risk;Rating;Mitigations")
# Printing the components
Components = LoadComponents()
for comp in Components:
	CompMobileAttacks = []
	CompICSAttacks = []
	CompEnterpriseAttacks = []
	
	#Printing the class	
	#print("=======[Component info]=========")
	#print("Class: "+comp[0])
	
	#Printing the name	
	#print("Name: "+comp[1])
	
	#Printing the type
	#if comp[2] == "[]":
	#	print("Type: Not Specified")
	#else:
	#	print("Type: "+comp[2])
	
	#Printing the platform(s)
	#if comp[3] == "[]":
	#	print("Platform(s): Not Specified")
	#else:
	#	print("platform(s): "+comp[3])	
	
	#Printing SIM usage
	#if comp[4] == "1":
	#	print("Sim usage: "+"True")
	#else:
	#	print("Sim usage: "+"False")

	# Matching with the relevant ATT&CK Matrix
	if comp[0] == "IT/Mobile":
		CompMobileAttacks= MatchwithMobileTechniques(comp)
		#y = 1
		#for x in CompMobileAttacks:
		#	y= y + 1
		#	print(str(x)+"-"+str(y))
		CompEnterpriseAttacks = MatchwithEnterpriseTechniques(comp)
	elif comp[0] == "Mobile":
		CompMobileAttacks= MatchwithMobileTechniques(comp)
		#y = 1
		#for x in CompMobileAttacks:
		#	y= y + 1
		#	print(str(x)+"-"+str(y))
	elif comp[0] == "IT":
		CompEnterpriseAttacks = MatchwithEnterpriseTechniques(comp)
	elif comp[0] == "OT/IT":
		CompEnterpriseAttacks = MatchwithEnterpriseTechniques(comp)
		CompICSAttacks = MatchwithICSTechniques(comp)	
	elif comp[0] == "OT":
		CompICSAttacks = MatchwithICSTechniques(comp)
	elif comp[0] == "OT/IT/Mobile":
		CompICSAttacks = MatchwithICSTechniques(comp)
		CompMobileAttacks= MatchwithMobileTechniques(comp)
		#y = 1
		#for x in CompMobileAttacks:
		#	y= y + 1
		#	print(str(x)+"-"+str(y))
		CompEnterpriseAttacks = MatchwithEnterpriseTechniques(comp)

	else:
		print("Unknown component class: matching not completed")
	Likelihood = 0
	Impact = 0
	Risk = 0
	OPModes = ['Mode 1','Mode 2']
	for Mode in OPModes:
		if len(CompMobileAttacks)>0:
			#print("===========[ Related Mobile Attacks ] ==============")
			"""
			CSV Header
			0	1	2			3	4		5		6		7	8	9	10
			number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V
			"""
			j=1
			Matrix = "Mobile"
			for i in CompMobileAttacks:
				Likelihood = CalculateLikelihood(i,comp,Mode)
				Impact = CalculateImpact(i,comp,Mode,ImpactScores,Matrix)
				Detectability = CalculateDetectability(i,comp,Mode,TechMitRelationships, MitigationCoverage,Matrix)
				MitigationsList = GetTechniqueMitigations(i,TechMitRelationships, Matrix)
				Risk = Likelihood * Impact * Detectability
				Rating = GetRiskRating(Risk)
				#print(i)
				print(str(Mode)+";"+comp[1]+";"+"Mob-Tech-"+str(j)+";"+str(i[1])+";"+str(i[2])+";"+"[]"+";"+str(Likelihood).replace(".", ",")+";"+str(Impact).replace(".", ",")+";"+str(Detectability).replace(".", ",") + ";"+ str(Risk).replace(".", ",")+";"+str(Rating)+";"+str(MitigationsList))
				j = j +1 
				#print("-----------------------------")
		if len(CompEnterpriseAttacks)>0:
			#print("===========[ Related IT Attacks ] ==============")
			"""
			CSV Header
			0	1	2			3	4		5		6		7	8	9	10
			number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V	
			"""
			j=1
			#comp.; tech_ID; tech_name; tactic; platforms; CAPEC Likelihood; impact_type; CAPEC ID ; CVSS_Exp
			Matrix = "Enterprise"
			for i in CompEnterpriseAttacks:
				Likelihood = CalculateLikelihood(i,comp,Mode)
				Impact = CalculateImpact(i,comp,Mode,ImpactScores,Matrix)
				Detectability = CalculateDetectability(i,comp,Mode,TechMitRelationships, MitigationCoverage,Matrix)
				MitigationsList = GetTechniqueMitigations(i,TechMitRelationships, Matrix)
				Risk = Likelihood * Impact * Detectability
				Rating = GetRiskRating(Risk)
				print(str(Mode)+";"+comp[1]+";"+"IT-Tech-"+str(j)+";"+str(i[1])+";"+str(i[2])+";"+str(i[3])+";"+str(Likelihood).replace(".", ",")+";"+str(Impact).replace(".", ",")+";"+str(Detectability).replace(".", ",") + ";"+ str(Risk).replace(".", ",")+";"+str(Rating)+";"+str(MitigationsList))
				j = j +1 
				#print("-----------------------------")
		if len(CompICSAttacks)>0:
			#print("===========[ Related ICS Attacks ] ==============")
			"""
			CSV Header
			0	1	2			3	4		5		6		7	8	9	10
			number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V
			"""
			j=1
			Matrix = "ICS"
			for i in CompICSAttacks:
				#print(i)
				Likelihood = CalculateLikelihood(i,comp,Mode)
				Impact = CalculateImpact(i,comp,Mode,ImpactScores,Matrix)
				Detectability = CalculateDetectability(i,comp,Mode,TechMitRelationships, MitigationCoverage,Matrix)
				MitigationsList = GetTechniqueMitigations(i,TechMitRelationships, Matrix)
				Risk = Likelihood * Impact * Detectability
				Rating = GetRiskRating(Risk)
				print(str(Mode)+";"+comp[1]+";"+"ICS-Tech-"+str(j)+";"+str(i[1])+";"+str(i[2])+";"+str(i[3])+";"+str(Likelihood).replace(".", ",")+";"+str(Impact).replace(".", ",")+";"+str(Detectability).replace(".", ",") + ";"+ str(Risk).replace(".", ",")+";"+str(Rating)+";"+str(MitigationsList))
				j = j +1 
				


		#print("-----------------------------")
		#print("Printed all components attacks in Operational mode: "+ Mode)
	#print("===========[ Related Attacks Summary ]==============")		
	#print("Numner of Mobile atttacks: "+str(len(CompMobileAttacks)))
	#print("Numner of IT atttacks: "+str(len(CompEnterpriseAttacks)))
	#print("Numner of ICS atttacks: "+str(len(CompICSAttacks)))	
	#print("\n")

#input("Press Enter to continue...")
