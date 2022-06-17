#!/usr/bin/python3

import csv
import time
import datetime  
import sys
import os
import colorama
from colorama import Fore, Back, Style

PrintRisks = 0
try: 
	if "-p" in sys.argv[1]:
		PrintRisks = 1
except:
	pass


current_time=datetime.datetime.now()
#WorkingDirectory = "/root/Desktop/FMECA-ATT&CK[Latest]/MITRE/mA2/Comparison/"

def ImportImpactScore():
	Impacts = []
	with open('ImpactScores.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Impacts.append(row)
	return Impacts		


def ImportRelationships():
	Relationships = []
	with open('technique-mitigation.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Relationships.append(row)
	return Relationships	

def ImportCoverage(filename):
	Coverage = []
	with open(filename, newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Coverage.append(row)
	return Coverage	
	
	
def ImportFMMT():
	Metrics = []
	with open('FMMT.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Metrics.append(row)
	return Metrics			

def CalculateLikelihood(i,comp,OPMODE):
	return float(i[6].replace(",", "."))	


def CalculateImpact(i,comp,OPMODE,ImpactScores,Matrix,FailureMetrics):
	"""
	Technique name : i[1]
	Tactics: i[2]

	Component name  comp[1]:

	OPMode : from function call

	ImpactScore Headers
	0	1		2	3	4	5	6	7	8	9	10	11	12	13	14
	OPmode	Comp_name	IPC	SC	FC1	FC2	LIC	CC	ODC	C2CF	C2MF	Zero	OCC
	mode	name		IPC	SC	FC1	FC2	LIC	CC	ODC	C2CF	C2MF	Zero	OCC	EC	RC
	
	FailureMetrics Headers
	0	1		2	3	4	5	6	7	8
	Matrix	Failure Mode	O	S	I	F	SE	R	E


	"""
	
	Impact_Sub_Score = 0
	
	Safety_Factor = 1
	Operational_Factor = 1
	Financial_Factor = 1	
	ODC_Factor = 1
	Reputation_Factor = 1
	Environmental_Factor = 1
	Privacy_Factor = 1		
	
	Safety_Index = 11
	Operational_Index = 11
	Financial_Index = 11
	Privacy_Index = 11
	ODC_Index = 11
	Reputation_Index = 11
	Environmental_Index = 11
	for metric in FailureMetrics:
		if "impact" not in i[2] and "network-effects" not in i[2] and "remote-service-effects" not in i[2]:
			#print(metric)
			#print("Not Impact Tactic - if  '"+ i[2] +"' == '"+str(metric[1])+"' and '"+str(Matrix)+"' == '"+str(metric[0])+"'")
			if  i[2] in metric[1] and Matrix in metric[0]:
				#print("metric[2] =" + metric[2])
				if metric[2] == "I2MF":
					Operational_Index = 10
				elif metric[2] == "I2CF":
					Operational_Index = 9	
				elif metric[2] == "OOI":
					Operational_Index = 7					
				elif metric[2] == "":
					Operational_Index = 11
				
				#print("metric[3] =" + metric[3])	
				if metric[3] == "SC":
					Safety_Index = 3				
				elif metric[3] == "":
					Safety_Index = 11	
				
				#print("metric[4] =" + metric[4])
				if metric[4] == "IC":
					Privacy_Index = 2
				elif metric[4] == "LIC":
					Privacy_Index = 6				
				elif metric[4] == "":
					Privacy_Index = 11	
					
				#print("metric[5] =" + metric[5])					
				if metric[5] == "FC": #FC metric refers to FC2 in the imapact score table
					Financial_Index = 5
				elif metric[5] == "FC2": #dont be confused that FC2 here refers to FC1 in the impact score table. Just lazy design
					Financial_Index = 4				
				elif metric[5] == "":
					Financial_Index = 11	
				
				#print("metric[6] =" + metric[6])
				if metric[6] == "ODC":
					ODC_Index = 8
				elif metric[6] == "OCC":
					ODC_Index = 12					
				elif metric[6] == "":
					ODC_Index = 11						

				try:
					#print("metric[7] =" + metric[7])
					if metric[7] == "RC":
						Reputation_Index = 14				
					elif metric[7] == "":
						Reputation_Index = 11
				except:
					#print("No Impact Score for the Reputation Consequence")		
					none = 1	
				
				try:
					#print("metric[8] =" + metric[8])
					if metric[8] == "EC":
						Environmental_Index = 13				
					elif metric[8] == "":
						Environmental_Index = 11										
				except:
					#print("No Impact Score for the Environmental Consequence")
					none = 1	
		else:
			#print("Impact Tactic - if  '"+ i[1] +"' == '"+str(metric[1])+"' and '"+str(Matrix)+"' == '"+str(metric[0])+"'")
			if  i[1] in metric[1] and Matrix in metric[0]:
				#print("metric[2] =" + metric[2])
				if metric[2] == "I2MF":
					Operational_Index = 10
				elif metric[2] == "I2CF":
					Operational_Index = 9	
				elif metric[2] == "OOI":
					Operational_Index = 7					
				elif metric[2] == "":
					Operational_Index = 11
				
				#print("metric[3] =" + metric[3])	
				if metric[3] == "SC":
					Safety_Index = 3				
				elif metric[3] == "":
					Safety_Index = 11	

				#print("metric[4] =" + metric[4])
				if metric[4] == "IC":
					Privacy_Index = 2
				elif metric[4] == "LIC":
					Privacy_Index = 6				
				elif metric[4] == "":
					Privacy_Index = 11	
					
				#print("metric[5] =" + metric[5])					
				if metric[5] == "FC": #FC metric refers to FC2 in the imapact score table
					Financial_Index = 5
				elif metric[5] == "FC2": #dont be confused that FC2 here refers to FC1 in the impact score table. Just lazy design
					Financial_Index = 4				
				elif metric[5] == "":
					Financial_Index = 11	

				#print("metric[6] =" + metric[6])
				if metric[6] == "ODC":
					ODC_Index = 8	
				elif metric[6] == "OCC":
					ODC_Index = 12									
				elif metric[6] == "":
					ODC_Index = 11						

				try:
					#print("metric[7] =" + metric[7])
					if metric[7] == "RC":
						Reputation_Index = 14				
					elif metric[7] == "":
						Reputation_Index = 11
				except:
					#print("No Impact Score for the Reputation Consequence")		
					none = 1	
				try:	
					#print("metric[8] =" + metric[8])
					if metric[8] == "EC":
						Environmental_Index = 13				
					elif metric[8] == "":
						Environmental_Index = 11
				except:
					#print("No Impact Score for the Environmental Consequence")		
					none = 1
	for Index in ImpactScores:
		if comp[1] == Index[1] and OPMODE == Index[0]: 
			#CombindPrivacy= (Privacy1_Factor*float(Index[Privacy_Index1].replace(",", "."))) + (Privacy2_Factor*float(Index[Privacy_Index2].replace(",", "."))) 
			#Scaled = CombindPrivacy/(Privacy1_Factor+Privacy2_Factor)
			Impact_Sub_Score = Operational_Factor*float(Index[Operational_Index].replace(",", ".")) + Safety_Factor*float(Index[Safety_Index].replace(",", ".")) + Privacy_Factor*float(Index[Privacy_Index].replace(",", ".")) + (Financial_Factor*float(Index[Financial_Index].replace(",", "."))) + (ODC_Factor*float(Index[ODC_Index].replace(",", "."))) + (Reputation_Factor*float(Index[Reputation_Index].replace(",", "."))) + (Environmental_Factor*float(Index[Environmental_Index].replace(",", ".")))

		#print("Component and Operational Mode Found")
			#print("Tactic "+i[2]+" Techniqe "+i[1]+" - Impact = "+str(Impact_Sub_Score))
	return Impact_Sub_Score		

def GetTechniqueMitigations(i,TechMitRelationships, Matrix):
	Mitigations = []
	Detections= []
	for relationship in TechMitRelationships:
		if i[1] == relationship[2] and Matrix == relationship[1]:
			Mitigations.append(relationship[3])
			Detections.append(relationship[5])
	Mitigations = list(set(Mitigations))
	Detections = list(set(Detections))
	#print("Mitigations for "+i[1]+" = "+str(Mitigations))
	return Mitigations,Detections

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
	TechniqueMitigations,Detections = GetTechniqueMitigations(i,TechMitRelationships, Matrix)	
	MitigationsCoverage = GetMitigationsCoverage(comp,MitigationCoverage,TechniqueMitigations)
	if MitigationsCoverage > 0:
		Detectability = 0
	else:
		Detectability = 1
	return Detectability

def GetRiskRating(Risk):

	#All1
	Low_Threshold = 4.85880347
	Medium_Threshold = 9.71760694
	High_Threshold = 14.57641041
	Critical_Threshold = 19.43521388

	#StagingX10
	#Low_Threshold = =6.50121791550824
	#Medium_Threshold = 13.00243583
	#High_Threshold = 19.50365375
	#Critical_Threshold = 26.00487166
	if 0 <= Risk <= Low_Threshold:
		return "Low"
	elif Low_Threshold < Risk <= Medium_Threshold:
		return "Medium" 
	elif Medium_Threshold < Risk <= High_Threshold:
		return "High"
	elif High_Threshold < Risk: #<= Critical_Threshold:
		return "Critical"	
	else:
		return "N/A"
	
def MatchwithMobileTechniques(comp):	
	"""
	CSV Header
	0	1	2			3	4		        5		    6		    7	    8	    9	    10
	number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V
    
    
	0	    1	    2	    3		    4		    5		    6			        7	    8			    9	    10
	class	name	type	platform	technology	Additions	ReachabilityMode1	UIMode1	ReachabilityMode2	UIMode2	Index    
	"""
	x = 1
	MobileTechnieques = []
	with open('mobile.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:			
			temp2 = []
			
			adds = comp[5].split(",")
			techs = comp[4].split(",")	
			for add in adds:
				for tech in techs:
					if add in row[5] and tech in row[4]:
						temp2 = row[2].split(",")			
						for tactic in temp2:
							temp = []
							temp = row
							temp[2] = tactic.replace("[","").replace("]","").replace(" ","").replace("'","").replace('"','')
							if list(temp) not in MobileTechnieques:
								MobileTechnieques.append(list(temp))																
	return MobileTechnieques

def MatchwithICSTechniques(comp):	
	"""
	CSV Header
	0	1	2			3	4		5		6		7	8	9	10
	number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V
	"""
	ICSTechnieques = []
	with open('ics.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)	
		for row in reader:		
			temp2 = []
			types =  comp[2].split(",")
			for eachtype in types: 
				#print("if "+eachtype+" in "+row[3])
				if eachtype in row[3]:
					#print("TRUE")
					temp2 = row[2].split(",")
					for tactic in temp2:
						temp = []
						temp = row	
						temp[2] = tactic.replace("[","").replace("]","").replace(" ","").replace("'","").replace('"','')
						if list(temp) not in ICSTechnieques:
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
	with open('enterprise_capec.csv', newline='') as f:
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
	0	    1	    2	    3		    4		    5		    6			        7	    8			    9	    10
	class	name	type	platform	technology	Additions	ReachabilityMode1	UIMode1	ReachabilityMode2	UIMode2	Index
	"""
	Components = []
	with open('components.csv', newline='') as f:
		reader = csv.reader(f, delimiter=';', quoting=csv.QUOTE_NONE)
		for row in reader:
			Components.append(row)
		return Components











# Get the list of all files and directories
path = "Strategies/"
MitigationStrategies = os.listdir(path)
print("Algorithm by "+Back.RED+Fore.WHITE+"Ahmed W. Amro"+Style.RESET_ALL+"for comparing the risk reduction levels \nbetween different cyber risk management strategies")
if not PrintRisks:
	print(Back.BLUE+"[To print the risk report, re-run the script and add -p argument]"+Style.RESET_ALL)
print(Back.BLACK+"========================================================================================================================="+Style.RESET_ALL)
#print("Files and directories in '", path, "' :")
RiskScores = []
print("{:40} {:20} {:20} {:20} {:20}".format("Strategy", "Low Risks", "Medium Risks", "High Risks", "Critical Risks"))
print("{:40} {:20} {:20} {:20} {:20}".format("========", "=========", "============", "==========", "=============="))

for strategy in MitigationStrategies:
	if "[IGNORE]" in strategy:
		MitigationStrategies.remove(strategy)

for strategy in MitigationStrategies:

	MitigationCoverage = []
	MitigationCoverage = ImportCoverage(path+strategy)		

	ImpactScores = ImportImpactScore()
	TechMitRelationships = ImportRelationships()
	FailureMetrics = ImportFMMT()
	Components = LoadComponents()

	# Statistics
	OverallRisk = 0
	Low_Risks = 0
	Medium_Risks = 0
	High_Risks = 0
	Critical_Risks = 0


	if PrintRisks:
		#OutputFileName="AllAttacks-"+current_time.strftime("%Y.%m.%d-%H.%M.%S")+".csv"
		OutputFileName="TempAllAttacks-["+strategy+"].csv"
		OutputFile = open(OutputFileName, 'w')
		Header="Opmode; comp.;tech_ID;MITRE_ID;tech_name;tactic;platforms;CVSS_Exp;Impact;Detectability;Risk;Rating;Mitigations;Detection;system_requirements"
		OutputFile.write(Header+"\n")  # python will convert \n to os.linesep

	for comp in Components:
	
	
		CompMobileAttacks = []
		CompICSAttacks = []
		CompEnterpriseAttacks = []
		
		# Matching with the relevant ATT&CK Matrix
		if comp[0] == "IT/Mobile":
			CompMobileAttacks= MatchwithMobileTechniques(comp)
			CompEnterpriseAttacks = MatchwithEnterpriseTechniques(comp)
		elif comp[0] == "Mobile":
			CompMobileAttacks= MatchwithMobileTechniques(comp)
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
			CompEnterpriseAttacks = MatchwithEnterpriseTechniques(comp)
			
		elif comp[0] == "OT/Mobile":
			CompICSAttacks = MatchwithICSTechniques(comp)	
			CompMobileAttacks= MatchwithMobileTechniques(comp)
		else:
			print("Unknown component class: matching not completed")

		OPModes = ['Mode 1']
		for Mode in OPModes:
			Likelihood = 0
			Impact = 0
			Risk = 0
			Rating=""
			ResultString = ""		
			if len(CompMobileAttacks)>0:
				#print("===========[ Related Mobile Attacks ] ==============")
				"""
				CSV Header
				0	1	2			3	4		5		6		7	8	9	10	11
				number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V	id
				"""
				j=1
				Matrix = "Mobile"
				for i in CompMobileAttacks:
					Likelihood = CalculateLikelihood(i,comp,Mode)
					Impact = CalculateImpact(i,comp,Mode,ImpactScores,Matrix,FailureMetrics)
					Detectability = CalculateDetectability(i,comp,Mode,TechMitRelationships, MitigationCoverage,Matrix)
					MitigationsList,DetectionList = GetTechniqueMitigations(i,TechMitRelationships, Matrix)
					Risk = Likelihood * Impact * Detectability
					Rating = GetRiskRating(Risk)
					if Rating == "Low":
						Low_Risks += 1
					elif Rating == "Medium":	
						Medium_Risks += 1
					elif Rating == "High":	
						High_Risks += 1
					elif Rating == "Critical":	
						Critical_Risks += 1			
					ResultString=str(Mode)+";"+comp[1]+";"+"Mob-Tech-"+str(j)+";"+str(i[11])+";"+str(i[1])+";"+str(i[2])+";"+"[]"+";"+str(Likelihood).replace(".", ",")+";"+str(Impact).replace(".", ",")+";"+str(Detectability).replace(".", ",") + ";"+ str(Risk).replace(".", ",")+";"+str(Rating)+";"+str(MitigationsList)+";"+str(DetectionList)+";"
					j = j +1 
					if PrintRisks:
						OutputFile.write(ResultString+"\n")  # python will convert \n to os.linesep
					OverallRisk = OverallRisk + Risk
					#print("-----------------------------")
			if len(CompEnterpriseAttacks)>0:
				#print("===========[ Related IT Attacks ] ==============")
				"""
				CSV Header
				0	1	2			3	4		5		6		7	8	9	10	11	12
				number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V	id	system_requirements	
				"""
				j=1
				#comp.; tech_ID; tech_name; tactic; platforms; CAPEC Likelihood; impact_type; CAPEC ID ; CVSS_Exp
				Matrix = "Enterprise"
				for i in CompEnterpriseAttacks:
					Likelihood = CalculateLikelihood(i,comp,Mode)
					Impact = CalculateImpact(i,comp,Mode,ImpactScores,Matrix,FailureMetrics)
					Detectability = CalculateDetectability(i,comp,Mode,TechMitRelationships, MitigationCoverage,Matrix)
					MitigationsList,DetectionList = GetTechniqueMitigations(i,TechMitRelationships, Matrix)
					Risk = Likelihood * Impact * Detectability
					Rating = GetRiskRating(Risk)
					if Rating == "Low":
						Low_Risks += 1
					elif Rating == "Medium":	
						Medium_Risks += 1
					elif Rating == "High":	
						High_Risks += 1
					elif Rating == "Critical":	
						Critical_Risks += 1				
					ResultString = str(Mode)+";"+comp[1]+";"+"IT-Tech-"+str(j)+";"+str(i[11])+";"+str(i[1])+";"+str(i[2])+";"+str(i[3])+";"+str(Likelihood).replace(".", ",")+";"+str(Impact).replace(".", ",")+";"+str(Detectability).replace(".", ",") + ";"+ str(Risk).replace(".", ",")+";"+str(Rating)+";"+str(MitigationsList)+";"+str(DetectionList)+";"+str(i[12])
					if PrintRisks:
						OutputFile.write(ResultString+"\n")  # python will convert \n to os.linesep
					j = j +1 
					OverallRisk = OverallRisk + Risk
					#print("-----------------------------")
			if len(CompICSAttacks)>0:
				#print("===========[ Related ICS Attacks ] ==============")
				"""
				CSV Header
				0	1	2			3	4		5		6		7	8	9	10	11
				number	name	kill_chain_phases	Asset	Technologies	Additions	CVSS_Exp	PR_V	AC_V	UI_V	AV_V	id
				"""
				j=1
				Matrix = "ICS"
				for i in CompICSAttacks:
					#print(i)
					Likelihood = CalculateLikelihood(i,comp,Mode)
					Impact = CalculateImpact(i,comp,Mode,ImpactScores,Matrix,FailureMetrics)
					Detectability = CalculateDetectability(i,comp,Mode,TechMitRelationships, MitigationCoverage,Matrix)
					MitigationsList,DetectionList = GetTechniqueMitigations(i,TechMitRelationships, Matrix)
					Risk = Likelihood * Impact * Detectability
					Rating = GetRiskRating(Risk)
					if Rating == "Low":
						Low_Risks += 1
					elif Rating == "Medium":	
						Medium_Risks += 1
					elif Rating == "High":	
						High_Risks += 1
					elif Rating == "Critical":	
						Critical_Risks += 1				
					ResultString = str(Mode)+";"+comp[1]+";"+"ICS-Tech-"+str(j)+";"+str(i[11])+";"+str(i[1])+";"+str(i[2])+";"+str(i[3])+";"+str(Likelihood).replace(".", ",")+";"+str(Impact).replace(".", ",")+";"+str(Detectability).replace(".", ",") + ";"+ str(Risk).replace(".", ",")+";"+str(Rating)+";"+str(MitigationsList)+";"+str(DetectionList)+";"
					if PrintRisks:
						OutputFile.write(ResultString+"\n")  # python will convert \n to os.linesep
					j = j +1 
					OverallRisk = OverallRisk + Risk	
	RiskScores.append(OverallRisk)								

	if PrintRisks: 
		OutputFile.close()  
	
	#print("Stats for Defense Strategy defined in ["+strategy+"]")
	#print(Fore.BLACK+"Overall Risk = ",OverallRisk)

	print(  "{:40} {:25} {:25} {:25} {:25}".format(strategy,Fore.GREEN +str(Low_Risks),Fore.YELLOW +str(Medium_Risks),Fore.RED +str(High_Risks),Fore.BLACK+str(Critical_Risks))+Style.RESET_ALL)


print(Back.BLACK+"========================================================================================================================="+Style.RESET_ALL)
print("{:40} {:40} {:40}".format("Strategy", "Overall Risk Score", "Risk Reduction %"))
print("{:40} {:40} {:40}".format("========", "==================", "================"))
for strategy,score in zip(MitigationStrategies,RiskScores):
	print("{:40} {:40} {:40}".format(strategy,str(score),str((100-(score/max(RiskScores))*100))+"%"))
	
	
print(Back.BLACK+"========================================================================================================================="+Style.RESET_ALL)
print("Defense strategy with maximum risk = "+Back.RED+str(MitigationStrategies[RiskScores.index(max(RiskScores))])+Style.RESET_ALL)
print(Fore.BLACK+"Defense strategy with minimum risk = "+Back.GREEN+str(MitigationStrategies[RiskScores.index(min(RiskScores))])+Style.RESET_ALL)

