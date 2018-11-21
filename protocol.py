import sys, json, itertools, time
from dgk import dgk
from utils import bigrams
from random import shuffle

# Threshold above which the Dice coefficient is considered a match
diceThreshold = 0.90
# Maximum allowable string length of a name
maxNameLength = 20
# maxNameLength = pub.QRRunLength - 1
maxBigramSetSize = maxNameLength + 1

bigramList = bigrams.generateBigrams()

nameFile = ""
encryptedDatabase = ""
matchFile = ""

def encryptNameDictionary(name):
	''' Create dictionary of bigram encryptions for a name. Keys are bigrams. Values are: Enc(1) if the bigram was present in the name, Enc(0) otherwise. '''

	convertedName = bigrams.bigramize(name, maxNameLength)
	encryptedName = {}
	[encryptedName.update({bg : (dgk.encryptOne()).digits(62)}) for bg in convertedName]
	[encryptedName.update({bg : (dgk.encryptZero()).digits(62)}) for bg in [bg for bg in bigramList if bg not in encryptedName]]
	encryptedName["length"] = len(convertedName)
	# Pseudo identifier
	encryptedName["pid"] = (dgk.randBits(128)).digits(62)

	return encryptedName

def createNameList(nameFile):
	'''Loads list of names to be encrypted from a file and returns in randomized order'''

	try: 
		names = open(nameFile, 'r')
	except:
		print "There was a problem reading from the name list"
		sys.exit()

	nameList = []

	for name in names:
		nameList.append(name.rstrip())

	# Built-in Python shuffle. For prototyping purposes. Should not be considered secure.
	shuffle(nameList)
	return nameList

def create(nameFile, encryptedDatabaseFile, pubKeyFile):
	'''For each name in the nameFileName file, bigramize, encrypt, and write to encryptedDatabaseFile
	Party A creates an encrypted name database for eventual use by Party B'''

	dgk.init(pubKeyFile)

	try:
		encryptedDatabase = open(encryptedDatabaseFile, 'w')
	except:
		print "There was a problem writing to the encrypted database"
		sys.exit()

	# File containing name / pid associations used later for recovering a name from a matching plaintext
	try: 
		PIDFile = open("pid-" + nameFile, 'w')
	except:
		print "There was a problem creating the Name-PID file"
		sys.exit()

	nameList = createNameList(nameFile)

	# print "Performing name encryption..."
	start_time = time.time()
	for name in nameList:
		encryptedName = encryptNameDictionary(name)
		json.dump({encryptedName["pid"] : name}, PIDFile)
		PIDFile.write("\n")
		json.dump(encryptedName, encryptedDatabase)
		encryptedDatabase.write("\n")
	end_time = time.time()
	print "Time to encrypt: " + str(end_time - start_time)

def match(nameFile, encryptedNameDatabaseFile, encryptedMatchDatabaseFile, pubKeyFile):
	'''Party B homomoprhically compares each of its names against A's encrypted database, creating a list of ciphertexts corresponding corresponding to whether a given comparison was a match'''

	dgk.init(pubKeyFile)

	try:
		encryptedMatchDatabase = open(encryptedMatchDatabaseFile, 'w')
	except:
		print "There was a problem writing to the encrypted match database"
		sys.exit()

	try:
		encryptedNameDatabase = open(encryptedNameDatabaseFile, 'r')
	except:
		print "There was a problem reading from the encrypted name database"
		sys.exit()

	nameList = createNameList(nameFile)
	thresholdTable = bigrams.generateDiceThesholdTable(diceThreshold, maxBigramSetSize)

	# print "Performing homomorphic matching..."
	start_time = time.time()
	for line in encryptedNameDatabase:
		shuffle(nameList)
		encryptedName = json.loads(line)
		for name in nameList:
			nameBigrams = bigrams.bigramize(name, maxNameLength)
			# Given the lengths of the two input strings, perform homomorphic matching only if a match is possible 
			matchThreshold = thresholdTable[len(nameBigrams)][encryptedName["length"]]
			if matchThreshold > 0:
				# For every bigram in name, get the corresponding ciphertexts in encrytedName and homomorphically add them together
				cipherTextList = [dgk.base62toMPZ(encryptedName[bigram]) for bigram in nameBigrams]
				# Create blinded, randomized ciphertext containting encrytion of the bit corresponding to the homomorphic sum of the cipherTextList exceeds the minimum necessary match threshold 
				matchCipherText = dgk.thresholdEval(dgk.haddList(cipherTextList), matchThreshold)
				json.dump({matchCipherText.digits(62) : encryptedName["pid"]}, encryptedMatchDatabase)
				encryptedMatchDatabase.write("\n")
	end_time = time.time()
	print "Time to match: " + str(end_time - start_time)

def decrypt(encryptedMatchDatabaseFile, PIDFile, matchedNameFile, pubKeyFile, prvKeyFile):
	''' Party A decrypts the encrypted comparison database received from Party B and produces a list of matched names'''

	dgk.init(pubKeyFile, prvKeyFile)

	try:
		encryptedMatchDatabase = open(encryptedMatchDatabaseFile, 'r')
	except:
		print "There was a problem reading from the encrypted match database"
		sys.exit()

	try:
		PIDFilePtr = open(PIDFile, 'r')
	except:
		print "There was a problem reading from the name/PID file"
		sys.exit()

	try:
		matchedNames = open(matchedNameFile, 'w')
	except:
		print "There was a problem writing to the matched names list"
		sys.exit()

	names = {}
	for pid in PIDFilePtr:
		names.update(json.loads(pid))	

	# print "Performing match decryption..."
	start_time = time.time()
	for line in encryptedMatchDatabase:
		encryptedMatch = json.loads(line)
		for matchCipherText, pid in encryptedMatch.iteritems():
			if dgk.decryptQR(dgk.base62toMPZ(matchCipherText)):
				matchedNames.write(names[pid]+ " : " + pid + "\n")

	end_time = time.time()
	print "Time to decrypt: " + str(end_time - start_time)

def init():
	'''Sample Commands:

	Create encrypted database "encdb" from names list "names-a" using public key in "test-112.pub". Writes a list of patient-ids (names-a-pids)
	$ python protocol.py create names-a encdb test-112.pub

	Create encrypted match list "enc-match-db" from matching names in "names-b" with encrypted records in "encdb" using public key "test-112.pub" 
	$ python protocol.py match names-b encdb enc-match-db test-112.pub

	Decrypt match list "enc-match-db" using private key "test-112.prv", and uses patien id list "names-a-pids" to output a list of matches into "matched-names"
	$ python protocol.py decrypt enc-match-db names-a-pids matched-names test-112.pub test-112.prv
	'''
	
	if not ( (sys.argv[1] == "create" and len(sys.argv) == 5) or (sys.argv[1] == "match" and len(sys.argv) == 6) or (sys.argv[1] == "decrypt" and len(sys.argv) == 7)):
		print "Public-key approximate name matching protocol"
		print "Usage: python protocol.py create <name file> <encrypted name database> <public-key file>"
		print "Usage: python protocol.py match <name file> <encrypted name database> <encrypted match database> <public-key file>"
		print "   or: python protocol.py decrypt <encrypted match database> <name/PID file> <matched name file> <public-key file> <private-key file>"
		print "    where <x> denotes the path to file x"
		sys.exit()

	if sys.argv[1] == "create":
		create(sys.argv[2], sys.argv[3], sys.argv[4])

	if sys.argv[1] == "match":
		match(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

	if sys.argv[1] == "decrypt":
		decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
		
init()
