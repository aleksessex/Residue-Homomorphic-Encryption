# utilities related to strings, bigrams and similarity metrics 

import string, sys
from sets import Set

# Returns a set of bigrams on the alphabet
def generateBigrams():

	alphabet = list(string.ascii_uppercase)

	# Set of valid bigrams
	bigrams = Set([])

	for i in alphabet:
		bigrams.add("_" + i)
		bigrams.add(i + "_")
		
		for j in alphabet:
			bigrams.add(i + j)

	return bigrams

# Convert string to set of bigrams
def toBigrams(s):
	return list(Set([s[i:i+2] for i in range(len(s)-1)]))

# Converts name to list of bigrams, removing any non alpha characters and truncating for length
def bigramize(name, maxNameLength):
	name = name.upper()
	name = ''.join(c for c in name if c.isupper())
	# Truncate string to max length
	name = name[:maxNameLength]
	name = '_' + name + '_'

	return toBigrams(name)

# Threshold Dice coefficient table. 
# Compute 2d matrix of minimum set intersection cardinality to generate match for given diceThreshold and string lengths
# Rows are cardinality of bigram set A. Columns are cardinality of bigram set B. 0 means no match possible 
def generateDiceThesholdTable(diceThreshold, maxBigramSetSize):
	thresholdTable = [[0] * maxBigramSetSize for i in range(0, maxBigramSetSize)]
	for lenA in range(2,maxBigramSetSize):
		for lenB in range(2,maxBigramSetSize):
			for intersectionCardinality in range(1,maxBigramSetSize+1):
				if intersectionCardinality <= lenA and intersectionCardinality <= lenB and thresholdTable[lenA][lenB] == 0:
					if float(2*intersectionCardinality)/(lenA+lenB) >= diceThreshold:
						thresholdTable[lenA][lenB] = intersectionCardinality
	
	return thresholdTable