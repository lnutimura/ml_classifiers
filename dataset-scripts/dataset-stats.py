#!/usr/bin/python3

# This script reads the CIC IDS 2017's CSV files
# and counts the appearance of each label in the
# dataset.

import glob

# Function that exports the labels' count to a
# text file (dataset-label-count.txt).
def exportDictionary(label_dict):
	file = open('dataset-stats.txt', 'w')

	# Sums all the labels' count.
	totalLabelCount = 0
	totalNonBenignCount = 0

	for key, value in label_dict.items():
		totalLabelCount += value
		if key != 'BENIGN':
			totalNonBenignCount += value

	# Displays everything in a nice format.
	file.write('Detailed count:\n\n')

	for key, value in label_dict.items():
		file.write('{}: {} ({})\n'.format(key, value, str((value / totalLabelCount) * 100)))

	file.write('\nSummary count:\n\n')
	file.write('BENIGN: {} ({})\n'.format(label_dict['BENIGN'], str((label_dict['BENIGN'] / totalLabelCount) * 100)))
	file.write('NON-BENIGN: {} ({})\n'.format(totalNonBenignCount, str((totalNonBenignCount / totalLabelCount) * 100)))

	file.close()

if __name__ == '__main__':
	# Dictionary used to store and count the appearance
	# of each label in the dataset.
	label_dict = {}

	# List of .txt/.csv files to read.
	# (Ignores the 'CIC-IDS-2017.csv').
	input_files = [f for f in glob.glob('./*.csv', recursive=True) if 'CIC-IDS-2017.csv' not in f]

	if input_files:
		for input_file in input_files:
			print('[*] Reading \'{}\'...'.format(input_file))
			try:
				file = open(input_file)

				for line in file:
					parameters_list = line.strip('\n').split(',')
					label = parameters_list[-1].strip()

					if label == 'Label': continue

					if label in label_dict: label_dict[label] += 1
					else: label_dict[label] = 1
			except Exception as err:
				print('[*] Error! Something went wrong.')
				print(err)
			finally:
				file.close()

		# Once every file is read,
		# we're ready to export the dictionary.
		exportDictionary(label_dict)
		print('[*] Done.')
	else:
		print('[*] Sorry, couldn\'t find any file with the {} extension.'.format(extension))
