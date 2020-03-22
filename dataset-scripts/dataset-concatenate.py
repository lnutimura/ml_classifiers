#!/usr/bin/python3

# This script concatenates the content of every .csv in this 
# folder to a single file, called 'CIC-IDS-2017.csv'.

import glob
import subprocess

if __name__ == '__main__':
	print('[*] Attempting to clean any output file previously created by this script...')

	sp = subprocess.Popen(['rm', 'CIC-IDS-2017.csv'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	sp_output, sp_error = sp.communicate()

	if sp.returncode != 0:
		print('\t[*] No previous file was removed (Return code: {}).'.format(str(sp.returncode)))
	else:
		print('\t[*] Successfully removed a previous file (Return code: {}).'.format(str(sp.returncode)))

	input_files = [f for f in glob.glob('./*.csv', recursive=True)]

	print('[*] Creating the output file \'CIC-IDS-2017.csv\'...')

	try:
		out_f = open('CIC-IDS-2017.csv', 'w')
	except Exception as err:
		print('[*] Error! Couldn\'t create the output file.')
		print(err)

	for input_file in input_files:
		print('[*] Reading \'{}\'...'.format(input_file))

		try:
			in_f = open(input_file, 'r')

			for line in in_f:
				split_line = line.strip('\n').split(',')
				label = split_line[-1].strip()

				if label == 'Label': continue
				if label == 'BENIGN':
					split_line[-1] = '0'
				else:
					split_line[-1] = '1'

				new_line = ','.join(split_line)

				out_f.write(new_line + '\n')
		except Exception as err:
			print('[*] Error! Something went wrong.')
			print(err)
		finally:
			in_f.close()
	print('[*] Done!')
	out_f.close()

