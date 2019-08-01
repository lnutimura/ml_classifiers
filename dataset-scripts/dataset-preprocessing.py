#!/usr/bin/python3

import glob
import time
import numpy as np

from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, recall_score, accuracy_score

from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import BernoulliNB, GaussianNB, MultinomialNB
from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier

from joblib import dump, load
from imblearn.over_sampling import SMOTE

if __name__ == '__main__':
	joblibs = [f[2:] for f in glob.glob('./*.joblib')]

	print('[*] Joblibs found:')
	print(joblibs)
	print()

	print('[*] Reading the contents of \'CIC-IDS-2017.csv\' into a numpy array...')
	dataset = np.genfromtxt('CIC-IDS-2017.csv', delimiter=',')
	filtered_dataset = dataset[~np.isnan(dataset).any(axis=1)]
	filtered_dataset = filtered_dataset[np.isfinite(filtered_dataset).all(axis=1)]
	print('\t[*] dataset numpy array shape: {}.'.format(str(dataset.shape)))
	print('\t[*] filtered_dataset numpy array shape: {}.'.format(str(filtered_dataset.shape)))

	print('[*] Splitting the dataset into \'features\' and \'labels\'...')
	dataset_features = filtered_dataset[:,:78]
	dataset_labels = filtered_dataset[:,78]
	print('\t[*] dataset_features numpy array shape: {}.'.format(str(dataset_features.shape)))
	print('\t[*] dataset_labels numpy array shape: {}.'.format(str(dataset_labels.shape)))

	print('[*] Splitting both \'features\' and \'labels\' into training and test sets...')
	training_features, test_features, training_labels, test_labels = train_test_split(dataset_features, dataset_labels, test_size=.33, random_state=12)
	print('\t[*] training_features numpy array shape: {}.'.format(str(training_features.shape)))
	print('\t[*] training_labels numpy array shape: {}.'.format(str(training_labels.shape)))
	print('\t[*] test_features numpy array shape: {}.'.format(str(test_features.shape)))
	print('\t[*] test_labels numpy array shape: {}.'.format(str(test_labels.shape)))

	print('[*] Splitting the training set into training and validation sets...')
	train_x, val_x, train_y, val_y = train_test_split(training_features, training_labels, test_size=.10, random_state=12)
	print('\t[*] train_x numpy array shape: {}.'.format(str(train_x.shape)))
	print('\t[*] train_y numpy array shape: {}.'.format(str(train_y.shape)))
	print('\t[*] val_x numpy array shape: {}.'.format(str(val_x.shape)))
	print('\t[*] val_y numpy array shape: {}.'.format(str(val_y.shape)))

	print('[*] Applying the Synthetic Minority Over-sampling Technique (SMOTE) algorithm to the training set...')
	sm = SMOTE(random_state=12, ratio=1.0)
	train_x_res, train_y_res = sm.fit_sample(train_x, train_y)
	print('\t[*] train_x_res numpy array shape: {}.'.format(str(train_x_res.shape)))
	print('\t[*] train_y_res numpy array shape: {}.'.format(str(train_y_res.shape)))

	print('[*] Applying the Min Max Scaler algorithm to the training/testing set...')
	scaler = MinMaxScaler()
	val_x_adjusted = scaler.fit_transform(val_x)
	train_x_res_adjusted = scaler.fit_transform(train_x_res)
	test_features_adjusted = scaler.fit_transform(test_features)

	# Classifiers' name, joblists and constructors
	clf_names = ['Linear SVC', 'AdaBoost', 'Decision Tree', 'Random Forest', 'Bernoulli NB', 'Gaussian NB'] #, 'Multinomial NB']
	clf_joblibs = ['clf_svc.joblib', 'clf_ab.joblib', 'clf_dt.joblib', 'clf_rf.joblib', 'clf_bnb.joblib', 'clf_gnb.joblib'] #,'clf_mnb.joblib']
	clf_constructors = [LinearSVC(C=100, dual=False), AdaBoostClassifier(), DecisionTreeClassifier(), RandomForestClassifier(), BernoulliNB(), GaussianNB()] #, MultinomialNB()]

	results = []

	for i, clf in enumerate(clf_constructors):
		start_time = time.time()

		print('\n[*] Classifier: {}'.format(clf_names[i]))
		
		if clf_joblibs[i] in joblibs:
			print('[*] Loading {}...'.format(clf_joblibs[i]))
			clf = load(clf_joblibs[i])
			predictions = clf.predict(test_features_adjusted)
		else:
			print('[*] No joblib was found. Running the classifier over the training set...')
			predictions = clf.fit(train_x_res_adjusted, train_y_res).predict(test_features_adjusted)
			dump(clf, clf_joblibs[i])

		accuracy = accuracy_score(test_labels, predictions)
		c_matrix = confusion_matrix(test_labels, predictions)
		precision, recall, fscore, support = precision_recall_fscore_support(test_labels, predictions)
		results.append([i, clf_names[i], accuracy, precision, recall, fscore, support, c_matrix, (time.time() - start_time)])

		print('[*] Accuracy: {}'.format(accuracy))
		print('[*] Result: {}'.format(results[i]))

		if clf_names[i] in ['AdaBoost', 'Decision Tree', 'Random Forest']:
			print(clf.feature_importances_)

	print('\n[*] Applying Grid Search to SVC...')
	param_grid = {'C':[0.1,1,10,100]}
	grid = GridSearchCV(LinearSVC(dual=False), param_grid, n_jobs=2, verbose=3)
	grid.fit(train_x_res_adjusted, train_y_res)
	print(grid.best_params_)

	# Extra
	print('\n[*] Validation Extra informations:')
	val_unique, val_counts = np.unique(val_y, return_counts=True)
	print(dict(zip(val_unique, val_counts)))	

	print('[*] Testing Extra informations:')
	test_unique, test_counts = np.unique(test_labels, return_counts=True)
	print(dict(zip(test_unique, test_counts)))

	'''
	print('[*] Validation results:')
	dt_start = time.time()
	print(clf_dt.score(val_x, val_y))
	print(recall_score(val_y, clf_dt.predict(val_x)))
	print('[*] Validation (sec): %d' % (time.time() - dt_start))

	print('[*] Test results:')
	dt_start = time.time()
	print(clf_dt.score(test_features, test_labels))
	print(recall_score(test_labels, clf_dt.predict(test_features)))
	print('[*] Testing (sec): %d' % (time.time() - dt_start))
	print()
	'''