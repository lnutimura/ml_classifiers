#!/usr/bin/python3

import sys
import glob
import time
import numpy as np

from sklearn.preprocessing import MinMaxScaler, StandardScaler

from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import BernoulliNB, GaussianNB, MultinomialNB
from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier

from joblib import dump, load

if len(sys.argv) != 2:
    print('Something went wrong.\nUsage: python3 /path/to/ml_classifiers.py <algorithm_code>')
    sys.exit(1)

if __name__ == '__main__':
    input_data = []
    input_file = open ('/home/lnutimura/Desktop/ml_classifiers/tmp/timeouted_connections.txt', 'r')
    output_file = open ('/home/lnutimura/Desktop/ml_classifiers/tmp/timeouted_connections_results.txt', 'w')

    clf_joblibs = {'svc':'clf_svc.joblib', 'ab':'clf_ab.joblib', 'dt':'clf_dt.joblib', 'rf':'clf_rf.joblib', 'bnb':'clf_bnb.joblib', 'gnb':'clf_gnb.joblib'}
    clf = load('/home/lnutimura/Desktop/ml_classifiers/joblibs/' + clf_joblibs[sys.argv[1]])
    scaler = load('/home/lnutimura/Desktop/ml_classifiers/joblibs/scaler.joblib')
    
    for line in input_file.readlines():
        features = line.strip().split(' ')
        feature_vector = [float(x) for x in features]
        
        input_data.append(feature_vector)
        
    np_input_data = np.array(input_data)
    np_input_data_adjusted = scaler.transform(np_input_data)
    
    start_time = time.time()
    predictions = clf.predict(np_input_data_adjusted)
    print('#{}'.format(time.time() - start_time))
    
    for prediction in predictions:
        output_file.write(str(prediction) + '\n')
        
    input_file.close()
    output_file.close()
