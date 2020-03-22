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
    
    print('[*] Applying the Synthetic Minority Over-sampling Technique (SMOTE) algorithm to the training set...')
    sm = SMOTE(random_state=12, ratio=1.0)
    train_x, train_y = sm.fit_sample(training_features, training_labels)
    print('\t[*] train_x numpy array shape: {}.'.format(str(train_x.shape)))
    print('\t[*] train_y numpy array shape: {}.'.format(str(train_y.shape)))

    print('[*] Applying the Min Max Scaler algorithm to the training set...')
    # Creates a new scaler to fit the training set and transform both training/test sets.
    # Default range is (0,1).
    scaler = MinMaxScaler()
    scaler.fit(train_x)
    train_x_adjusted = scaler.transform(train_x)
    test_features_adjusted = scaler.transform(test_features)
    
    # Saves the scaler for later use in the real-time intrusion detection step.
    dump(scaler, 'scaler.joblib')
    
    # Classifiers' names, joblists and constructors.
    clf_names = ['Linear SVC', 'AdaBoost', 'Decision Tree', 'Random Forest', 'Bernoulli NB', 'Gaussian NB']
    clf_joblibs = ['clf_svc.joblib', 'clf_ab.joblib', 'clf_dt.joblib', 'clf_rf.joblib', 'clf_bnb.joblib', 'clf_gnb.joblib']
    clf_constructors = [LinearSVC(dual=False), AdaBoostClassifier(), DecisionTreeClassifier(), RandomForestClassifier(), BernoulliNB(), GaussianNB()]
    
    # GridSearchCV related
    clf_best_estimators = []
    clf_parameters = [{'C': [0.1, 1, 10, 100]}, {'n_estimators': [10, 50, 100], 'learning_rate': [0.01, 0.05, 0.1, 1]}, {'max_depth': [None, 3], 'min_samples_split': np.linspace(0.1, 1.0, 10, endpoint=True), 'min_samples_leaf': np.linspace(0.1, 0.5, 5, endpoint=True), 'max_features': [0.1, 0.5, 1.0]}, {'n_estimators': [10, 50, 100], 'max_depth': [None, 3], 'min_samples_split': np.linspace(0.1, 1.0, 10, endpoint=True), 'min_samples_leaf': np.linspace(0.1, 0.5, 5, endpoint=True), 'max_features': [0.1, 0.5, 1.0]}]

    # GridSearchCV Parameters.
    # svc_parameters = {'C': [0.1, 1, 10, 100]}
    # ab_parameters = {'n_estimators': [10, 50, 100], 'learning_rate': [0.01, 0.05, 0.1, 1]}
    # dt_parameters = {'max_depth': [None, 3], 'min_samples_split': np.linspace(0.1, 1.0, 10, endpoint=True), 'min_samples_leaf': np.linspace(0.1, 0.5, 5, endpoint=True), 'max_features': [0.1, 0.5, 1.0]}
    # rf_parameters = {'n_estimators': [10, 50, 100], 'max_depth': [None, 3], 'min_samples_split': np.linspace(0.1, 1.0, 10, endpoint=True), 'min_samples_leaf': np.linspace(0.1, 0.5, 5, endpoint=True), 'max_features': [0.1, 0.5, 1.0]}

    results = []
    results_gs = []
    
    print('[*] Running GridSearchCV...')
    # GridSearchCV for Linear SVC, AdaBoost, DecisionTree, RandomForest.
    for i, clf in enumerate(clf_constructors[:-2]):
        print('\t[*] {}...'.format(clf_names[i]))
        
        start_time = time.time()
        
        grid = GridSearchCV(clf_constructors[i], clf_parameters[i], n_jobs=-1, verbose=3)
        grid.fit(train_x_adjusted, train_y)
        
        # results_gs consists of [index, best score, best parameters, fit time].
        results_gs.append([i, grid.best_score_, grid.best_params_, (time.time() - start_time)])
        
        clf_best_estimators.append(grid.best_estimator_)
    
    print('[*] Running fifteen rounds of training for all classifiers...')
    for t in range(15):
        print('\t[*] Round {}.'.format(t))
        print('\t[*] Splitting the dataset...')
        training_features, test_features, training_labels, test_labels = train_test_split(dataset_features, dataset_labels, test_size=.33)
        print('\t[*] Applying the SMOTE algorithm...')
        train_x, train_y = sm.fit_sample(training_features, training_labels)
        print('\t[*] Scaling the features...')
        scaler.fit(train_x)
        train_x_adjusted = scaler.transform(train_x)
        test_features_adjusted = scaler.transform(test_features)
        
        for i, clf in enumerate(clf_constructors):
            print('\t\t[*] {}...'.format(clf_names[i]))
            if i < 4:
                # For Linear SVC, AdaBoost, DecisionTree and RandomForest,
                # we load the best estimators according to GridSearchCV.
                
                clf = clf_best_estimators[i]
                
                start_time = time.time()
                clf.fit(train_x_adjusted, train_y)
                fit_time = time.time() - start_time
                
                start_time = time.time()
                predictions = clf.predict(test_features_adjusted)
                test_time = time.time() - start_time
                
                accuracy = accuracy_score(test_labels, predictions)
                c_matrix = confusion_matrix(test_labels, predictions)
                precision, recall, fscore, support = precision_recall_fscore_support(test_labels, predictions)
                
                results.append([t, i, clf_names[i], accuracy, precision, recall, fscore, support, c_matrix, fit_time, test_time])
                
                print('\t\t[*] Accuracy: {}'.format(accuracy))
                print('\t\t[*] Result: {}'.format(results[i]))
            else:
                start_time = time.time()
                clf.fit(train_x_adjusted, train_y)
                fit_time = time.time() - start_time
                
                start_time = time.time()
                predictions = clf.predict(test_features_adjusted)
                test_time = time.time() - start_time
                
                accuracy = accuracy_score(test_labels, predictions)
                c_matrix = confusion_matrix(test_labels, predictions)
                precision, recall, fscore, support = precision_recall_fscore_support(test_labels, predictions)
                
                results.append([t, i, clf_names[i], accuracy, precision, recall, fscore, support, c_matrix, fit_time, test_time])
            
                print('\t\t[*] Accuracy: {}'.format(accuracy))
                print('\t\t[*] Result: {}'.format(results[i]))
                
            # If it's the last round, we save the classifiers
            # for later use in the real-time intrusion detection.
            if t == 14:
                dump(clf, clf_joblibs[i])
    
    print('[*] Dumping results/results_gs to .txt files...')
    with open('results.txt', 'w') as f:
        for item in results:
            f.write('%s\n' % item)
    
    with open('results_gs.txt', 'w') as f:
        for item in results_gs:
            f.write('%s\n' % item)

    # Extra
    print('[*] Extra informations of the test set:')
    test_unique, test_counts = np.unique(test_labels, return_counts=True)
    print(dict(zip(test_unique, test_counts)))

