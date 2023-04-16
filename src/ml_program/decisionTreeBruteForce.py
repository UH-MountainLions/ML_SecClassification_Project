# -*- coding: utf-8 -*-
"""decisionTree supervised learning algorithm for classification of BruteForce attacks.

Full license in LICENSE.md
"""
import os
from joblib import dump, load
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

import utilities as util
from utilities import BRUTEFORCE_FEATURES


# Craft the default specific path to the resources folder which holds the training and testing data
st_path = os.path.join(os.getcwd(), 'resources', 'TrafficLabelling')
# Specify the training file
# st_file = 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
# st_file = 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Morning.pcap_ISCX.csv'
# st_file = 'Monday-WorkingHours.pcap_ISCX.csv'
st_file = 'Tuesday-WorkingHours.pcap_ISCX.csv'
# st_file = 'Wednesday-workingHours.pcap_ISCX.csv'
st_file_2 = 'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv'
encoding = 'utf_8'

# Read the CSV file using pandas
df_data = pd.read_csv(os.path.join(st_path, st_file), encoding=encoding)
# Define required features
df_data = util.fix_headers(df_data)
# Grab only columns needed
df_features = df_data.filter(BRUTEFORCE_FEATURES, axis='columns')
# pre-process and clean dataset
df_features, df_targets = util.data_training_prep(df_features,
                                                  util.get_targets_int(df_data))
df_target_names = util.get_target_names(df_data)

# ***************************************
# MODELING
# ***************************************
# Split the data into training and testing sets
X_train, X_test, true_train, true_test = train_test_split(df_features,
                                                          df_targets,
                                                          test_size=0.2,
                                                          random_state=42)
# Training the model
# Decision Tree Classifier - This is the key part of the code.
clf = DecisionTreeClassifier()
clf.fit(X_train, true_train)
dump(clf, 'decisionTree_Training.joblib')

# Testing the Model - Predictions and Evaluations
prediction_test = clf.predict(X_test)
print('***** Classification Test Report *****\n{}\n**********'.format(classification_report(true_test,
                                                                                            prediction_test,
                                                                                            target_names=df_target_names)))
# Clear old variables and save memory
df_features = None
df_targets = None
# Display Results - Confusion Matrix
cm = confusion_matrix(true_test, prediction_test)
disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                              display_labels=df_target_names)
disp.plot()
print('Confusion Matrix:\n{}'.format(cm))

# New file test
df_data = pd.read_csv(os.path.join(st_path, st_file_2), encoding=encoding)
df_data = util.fix_headers(df_data)
df_features = df_data.filter(BRUTEFORCE_FEATURES, axis='columns')
# pre-process and clean dataset
df_features, df_targets = util.data_training_prep(df_features,
                                                  util.get_targets_int(df_data))
df_target_names = util.get_target_names(df_data)
prediction_test = clf.predict(df_features)
print('***** Classification RUN Report *****\n{}\n**********'.format(classification_report(df_targets,
                                                                                           prediction_test,
                                                                                           target_names=df_target_names)))
