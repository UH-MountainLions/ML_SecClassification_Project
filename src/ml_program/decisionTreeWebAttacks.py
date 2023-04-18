# -*- coding: utf-8 -*-
"""decisionTree supervised learning algorithm for classification of Web attacks.

Full license in LICENSE.md
"""
import os
from joblib import dump, load
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

import utilities as util

# The list of features for detecting Web Attacks.
WEBATTACK_FEATURES = ['Dst Port',
                      'Protocol',
                      # 'Flow Duration',
                      'Tot Fwd Pkts',
                      'Tot Bwd Pkts',
                      'TotLen Fwd Pkts',
                      'TotLen Bwd Pkts',
                      'Flow Byts/s',
                      'Flow Pkts/s',
                      # 'Fwd IAT Tot',
                      # 'Bwd IAT Tot',
                      # 'Fwd PSH Flags',
                      # 'Bwd PSH Flags',
                      # 'Fwd URG Flags',
                      # 'Bwd URG Flags',
                      'Fwd Header Len',
                      'Bwd Header Len',
                      'Fwd Pkts/s',
                      'Bwd Pkts/s',
                      'FIN Flag Cnt',
                      'SYN Flag Cnt',
                      'RST Flag Cnt',
                      'PSH Flag Cnt',
                      'ACK Flag Cnt',
                      'URG Flag Cnt',
                      'CWE Flag Count',
                      'ECE Flag Cnt',
                      # 'Down/Up Ratio',
                      # 'Subflow Fwd Pkts',
                      # 'Subflow Fwd Byts',
                      # 'Subflow Bwd Pkts',
                      # 'Subflow Bwd Byts',
                      'Init Fwd Win Byts',
                      'Init Bwd Win Byts',
                      'Fwd Act Data Pkts',
                      'Fwd Seg Size Min'
                      ]

CONVERT_TRAINING = {'Brute Force -Web': 'Web Attack  Brute Force',
                    'SQL Injection': 'Web Attack  Sql Injection',
                    'Brute Force -XSS': 'Web Attack  XSS',
                    'Benign': 'BENIGN'
                    }

# Craft the default specific path to the resources folder which holds the training and testing data
st_path = os.path.join(os.getcwd(), 'resources', 'TrafficLabelling')
# Specify the training file
# Web Attacks
st_file = 'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv'
st_file_2 = 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
# DDos
# st_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
# Brute force
# st_file = 'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv'
# st_file_2 = 'Tuesday-WorkingHours.pcap_ISCX.csv'
# Misc
# st_file = 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Morning.pcap_ISCX.csv'
# st_file = 'Monday-WorkingHours.pcap_ISCX.csv'
# st_file = 'Wednesday-workingHours.pcap_ISCX.csv'
# encoding = 'cp1252'
encoding = 'utf_8'

# Read the CSV file using pandas
df_data = pd.read_csv(os.path.join(st_path, st_file), encoding=encoding)
df_data['Label'] = df_data['Label'].map(CONVERT_TRAINING)
df_data = util.fix_headers(df_data)
df_target_names = util.get_target_names(df_data)
df_features = util.data_training_prep(df_data)  # clean and prep all data
# pre-process and clean dataset - Grab only columns needed
df_features = df_data.filter(WEBATTACK_FEATURES, axis='columns')
df_targets = util.get_targets_int(df_data)  # grab test answers before they are purged
assert len(df_targets) == len(df_features)

# ***************************************
# MODELING
# ***************************************
# Split the data into training and testing sets
X_train, X_test, true_train, true_test = train_test_split(df_features,
                                                          df_targets,
                                                          test_size=0.6,
                                                          random_state=42)
# Training the model
# Decision Tree Classifier - This is the key part of the code.
clf = DecisionTreeClassifier()
clf.fit(X_train, true_train)
dump(clf, 'decisionTree_WebAttacks.joblib')

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
test_data = pd.read_csv(os.path.join(st_path, st_file_2), encoding=encoding, encoding_errors='ignore')
# pre-process and clean dataset
test_data = util.fix_headers(test_data)  # prep column headers
test_target_names = util.get_target_names(test_data)
test_data = util.data_training_prep(test_data)  # Clean and prep all test_data
test_targets = util.get_targets_int(test_data)  # grab test answers before they are purged
test_features = test_data.filter(WEBATTACK_FEATURES, axis='columns')  # purge all columns not required
assert len(test_targets) == len(test_features)
prediction_test = clf.predict(test_features)
print('***** Classification RUN Report *****\n{}\n**********'.format(classification_report(test_targets,
                                                                                           prediction_test,
                                                                                           target_names=test_target_names)))
# Display Results - Confusion Matrix
cm = confusion_matrix(test_targets, prediction_test)
disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                              display_labels=test_target_names)
disp.plot()
print('Confusion Matrix:\n{}'.format(cm))
