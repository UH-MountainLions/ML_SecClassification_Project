# -*- coding: utf-8 -*-
"""decisionTree supervised learning algorithm for classification of BruteForce attacks.

Full license in LICENSE.md
"""
import os
from joblib import dump, load
from sklearn.model_selection import train_test_split
from sklearn import tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import utilities as util
import numpy as np
from matplotlib import pyplot as plt

MODEL_FILE = 'randomForest.WebAttack.joblib'
# The list of features for detecting bruteforce (FTP/SSH) attacks.
WEBATTACK_FEATURES = ['Dst Port',
                      'Protocol',
                      'Flow Duration',
                      'Tot Fwd Pkts',
                      'Tot Bwd Pkts',
                      'TotLen Fwd Pkts',
                      'TotLen Bwd Pkts',
                      'Flow Byts/s',
                      'Flow Pkts/s',
                      'Fwd IAT Tot',
                      'Bwd IAT Tot',
                      'Fwd PSH Flags',
                      'Bwd PSH Flags',
                      'Fwd URG Flags',
                      'Bwd URG Flags',
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
                      'CWE Flag Cnt',
                      'ECE Flag Cnt',
                      'Down/Up Ratio',
                      'Subflow Fwd Pkts',
                      'Subflow Fwd Byts',
                      'Subflow Bwd Pkts',
                      'Subflow Bwd Byts',
                      'Init Fwd Win Byts',
                      'Init Bwd Win Byts',
                      'Fwd Act Data Pkts',
                      'Fwd Seg Size Min',
                      'Active Mean',
                      'Active Std',
                      'Active Max',
                      'Active Min',
                      'Idle Mean',
                      'Idle Std',
                      'Idle Max',
                      'Idle Min',
                      ]
WEBATTACK_FEATURES_V2 = ['Destination Port', 'Protocol', 'Flow Duration', 'Total Fwd Packets'
 'Total Backward Packets', 'Total Length of Fwd Packets'
 'Total Length of Bwd Packets', 'Fwd Packet Length Max'
 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std'
 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean'
 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean'
 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total'
 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total'
 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min'
 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s'
 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean'
 'Packet Length Std', 'Packet Length Variance', 'PSH Flag Count'
 'Avg Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size'
 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets'
 'Subflow Bwd Bytes', 'Init Fwd Win Byts', 'Init Bwd Win Byts'
 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std'
 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

# Craft the default specific path to the resources folder which holds the training and testing data
st_path = os.path.join(os.getcwd(), 'resources', 'TrafficLabelling')
# Specify the training file
# Webattacks
st_file = 'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv'
st_file_2 = 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
# st_file_2 = 'Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv'
# DDos
# st_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
# Brute force
# st_file_2 = 'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv'
# st_file = 'Tuesday-WorkingHours.pcap_ISCX.csv'
# Misc
# st_file = 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Morning.pcap_ISCX.csv'
# st_file = 'Monday-WorkingHours.pcap_ISCX.csv'
# st_file = 'Wednesday-workingHours.pcap_ISCX.csv'
# encoding = 'cp1252'
encoding = 'utf_8'

# ***************************************
# MODELING
# ***************************************
RESAMPLE = True
USE_TRAINED_MODEL = False  # Change this for training vs using existing model
# Split the data into training and testing sets
if USE_TRAINED_MODEL:
    # Load pretrained Decision Tree Classifier
    clf = load(MODEL_FILE)
    # New file test
    X_test, y_test, test_target_names = util.prep_pipeline(os.path.join(st_path, st_file),
                                                           WEBATTACK_FEATURES_V2,
                                                           encoding)
    # Make predictions
    prediction_test = clf.predict(X_test)
    print('*** Classification Load Test Report ***\n{}\n******'.format(classification_report(y_test,
                                                                                             prediction_test,
                                                                                             target_names=test_target_names)
                                                                       )
          )
else:
    X_data, y_data, target_names = util.prep_pipeline(os.path.join(st_path, st_file),
                                                        WEBATTACK_FEATURES_V2,
                                                        encoding)
    if RESAMPLE:
        X_data, y_data = util.resample(X_data, y_data)
    # Build new training data
    X_train, X_test, y_train, y_test = train_test_split(X_data,
                                                        y_data,
                                                        test_size=0.3,
                                                        random_state=42)
    X_data, y_data = None, None
    # Training the model
    # Decision Tree Classifier - This is the key part of the code.
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)
    dump(clf, MODEL_FILE)

    # Testing the Model - Predictions and Evaluations
    prediction_test = clf.predict(X_test)
    X_test = None
    print('*** Classification TRAIN Report ***\n{}\n******'.format(classification_report(y_test,
                                                                                         prediction_test,
                                                                                         target_names=target_names)))
    y_test, prediction_test = None, None

# *******************************************************************
# New file test
test_features, test_targets, test_target_names = util.prep_pipeline(os.path.join(st_path, st_file_2),
                                                                    WEBATTACK_FEATURES_V2,
                                                                    encoding)
# Make predictions
prediction_test = clf.predict(test_features)
print('*** Classification RUN Report ***\n{}\n******'.format(classification_report(test_targets,
                                                                                   prediction_test,
                                                                                   target_names=test_target_names)))
