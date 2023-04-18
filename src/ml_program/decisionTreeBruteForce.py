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


USE_TRAINED_MODEL = False  # Change this for training vs using existing model
# The list of features for detecting bruteforce (FTP/SSH) attacks.
BRUTEFORCE_FEATURES = ['Dst Port',
                       'Protocol',
                       # 'Flow Duration',
                       'Tot Fwd Pkts',
                       # 'Tot Bwd Pkts',
                       'TotLen Fwd Pkts',
                       # 'TotLen Bwd Pkts',
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
                       # 'Fwd Pkts/s',
                       # 'Bwd Pkts/s',
                       'FIN Flag Cnt',
                       'SYN Flag Cnt',
                       'RST Flag Cnt',
                       'PSH Flag Cnt',
                       'ACK Flag Cnt',
                       'URG Flag Cnt',
                       'CWE Flag Count',
                       'ECE Flag Cnt',
                       'Down/Up Ratio',
                       'Subflow Fwd Pkts',
                       'Subflow Fwd Byts',
                       'Subflow Bwd Pkts',
                       'Subflow Bwd Byts',
                       'Init Fwd Win Byts',
                       'Init Bwd Win Byts',
                       'Fwd Act Data Pkts',
                       'Fwd Seg Size Min'
                       ]


def prep_pipeline(filename, encoding='utf_8'):
    # pre-process and clean dataset
    pass
    # Read the CSV file using pandas
    data = pd.read_csv(filename, encoding=encoding)
    data = util.fix_headers(data)
    target_names = util.get_target_names(data)
    feature_data = util.data_training_prep(data)  # clean and prep all data
    # grab test answers
    answer_key = util.get_targets_int(data)  # grab test answers before they are purged
    # Grab only columns needed
    feature_data = feature_data.filter(BRUTEFORCE_FEATURES, axis='columns')
    assert len(answer_key) == len(feature_data)
    return feature_data, answer_key, target_names


# Craft the default specific path to the resources folder which holds the training and testing data
st_path = os.path.join(os.getcwd(), 'resources', 'TrafficLabelling')
# Specify the training file
# Webattacks
# st_file = 'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv'
# st_file_2 = 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
# DDos
# st_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
# Brute force
st_file = 'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv'
st_file_2 = 'Tuesday-WorkingHours.pcap_ISCX.csv'
# Misc
# st_file = 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Morning.pcap_ISCX.csv'
# st_file = 'Monday-WorkingHours.pcap_ISCX.csv'
# st_file = 'Wednesday-workingHours.pcap_ISCX.csv'
# encoding = 'cp1252'
encoding = 'utf_8'

df_features, df_targets, df_target_names = prep_pipeline(os.path.join(st_path, st_file))

# ***************************************
# MODELING
# ***************************************
# Split the data into training and testing sets

if USE_TRAINED_MODEL:
    # Load pretrained Decision Tree Classifier
    clf = load('decisionTree_BruteForce.joblib.backup')
    prediction_test = clf.predict(df_features)
    true_test = df_targets  # rename for classification_report
else:
    # Build new training data
    X_train, X_test, true_train, true_test = train_test_split(df_features,
                                                              df_targets,
                                                              test_size=0.5,
                                                              random_state=42)
    # Training the model
    # Decision Tree Classifier - This is the key part of the code.
    clf = DecisionTreeClassifier(max_depth=5)
    clf.fit(X_train, true_train)
    dump(clf, 'decisionTree_BruteForce.joblib')
    # Testing the Model - Predictions and Evaluations
    prediction_test = clf.predict(X_test)  # Test split data

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
test_features, test_targets, test_target_names = prep_pipeline(os.path.join(st_path, st_file_2), encoding)


# Make predictions
prediction_test = clf.predict(test_features)
print('***** Classification RUN Report *****\n{}\n**********'.format(classification_report(test_targets,
                                                                                           prediction_test,
                                                                                           target_names=test_target_names)))
