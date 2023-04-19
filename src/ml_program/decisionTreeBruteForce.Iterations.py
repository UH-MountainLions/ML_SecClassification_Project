# -*- coding: utf-8 -*-
"""decisionTree supervised learning algorithm for classification of BruteForce attacks.

Full license in LICENSE.md
"""
import os
from itertools import chain, combinations
from joblib import dump, load
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay, f1_score
import utilities as util


# The list of features for detecting bruteforce (FTP/SSH) attacks.
BRUTEFORCE_FEATURES = ['Dst Port',
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
                       'Fwd Seg Size Min'
                       ]


def powerset(iterable):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)  # allows duplicate elements
    return chain.from_iterable(combinations(s, r) for r in range(len(s)+1))


def prep_pipeline(filename, file_encoding='utf_8'):
    # Read the CSV file using pandas
    data = pd.read_csv(filename, encoding=file_encoding)
    data = util.fix_headers(data)
    target_names = util.get_target_names(data)
    # clean and prep all data
    feature_data = util.data_training_prep(data)
    # grab test answers
    answer_key = util.get_targets_int(data)  # grab test answers before they are purged
    assert len(answer_key) == len(feature_data)
    return feature_data, answer_key, target_names


def get_features_data(data, features=BRUTEFORCE_FEATURES):
    # Grab only columns needed
    return data.filter(features, axis='columns')


def fit_and_predict(features, answers):

    return clf


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

# load training data
train_data, train_answers, train_target_names = prep_pipeline(os.path.join(st_path, st_file), encoding)
# load testing data
test_data, test_answers, test_target_names = prep_pipeline(os.path.join(st_path, st_file_2), encoding)

# ***************************************
# MODELING
# ***************************************
# Split the data into training and testing sets
# Build new training data
# X_train, X_test, true_train, true_test = train_test_split(df_features,
#                                                           df_targets,
#                                                           test_size=0.6,
#                                                           random_state=42)
# Training the model
# Decision Tree Classifier - This is the key part of the code.
# TODO build feature finding

old_score = 0
for x in powerset(BRUTEFORCE_FEATURES):
    if x == ():
        continue
    train_features = get_features_data(train_data, x)
    test_features = get_features_data(test_data, x)
    # Make predictions
    clf = DecisionTreeClassifier()
    try:
        clf.fit(train_features, train_answers)
    except ValueError as err:
        print('ValueError: {} :: {}'.format(err, x))
        continue
    prediction_test = clf.predict(test_features)
    current_score = f1_score(test_answers, prediction_test, average='macro')
    if current_score > old_score:
        clf_save = clf
        old_score = current_score
        save_features = x
        print('{}\n{}\n************'.format(classification_report(test_answers, prediction_test, target_names=test_target_names),
                                            x)
              )

# Final report
test_features = get_features_data(test_data, save_features)
prediction_test = clf_save.predict(test_features)
print('***** Classification RUN Report *****\n{}\n**********'.format(classification_report(test_answers,
                                                                                           prediction_test,
                                                                                           target_names=test_target_names)))
# Display Results - Confusion Matrix
cm = confusion_matrix(test_answers, prediction_test)
disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                              display_labels=test_target_names)
disp.plot()
print('Confusion Matrix:\n{}'.format(cm))
