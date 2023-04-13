# -*- coding: utf-8 -*-
"""decisionTree supervised learning algorithm for classification and regression.

Full license in LICENSE.md
"""
import os
from joblib import dump, load
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np


def convert(lst):
    """convert a list into a dict of very specific shape

    This method will take a simple list, and convert that list into a dict that is value: place
    e.g., ['one', 'two', 'three'] returns {'one': 0, 'two': 1, 'three': 2}
    This is required for DataFrame mapping of values from string to an integer in order of appearance.

    :param lst: list to convert into a dict
    :return: (dict)
    """
    res_dct = {lst[i]: i for i in range(0, len(lst))}
    return res_dct

le = LabelEncoder()


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
# encoding = 'cp1252'
encoding = 'utf_8'

# Read the CSV file using pandas
df_data = pd.read_csv(os.path.join(st_path, st_file), encoding=encoding)

# ***************************************
# Data Prep
# ***************************************

# Drop the columns that are not needed for the model
df_features = df_data.drop(' Label', axis='columns')  # Features
# Build target values for decison tree classifier
df_target_names = np.unique(df_data[' Label'].values)
df_target = df_data[' Label']  # Target variable
df_target = df_target.map(convert(df_target_names))


features = [' Destination Port',
            ' Protocol',
            ' Flow Duration'
            ]
df_features = df_data.filter(features, axis='columns')

# Iterate over the columns in the dataframe to check if they are strings
for st_col in df_features.columns:
    if df_features[st_col].dtypes not in ['int64', 'float64']:
        df_features[st_col] = le.fit_transform(df_features[st_col])


# Search for the columns with infinite values
lt_columns = df_features[df_features.columns[df_features.max() == np.inf]].columns

# modify infinite values (10 x max)
for st_column_inf in lt_columns:
    df_column_aux = df_features[st_column_inf]
    # identify the max value
    vl_max_aux = df_column_aux[df_column_aux < np.inf].max()
    # .loc is important to modify the value in the dataframe
    df_features.loc[df_features[st_column_inf] == np.inf, st_column_inf] = 10*vl_max_aux


# check if there are still columns with infinite values
lt_columns = df_features[df_features.columns[df_features.max() == np.inf]].columns
assert len(lt_columns) == 0


# Search for the columns with NaN values
for st_column_nan in df_features.columns:
    df_column_aux = df_features[df_features[st_column_nan].isna()].copy()
    if len(df_column_aux) > 0:
        print('df_column_aux:\n{}'.format(df_column_aux.transpose()))
        print('Transpose:\n{}\n'.format(df_target[df_features[st_column_nan].isna()].transpose()))
        print('st_column_nan: {}'.format(st_column_nan))
        print('The total amount of NaNs are: {}'.format(len(df_features[df_features[st_column_nan].isna()])))
        print('*** df_features ***\n{}'.format(df_features[st_column_nan].describe()))
# Drop the rows with NaN values
df_features.dropna(inplace=True)
df_target = df_target[df_target.index.isin(df_features.index)]

# ***************************************
# MODELING
# ***************************************
# Split the data into training and testing sets
assert len(df_features) == len(df_target)
X_train, X_test, true_train, true_test = train_test_split(df_features,
                                                          df_target,
                                                          test_size=0.2,
                                                          random_state=42)
# Training the model
# Decision Tree Classifier - This is the key part of the code. This could be modified to
# RandomForestClassifier, etc

clf = DecisionTreeClassifier()
clf.fit(X_train, true_train)
dump(clf, 'decisionTree_Training.joblib')

# Predictions and Evaluations
pred_test = clf.predict(X_test)
print('***** Classification Report *****\n{}\n**********'.format(classification_report(true_test,
                                                                                       pred_test,
                                                                                       target_names=df_target_names)))


# Confusion Matrix
cm = confusion_matrix(true_test, pred_test)

vl_equals = len(df_results[df_results['equals'] == True])
vl_len_data = len(df_results)
print('Total:  {}  {}  {}'.format(vl_equals, vl_len_data, vl_equals/vl_len_data))

df_ddos = df_results[df_results['test'] != 'BENIGN'].copy()
vl_equals = len(df_ddos[df_ddos['equals'] == True])
vl_len_data = len(df_ddos)
print('Attack: {}  {}  {}'.format(vl_equals, vl_len_data, vl_equals/vl_len_data))

df_results = pd.DataFrame(y_pred, columns=['pred'])
df_results = pd.concat((df_results, pd.DataFrame(y_test, columns=['test'])), axis=1)
print('df_results:\n{}'.format(df_results))
print('END')
