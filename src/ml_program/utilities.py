# -*- coding: utf-8 -*-
"""shared utilities for supervised learning algorithm for classification.

Full license in LICENSE.md
"""
import numpy as np
from sklearn.preprocessing import LabelEncoder
import pandas as pd
from imblearn.pipeline import Pipeline
from imblearn.over_sampling import RandomOverSampler
from imblearn.under_sampling import RandomUnderSampler

# List of headers that are not required
DROP_HEADERS = ["Flow ID",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Fwd Header Length.1",
                "Timestamp"
                ]
# Global dict to convert various headers into a central, common header structure.
# in the structure of {"str_to_be_changed_to": ["str_to_look_for_to_change_from"]
CONVERT_HEADERS = {"Destination Port": ["Dst Port"],
                   "Protocol": ["Protocol"],
                   "Timestamp": ["Timestamp"],
                   "Flow Duration": ["Flow Duration"],
                   "Total Fwd Packets": ["Tot Fwd Pkts"],
                   "Total Backward Packets": ["Tot Bwd Pkts"],
                   "Total Length of Fwd Packets": ["TotLen Fwd Pkts"],
                   "Total Length of Bwd Packets": ["TotLen Bwd Pkts"],
                   "Fwd Packet Length Max": ["Fwd Pkt Len Max"],
                   "Fwd Packet Length Min": ["Fwd Pkt Len Min"],
                   "Fwd Packet Length Mean": ["Fwd Pkt Len Mean"],
                   "Fwd Packet Length Std": ["Fwd Pkt Len Std"],
                   "Bwd Packet Length Max": ["Bwd Pkt Len Max"],
                   "Bwd Packet Length Min": ["Bwd Pkt Len Min"],
                   "Bwd Packet Length Mean": ["Bwd Pkt Len Mean"],
                   "Bwd Packet Length Std": ["Bwd Pkt Len Std"],
                   "Flow Bytes/s": ["Flow Byts/s"],
                   "Flow Packets/s": ["Flow Pkts/s"],
                   "Flow IAT Mean": ["Flow IAT Mean"],
                   "Flow IAT Std": ["Flow IAT Std"],
                   "Flow IAT Max": ["Flow IAT Max"],
                   "Flow IAT Min": ["Flow IAT Min"],
                   "Fwd IAT Total": ["Fwd IAT Tot"],
                   "Fwd IAT Mean": ["Fwd IAT Mean"],
                   "Fwd IAT Std": ["Fwd IAT Std"],
                   "Fwd IAT Max": ["Fwd IAT Max"],
                   "Fwd IAT Min": ["Fwd IAT Min"],
                   "Bwd IAT Total": ["Bwd IAT Tot"],
                   "Bwd IAT Mean": ["Bwd IAT Mean"],
                   "Bwd IAT Std": ["Bwd IAT Std"],
                   "Bwd IAT Max": ["Bwd IAT Max"],
                   "Bwd IAT Min": ["Bwd IAT Min"],
                   "Fwd PSH Flags": ["Fwd PSH Flags"],
                   "Bwd PSH Flags": ["Bwd PSH Flags"],
                   "Fwd URG Flags": ["Fwd URG Flags"],
                   "Bwd URG Flags": ["Bwd URG Flags"],
                   "Fwd Header Length": ["Fwd Header Len"],
                   "Fwd Header Length.1": ["Fwd Header Length.1"],
                   "Bwd Header Length": ["Bwd Header Len"],
                   "Fwd Packets/s": ["Fwd Pkts/s"],
                   "Bwd Packets/s": ["Bwd Pkts/s"],
                   "Min Packet Length": ["Pkt Len Min"],
                   "Max Packet Length": ["Pkt Len Max"],
                   "Packet Length Mean": ["Pkt Len Mean"],
                   "Packet Length Std": ["Pkt Len Std"],
                   "Packet Length Variance": ["Pkt Len Var"],
                   "FIN Flag Count": ["FIN Flag Cnt"],
                   "SYN Flag Count": ["SYN Flag Cnt"],
                   "RST Flag Count": ["RST Flag Cnt"],
                   "PSH Flag Count": ["PSH Flag Cnt"],
                   "ACK Flag Count": ["ACK Flag Cnt"],
                   "URG Flag Count": ["URG Flag Cnt"],
                   "CWE Flag Count": ["CWE Flag Count"],
                   "ECE Flag Count": ["ECE Flag Cnt"],
                   "Down/Up Ratio": ["Down/Up Ratio"],
                   "Avg Packet Size": ["Pkt Size Avg", "Average Packet Size"],
                   "Avg Fwd Segment Size": ["Fwd Seg Size Avg"],
                   "Avg Bwd Segment Size": ["Bwd Seg Size Avg"],
                   "Fwd Avg Bytes/Bulk": ["Fwd Byts/b Avg"],
                   "Fwd Avg Packets/Bulk": ["Fwd Pkts/b Avg"],
                   "Fwd Avg Bulk Rate": ["Fwd Blk Rate Avg"],
                   "Bwd Avg Bytes/Bulk": ["Bwd Byts/b Avg"],
                   "Bwd Avg Packets/Bulk": ["Bwd Pkts/b Avg"],
                   "Bwd Avg Bulk Rate": ["Bwd Blk Rate Avg"],
                   "Subflow Fwd Packets": ["Subflow Fwd Pkts"],
                   "Subflow Fwd Bytes": ["Subflow Fwd Byts"],
                   "Subflow Bwd Packets": ["Subflow Bwd Pkts"],
                   "Subflow Bwd Bytes": ["Subflow Bwd Byts"],
                   "Init Fwd Win Byts": ["Init_Win_bytes_forward"],
                   "Init Bwd Win Byts": ["Init_Win_bytes_backward"],
                   "Fwd Act Data Pkts": ["act_data_pkt_fwd"],
                   "Fwd Seg Size Min": ["min_seg_size_forward"],
                   "Active Mean": ["Active Mean"],
                   "Active Std": ["Active Std"],
                   "Active Max": ["Active Max"],
                   "Active Min": ["Active Min"],
                   "Idle Mean": ["Idle Mean"],
                   "Idle Std": ["Idle Std"],
                   "Idle Max": ["Idle Max"],
                   "Idle Min": ["Idle Min"],
                   "Label": ["Label"]
                   }


def convert(lst):
    """convert a list into a dict of very specific shape

    This method will take a simple list, and convert that list into a dict that is `value: place`
    e.g., ['one', 'two', 'three'] returns {'one': 0, 'two': 1, 'three': 2}
    This is required for DataFrame mapping of values from string to an integer in order of appearance.

    :param lst: (list) to convert into a dict
    :return: (dict)
    """
    res_dct = {lst[i]: i for i in range(0, len(lst))}
    return res_dct


def fix_headers(data):
    """Normalize headers from packet dumps.

    Normalize headers using the CONVERT_HEADERS dict to account for documented possible changes in header table.
    This will also strip all white space at the beginning and end of the header string.

    :param data: Raw Dataframe
    :return:
    """
    old_lst = []
    fix_lst = []
    # Strip beginning and end white spaces in headers
    for column in data.columns:
        old_lst.append(column)
        fix_lst.append(column.strip())
    res_dct = {old_lst[i]: fix_lst[i] for i in range(len(data.columns))}  # Build converting dict for DataFrame.Rename
    data = data.rename(res_dct, axis='columns')
    # Convert any headers according to the CONVERT_HEADERS dict.
    old_lst = []
    fix_lst = []
    for column in data.columns:
        for header in CONVERT_HEADERS:
            if column in CONVERT_HEADERS[header]:
                old_lst.append(column)
                fix_lst.append(header)
    res_dct = {old_lst[i]: fix_lst[i] for i in range(len(old_lst))}  # Build converting dict for DataFrame.Rename
    data = data.rename(res_dct, axis='columns')
    # Drop useless headers
    data.drop(DROP_HEADERS, axis='columns', errors='ignore', inplace=True)
    return data


def resample(data, answers):
    """

    :param data: (pandas.DataFrame) dataframe without answer key.
    :param answers: (list) of answers from the original dataframe
    :return: (tuple) 0: list of transformed samples
                     1: list of transformed target
    """
    assert len(data) == len(answers)  # sanity check
    # Define the oversampling and undersampling methods
    over_sampler = RandomOverSampler(sampling_strategy='auto')
    under_sampler = RandomUnderSampler(sampling_strategy='auto')

    # Create a pipeline for resampling
    pipeline = Pipeline(steps=[('o', over_sampler),
                               ('u', under_sampler)])
    X_resampled, y_resampled = pipeline.fit_resample(data, answers)

    unique, counts = np.unique(y_resampled, return_counts=True)
    new_class_distribution = dict(zip(unique, counts))
    print('new_class_distribution:', new_class_distribution)

    # Fit and transform the dataset using the pipeline
    return X_resampled, y_resampled


def get_target_names(data, column: str = 'Label') -> list:
    """Build a list of unique values from the 'answer key' column for supervised learning.

    This method was built to get a list of target labels for supervised learning. The dataframe will
    return the target values in the order they first appear and build an

    :param data: (pandas.DataFrame) Initial dataset which still has the "answer key" attached.
    :param column: (str) Column name that contains supervised training answers
    :return: (list) List of unique values from 'answer key' in order that they first appear in data
             set.
    """
    return np.unique(data[column].dropna())


def get_targets_int(data, column='Label'):
    """Get the list of target values from the Label column

    Grabs just the supervised training results, and maps it as an ordered integer according to the
    "get_target_names" method.

    :param data: (pandas.DataFrame) raw Dataframe with answers still included
    :param column: (str) name of the column in the DataFrame where the answers are stored
    :return: (list) values from `Label` column mapped as integer values.
    """
    target_names = get_target_names(data)
    # `dataframe.map(<dict>)` works with dict `{"what you have": "what you want it to become"}`
    return data[column].map(convert(target_names))


def prep_pipeline(filename: str, features: list=None, encoding: str='utf_8' ):
    """

    :param filename: (str) full path of the csv file to import
    :param features: (list) List of features to select out of the csv file.
    :param encoding: (str) different encoding if needed.
    :return: (tuple) of 0: pandas.Dataframe of all data (minus answers);
                      1: List of all training answers
                      2: List of unique answers in order of appearance in raw data
    """
    # Read the CSV file using pandas
    data = pd.read_csv(filename, encoding=encoding, encoding_errors='ignore')
    data = fix_headers(data)
    target_names = get_target_names(data)  # Get training data results
    feature_data = data_training_prep(data)  # clean and prep all data
    # grab test answers
    answer_key = get_targets_int(data)  # grab test answers before they are purged
    data.drop('Label', axis='columns', inplace=True)
    # Grab only columns needed
    if features is not None:
        feature_data = feature_data.filter(features, axis='columns')
    assert len(answer_key) == len(feature_data)
    return feature_data, answer_key, target_names


def data_training_prep(data):
    """Prepare data for training

    :param data: (pandas.DataFrame) Data set without the answer column.
    :return: (pandas.DataFrame) of cleaned data removing any invalid data points.
    """
    # Drop the rows with NaN values
    data.dropna(inplace=True)
    # Drop answer columns
    if 'Label' in data.columns:
        data.drop(columns='Label')
    elif ' Label' in data.columns:
        data.drop(columns=' Label')
    # Iterate over the columns in the dataframe to check if they are strings
    le = LabelEncoder()
    for col in data.columns:
        if data[col].dtypes not in ['int64', 'float64']:
            data[col] = le.fit_transform(data[col])
            if data[col].dtype == 'int32':
                data[col] = data[col].astype('int64')
            elif data[col].dtype == 'float32':
                data[col] = data[col].astype('float64')

    # Search for the columns with infinite values
    lt_columns = data[data.columns[data.max() == np.inf]].columns

    # modify infinite values (10 x max)
    for st_column_inf in lt_columns:
        df_column_aux = data[st_column_inf]
        # identify the max value
        vl_max_aux = df_column_aux[df_column_aux < np.inf].max()
        # .loc is important to modify the value in the dataframe
        data.loc[data[st_column_inf] == np.inf, st_column_inf] = 10*vl_max_aux

    # check if there are still columns with infinite values
    lt_columns = data[data.columns[data.max() == np.inf]].columns
    assert len(lt_columns) == 0
    return data


if __name__ == '__main__':
    print('Hommie don\'t play that')
