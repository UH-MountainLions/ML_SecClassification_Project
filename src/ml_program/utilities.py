# -*- coding: utf-8 -*-
"""shared utilities for supervised learning algorithm for classification and regression.

Full license in LICENSE.md
"""
import numpy as np
from sklearn.preprocessing import LabelEncoder

# Global dict to convert various headers into a central, common header structure.
CONVERT_HEADERS = {"Dst Port": ["Destination Port"],
                   "Protocol": ["Protocol"],
                   "Flow Duration": ["Flow Duration"],
                   "Tot Fwd Pkts": ["Total Fwd Packets"],
                   "Tot Bwd Pkts": ["Total Backward Packets"],
                   "TotLen Fwd Pkts": ["Total Length of Fwd Packets"],
                   "TotLen Bwd Pkts": ["Total Length of Bwd Packets"],
                   "Flow Byts/s": ["Flow Bytes/s"],
                   "Flow Pkts/s": ["Flow Packets/s"],
                   "Fwd IAT Tot": ["Fwd IAT Total"],
                   "Bwd IAT Tot": ["Bwd IAT Total"],
                   "Fwd PSH Flags": ["Fwd PSH Flags"],
                   "Bwd PSH Flags": ["Bwd PSH Flags"],
                   "Fwd URG Flags": ["Fwd URG Flags"],
                   "Bwd URG Flags": ["Bwd URG Flags"],
                   "Fwd Header Len": ["Fwd Header Length"],
                   "Bwd Header Len": ["Bwd Header Length"],
                   "Fwd Pkts/s": ["Fwd Packets/s"],
                   "Bwd Pkts/s": ["Bwd Packets/s"],
                   "FIN Flag Cnt": ["FIN Flag Count"],
                   "SYN Flag Cnt": ["SYN Flag Count"],
                   "RST Flag Cnt": ["RST Flag Count"],
                   "PSH Flag Cnt": ["PSH Flag Count"],
                   "ACK Flag Cnt": ["ACK Flag Count"],
                   "URG Flag Cnt": ["URG Flag Count"],
                   "CWE Flag Cnts": ["CWE Flag Count"],
                   "ECE Flag Cnt": ["ECE Flag Count"],
                   "Down/Up Ratio": ["Down/Up Ratio"],
                   "Subflow Fwd Pkts": ["Subflow Fwd Packets"],
                   "Subflow Fwd Byts": ["Subflow Fwd Bytes"],
                   "Subflow Bwd Pkts": ["Subflow Bwd Packets"],
                   "Subflow Bwd Byts": ["Subflow Bwd Bytes"],
                   "Init Fwd Win Byts": ["Init_Win_bytes_forward"],
                   "Init Bwd Win Byts": ["Init_Win_bytes_backward"],
                   "Fwd Act Data Pkts": ["act_data_pkt_fwd"],
                   "Fwd Seg Size Min": ["min_seg_size_forward"],
                   "Label": ["Label"]
                   }


def convert(lst):
    """convert a list into a dict of very specific shape

    This method will take a simple list, and convert that list into a dict that is `value: place`
    e.g., ['one', 'two', 'three'] returns {'one': 0, 'two': 1, 'three': 2}
    This is required for DataFrame mapping of values from string to an integer in order of appearance.

    :param lst: list to convert into a dict
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
    red_dct = None
    for column in data.columns:
        for header in CONVERT_HEADERS:
            if column in CONVERT_HEADERS[header]:
                old_lst.append(column)
                fix_lst.append(header)
    res_dct = {old_lst[i]: fix_lst[i] for i in range(len(old_lst))}  # Build converting dict for DataFrame.Rename
    data = data.rename(res_dct, axis='columns')
    return data


def get_target_names(data, column: str = 'Label') -> list:
    """Build a list of unique values from the 'answer key' column for supervised learning.

    This method was built to get a list of target labels for supervised learning. The dataframe will return the target
    values in the order they first appear and build an

    :param data: (pandas.DataFrame) Initial dataset which still has the "answer key" attached.
    :param column: (str) Column name that contains supervised training answers
    :return: (list) List of unique values from 'answer key' in order that they first appear in data set.
    """
    return np.unique(data[column].dropna())


def get_targets_int(data, column='Label'):
    """Get the list of target values from the Label column

    Grabs just the supervised training results, and maps it as an ordered integer according to the "get_target_names"
    method.

    :return: (list) values from `Label` column mapped as integer values.
    """
    target_names = get_target_names(data)
    # `dataframe.map(<dict>)` works with dict `{"what you have": "what you want it to become"}`
    return data[column].map(convert(target_names))


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
