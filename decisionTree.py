import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np

le = LabelEncoder()

# Specify the file path, file name, and encoding format
st_path = 'C:/Users/lenovo/DataSet/CIC-IDS-2017/GeneratedLabelledFlows/TrafficLabelling/'
# st_file = 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
st_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
# st_file = 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Morning.pcap_ISCX.csv'
# st_file = 'Monday-WorkingHours.pcap_ISCX.csv'
# st_file = 'Tuesday-WorkingHours.pcap_ISCX.csv'
# st_file = 'Wednesday-workingHours.pcap_ISCX.csv'
encoding = 'cp1252'

# Read the CSV file using pandas
df_data = pd.read_csv(st_path+st_file, encoding=encoding)
df_data.head()

# Drop the columns that are not needed for the model
df_features = df_data.drop(' Label', axis=1) # Features
df_target = df_data[' Label'] # Target variable

# Iterate over the columns in the dataframe to check if they are strings
for st_col in df_features.columns:
  if df_features[st_col].dtypes not in ['int64', 'float64']:
    print(df_features[st_col].dtypes)    
    df_features[st_col] = le.fit_transform(df_features[st_col])


# Search for the columns with infinite values
lt_columns = df_features[df_features.columns[df_features.max() == np.inf]].columns

# modify infinite values (10 x max)
for st_column_inf in lt_columns:
  print(st_column_inf)
  df_column_aux = df_features[st_column_inf]
  # identify the max value
  vl_max_aux = df_column_aux[df_column_aux < np.inf].max()
  print(vl_max_aux)
  # .loc is important to modify the value in the dataframe
  df_features.loc[df_features[st_column_inf] == np.inf, st_column_inf] = 10*vl_max_aux


# check if there are still columns with infinite values
lt_columns = df_features[df_features.columns[df_features.max() == np.inf]].columns
print('columns inf', lt_columns)


# Search for the columns with NaN values
for st_column_nan in df_features.columns:
  df_column_aux = df_features[df_features[st_column_nan].isna()].copy()
  if len(df_column_aux) > 0:
    print(df_column_aux.transpose())
    print(df_target[df_features[st_column_nan].isna()].transpose())
    print(st_column_nan)
    print('The total amount of NaNs are', len(df_features[df_features[st_column_nan].isna()]))
    print(df_features[st_column_nan].describe())
# Drop the rows with NaN values
df_features.dropna(inplace=True)
df_target = df_target[df_target.index.isin(df_features.index)]


# Scale numerical features
scaler = StandardScaler()
mt_features_scaled = scaler.fit_transform(df_features)

# This is the MODEL
## Split the data into training and testing sets

X_train, X_test, y_train, y_test = train_test_split(mt_features_scaled, df_target, test_size=0.2, random_state=42)

# Training the model

## Decision Tree Classifier - This is the key part of the code. This could be modifid to RandomForestClassifier, etc

clf = DecisionTreeClassifier()
clf.fit(X_train, y_train)

## Predictions and Evaluations
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))


# Confusion Matrix
mt_results = np.concatenate((np.matrix(y_pred), np.matrix(y_test)))
df_results = pd.DataFrame(mt_results, index=['pred', 'test']).transpose()
df_results['equals'] = df_results['test'] == df_results['pred']

vl_equals = len(df_results[df_results['equals'] == True])
vl_len_data = len(df_results)
print('total', vl_equals, vl_len_data, vl_equals/vl_len_data)

df_ddos = df_results[df_results['test'] != 'BENIGN'].copy()
vl_equals = len(df_ddos[df_ddos['equals'] == True])
vl_len_data = len(df_ddos)
print('Attack', vl_equals, vl_len_data, vl_equals/vl_len_data)

# df_results = pd.DataFrame(y_pred, columns=['pred'])
# df_results = pd.concat((df_results, pd.DataFrame(y_test, columns=['test'])), axis=1)
df_results