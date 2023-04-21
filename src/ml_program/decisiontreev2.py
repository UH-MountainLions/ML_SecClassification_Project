import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from imblearn.over_sampling import RandomOverSampler
from imblearn.under_sampling import RandomUnderSampler
from imblearn.pipeline import Pipeline

le = LabelEncoder()

st_path = 'C:/Users/lenovo/DataSet/CIC-IDS-2017/GeneratedLabelledFlows/TrafficLabelling/'
# st_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
st_file = 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
# st_file_merged = 'merged.csv'
# st_file = 'Friday-WorkingHours-Morning.pcap_ISCX.csv'
# st_file = 'Monday-WorkingHours.pcap_ISCX.csv'
# st_file = 'Tuesday-WorkingHours.pcap_ISCX.csv'
encoding = 'utf_8'
df_data = pd.read_csv(os.path.join(st_path, st_file), encoding=encoding)
# df_data2 = pd.read_csv(os.path.join(st_path, st_file2), encoding=encoding)
# df_data.columns

# st_path_test_file = 'C:/Users/lenovo/DataSet/MachineLearningCSV/MachineLearningCVE/'
# st_file_test_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
# encoding = 'utf_8'
# df_data_test_file= pd.read_csv(os.path.join(st_path_test_file, st_file_test_file), encoding=encoding)

filtered_df = df_data[df_data[' Label'] != 'BENIGN']
label_column = filtered_df[' Label']
unique_labels = label_column.unique()
print(unique_labels)

## Step 1: Calculate the entropy of the target variable

p_attack = (df_data[" Label"] == "DDoS").mean()
p_normal = (df_data[" Label"] == "BENIGN").mean()
entropy = -(p_attack * np.log2(p_attack)) - (p_normal * np.log2(p_normal))
print('The entropy of the target variable is: ', entropy)

# Split the dataset into features and target variable
X = df_data.drop(" Label", axis=1)  # df_features
y = df_data[" Label"]  # df_target

# Iterate over the columns in the dataframe to check if they are strings
for st_col in X.columns:
    if X[st_col].dtypes not in ['int64', 'float64']:
        # print(X[st_col].dtypes)
        X[st_col] = le.fit_transform(X[st_col])

lt_columns = X[X.columns[X.max() == np.inf]].columns

# modify infinite values (10 x max)
for st_column_inf in lt_columns:
    # print(st_column_inf)
    df_column_aux = X[st_column_inf]
    # identify the max value
    vl_max_aux = df_column_aux[df_column_aux < np.inf].max()
    # print(vl_max_aux)
    # .loc is important to modify the value in the dataframe
    X.loc[X[st_column_inf] == np.inf, st_column_inf] = 10*vl_max_aux

lt_columns = X[X.columns[X.max() == np.inf]].columns
print('columns inf', lt_columns)

# Search for the columns with NaN values
for st_column_nan in X.columns:
    df_column_aux = X[X[st_column_nan].isna()].copy()
    if len(df_column_aux) > 0:
        # print(df_column_aux.transpose())
        # print(y[X[st_column_nan].isna()].transpose())
        # print(st_column_nan)
        print('The total amount of NaNs are', len(X[X[st_column_nan].isna()]))
        # print(X[st_column_nan].describe())

# Drop the columns with NaN values
X.dropna(inplace=True)
y = y[y.index.isin(X.index)]

# Impute missing values
from sklearn.impute import SimpleImputer

imputer = SimpleImputer(strategy='mean')
X_imputed = imputer.fit_transform(X)

# Encode the target variable if it's not numerical
if y.dtype == 'object':
    y = le.fit_transform(y)

# Define the oversampling and undersampling methods
over_sampler = RandomOverSampler(sampling_strategy='auto')
under_sampler = RandomUnderSampler(sampling_strategy='auto')

# Create a pipeline for resampling
pipeline = Pipeline(steps=[('o', over_sampler), ('u', under_sampler)])

# Fit and transform the dataset using the pipeline
X_resampled, y_resampled = pipeline.fit_resample(X_imputed, y)

# Encode the target variable if it's not numerical
if y.dtype == 'object':
    y = le.fit_transform(y)

# Define the oversampling and undersampling methods
over_sampler = RandomOverSampler(sampling_strategy='auto')
under_sampler = RandomUnderSampler(sampling_strategy='auto')

# Create a pipeline for resampling
pipeline = Pipeline(steps=[('o', over_sampler), ('u', under_sampler)])

# Fit and transform the dataset using the pipeline
X_resampled, y_resampled = pipeline.fit_resample(X, y)

# Check the new class distribution
unique, counts = np.unique(y_resampled, return_counts=True)
new_class_distribution = dict(zip(unique, counts))
print('new_class_distribution:', new_class_distribution)

# Scale numerical features
scaler = StandardScaler()
mt_features_scaled = scaler.fit_transform(X_resampled)



## Step 2: Calculate the information gain for each feature

def calculate_entropy(probs):
    probs = np.array(probs)
    non_zero_probs = probs[probs > 0]
    return -np.sum(non_zero_probs * np.log2(non_zero_probs))

## Step 2: Calculate the information gain for each feature

# Calculate the information gain for each feature
features = df_data.drop(" Label", axis=1).columns
information_gains = []

for feature in features:
    # Calculate entropy before splitting on the feature
    entropy_before_split = entropy
    
    # Calculate entropy after splitting on the feature
    grouped_data = df_data.groupby([feature, " Label"]).size().unstack(fill_value=0)
    grouped_probs = grouped_data.div(grouped_data.sum(axis=1), axis=0)
    entropies = grouped_probs.apply(calculate_entropy, axis=1)
    p_values = df_data[feature].value_counts(normalize=True)
    
    entropy_after_split = (p_values * entropies).sum()
    
    # Calculate information gain
    information_gain = entropy_before_split - entropy_after_split
    information_gains.append(information_gain)


# Split the resampled data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(mt_features_scaled, y_resampled, test_size=0.3, random_state=42)

# Train a Decision Tree model
dt_classifier = DecisionTreeClassifier()
dt_classifier.fit(X_train, y_train)

# Make predictions on the testing set
y_pred = dt_classifier.predict(X_test)

# Evaluate the model
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Calculate the new entropy after resampling
p_attack_new = (y_resampled == 1).mean()
p_normal_new = (y_resampled == 0).mean()
entropy_new = -(p_attack_new * np.log2(p_attack_new)) - (p_normal_new * np.log2(p_normal_new))
print('The entropy of the target variable after resampling is: ', entropy_new)



# Plot the confusion matrix
def plot_confusion_matrix(cm, labels):
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False, xticklabels=labels, yticklabels=labels)
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.show()

# Get confusion matrix
cm = confusion_matrix(y_test, y_pred)
labels = np.concatenate((["BENIGN"], unique_labels))

# Call the function to plot the confusion matrix
plot_confusion_matrix(cm, labels)

# Plot feature importances
def plot_feature_importance(importances, feature_names):
    sorted_indices = np.argsort(importances)[::-1]
    plt.figure(figsize=(10, 8))
    plt.title("Feature Importance")
    plt.bar(range(X_train.shape[1]), importances[sorted_indices], align="center")
    plt.xticks(range(X_train.shape[1]), feature_names[sorted_indices], rotation=90)
    plt.tight_layout()
    plt.show()

# Get feature importances from the trained model
feature_importances = dt_classifier.feature_importances_
feature_names = X.columns

# Call the function to plot the feature importance
plot_feature_importance(feature_importances, feature_names)






