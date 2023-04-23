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
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA, IncrementalPCA
from sklearn.feature_selection import VarianceThreshold

from sklearn.decomposition import PCA, FactorAnalysis
from sklearn.covariance import ShrunkCovariance, LedoitWolf
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import GridSearchCV


def compute_scores(x):
    pca = PCA(svd_solver="auto")
    fa = FactorAnalysis()

    pca_score, fa_score = [], []
    for n in n_components:
        pca.n_components = n
        fa.n_components = n
        pca_score.append(np.mean(cross_val_score(pca, x)))
        fa_score.append(np.mean(cross_val_score(fa, x)))
    return pca_score, fa_score


def shrunk_cov_score(x):
    shrinkages = np.logspace(-2, 0, 30)
    cv = GridSearchCV(ShrunkCovariance(), {"shrinkage": shrinkages})
    return np.mean(cross_val_score(cv.fit(x).best_estimator_, x))


def lw_score(x):
    return np.mean(cross_val_score(LedoitWolf(), x))


# Craft the default specific path to the resources folder which holds the training and testing data
st_path = os.path.join(os.getcwd(), 'resources', 'TrafficLabelling')
# Specify the training file
# Webattacks
# st_file = 'Friday-23-02-2018_TrafficForML_CICFlowMeter.csv'
# st_file_2 = 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
# DDos
# st_file = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
# Brute force
st_file_2 = 'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv'
st_file = 'Tuesday-WorkingHours.pcap_ISCX.csv'
# Misc
# st_file = 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
# st_file = 'Friday-WorkingHours-Morning.pcap_ISCX.csv'
# st_file = 'Monday-WorkingHours.pcap_ISCX.csv'
# st_file = 'Wednesday-workingHours.pcap_ISCX.csv'
# encoding = 'cp1252'
encoding = 'utf_8'

# Load file
df_features, df_targets, df_target_names = util.prep_pipeline(os.path.join(st_path, st_file))
# Variance Check
sel = VarianceThreshold(threshold=(.8 * (1 - .8)))
sel.fit_transform(df_features)
print(sel.get_feature_names_out())

# PCA
for x in df_features.columns:
    if df_features[x].dtype != 'float64':
        df_features.drop(x, axis='columns')
n_features = len(df_features.columns)
n_components = np.arange(0, n_features, 5)  # options for n_components

for X, title in [(df_features, "first file")]:
    pca_scores, fa_scores = compute_scores(X)
    n_components_pca = n_components[np.argmax(pca_scores)]
    n_components_fa = n_components[np.argmax(fa_scores)]

    pca = PCA(svd_solver="auto", n_components="mle")
    pca.fit(X)
    n_components_pca_mle = pca.n_components_

    print("best n_components by PCA CV = %d" % n_components_pca)
    print("best n_components by FactorAnalysis CV = %d" % n_components_fa)
    print("best n_components by PCA MLE = %d" % n_components_pca_mle)