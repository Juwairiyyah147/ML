

#----------------importing libraries
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import itertools
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from featureeng import *


#importing the dataset
print(dataset.head())


X = dataset[['use_of_ip','url_length', 'short_url','count@','count_embed_domian','prefix_suffix','sub_domain','https_token',
             'abnormal_url', 'count.', 'count-www', 
       'count_dir',  'count-https',
       'count-http', 'count%', 'count?', 'count-', 'count=', 
       'hostname_length', 'sus_url',  'count-digits',
       'count-letters','fd_length', 'tld_length',]]

#Target Variable
y = dataset['type_code']


#spliting the dataset into training set and test set
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2,shuffle=True, random_state=5)

import sklearn.metrics as metrics

rf = RandomForestClassifier(n_estimators=100,max_features='sqrt')
rf.fit(X_train.values,y_train)
y_pred_rf = rf.predict(X_test.values)
print(classification_report(y_test,y_pred_rf,target_names=['benign', 'defacement','phishing','malware']))

score = metrics.accuracy_score(y_test, y_pred_rf)
print("accuracy:   %0.3f" % score)

#printing confusion matrix
cm = confusion_matrix(y_test, y_pred_rf)
cm_df = pd.DataFrame(cm,
                     index = ['benign', 'defacement','phishing','malware'], 
                     columns = ['benign', 'defacement','phishing','malware'])
plt.figure(figsize=(8,6))
sns.heatmap(cm_df, annot=True,fmt=".1f")
plt.title('Confusion Matrix')
plt.ylabel('Actual Values')
plt.xlabel('Predicted Values')
plt.show()

#plotting feature importance graph
feat_importances = pd.Series(rf.feature_importances_, index=X_train.columns)
feat_importances.sort_values().plot(kind="barh",figsize=(10, 6))

#pickle file joblib
joblib.dump(rf, '../final_models/rf_final.pkl')



