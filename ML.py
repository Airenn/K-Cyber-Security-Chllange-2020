from operator import length_hint
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import warnings
import seaborn as sns
from sklearn.preprocessing import StandardScaler,MinMaxScaler,LabelEncoder
from sklearn.model_selection import train_test_split,GridSearchCV,StratifiedKFold
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score,roc_auc_score,precision_recall_curve
from sklearn.linear_model import LogisticRegression
import lightgbm as lgb 
from lightgbm import plot_importance
from sklearn.ensemble import RandomForestClassifier

from sklearn.model_selection import KFold
from sklearn.svm import SVC
from sklearn.feature_selection import RFECV, RFE
from sklearn.datasets import load_iris



warnings.filterwarnings('ignore')
pd.set_option('display.max_row', 500)
pd.set_option('display.max_columns', 100)


malware_train_df= pd.read_csv('C:\\Users\\USER\\Desktop\\박해민\\공부\\ML\\2. AI Malware\\2020_train.csv') #학습데이터 
malware_test_df= pd.read_csv('C:\\Users\\USER\\Desktop\\박해민\\공부\\ML\\2. AI Malware\\2020_test.csv') #검증 데이터 
malware_train_df.drop(['Filename'],axis=1,inplace=True)  #학습 File name 제거
malware_test_df.drop(['Filename'],axis=1,inplace=True)  #학습 File name 제거

feature_name = malware_train_df.columns.tolist()
feature_name_df =pd.DataFrame(feature_name, columns=['cloumn_name']) #feature name data frame 


label_train_df=malware_train_df['Label']  #라벨 데이터 
label_test_df= malware_test_df['Label']


std_scaler = StandardScaler() # 평균 0, 분산 1 정규분포 스케일링  


Train_data = malware_train_df.iloc[:, :26] # 사용할 피처 열 
Test_data = malware_test_df.iloc[:, :26]

print(Train_data)
print(Train_data.iloc[:, :3])
std_scaler.fit(Train_data)
print(Test_data)
test_data_standardScaled = std_scaler.transform(Test_data)
print(test_data_standardScaled)
Test_data = pd.DataFrame(test_data_standardScaled, columns=Test_data.columns, index=list(Test_data.index.values))
print(Test_data)
Train_label = pd.DataFrame(data=malware_train_df.Label, columns=['Label'])
print(Test_data.iloc[:, :3])

print(Train_label)
encoder = LabelEncoder()
encoder.fit(Train_label)
labels = encoder.transform(Train_label)

# train__data, test__data, train__label,test__label = train_test_split(Test_data,labels,random_state=2020, shuffle=True) # Train_df.csv에서 학습, 검증용 데이터셋 나눔
################################################## 머신러닝 실행,학습,예측 ##################################################

train_ds = lgb.Dataset(Train_data, label= label_train_df)
# test_ds = lgb.Dataset(Test_data, label= label_test_df)

params = {'learning_rate' : 0.01,
            'max_depth' : 16,
            'boosting' : 'gbdt',
            'objective' : 'binary',
            'metric' : 'binary_logloss',
            'is_training_metric' : True,
            'num_leaves' : 144,
            'feature_fraction' : 0.9,
            'bagging_fraction' : 0.7,
            'bagging_freq' : 5,
            'seed' : 2020
}

lgb_model = lgb.train(params, train_ds, 1000, train_ds, verbose_eval=100, early_stopping_rounds=100)
#lgb.fit(train__data, train__label) # Train_df.csv에서 나눠진 학습용 데이터 학습

####################################################### 정답 예측 #######################################################
Test_Predict = lgb_model.predict(Test_data) # 검증용 데이터셋 정답 예측
#Test_Predict = clf_from_joblib.predict(Test_data)
####################################################### 결과 분석 #######################################################
Test_Predict = pd.DataFrame(Test_Predict)
print(Test_Predict)
print(type(Test_Predict))

#print(test__label)
#print(type(test__label))

prediction=np.expm1(Test_Predict)
Test_Predict=prediction.astype(int)
print(Test_Predict)
Test_Predict.to_csv("RESULT.csv", index=False)

#lgbm_clf = LGBMClassifier(n_estimators=1000,max_depth=128,min_child_samples=60, num_leaves=64,n_jobs=-1, boost_from_average=False)
rf_clf = RandomForestClassifier(random_state=0, verbose=2)
rf_clf.fit(Train_data, label_train_df) # Train_df.csv에서 나눠진 학습용 데이터 학습
Test_Predict = rf_clf.predict(Test_data) # 검증용 데이터셋 정
Test_Predict = pd.DataFrame(Test_Predict)
Test_Predict.to_csv("RESULT2.csv", index=False)
print(Test_Predict)
for i in len(Test_Predict):
    print(i)
"""
for i in lr_clf,lgbm_clf,rf_clf:
    get_model_train_eval(i, ftr_train=X_train, ftr_test=X_test, tgt_train=y_train, tgt_test=y_test)

for i in lr_clf,lgbm_clf,rf_clf:
    exec_kfold(i,folds=5)
"""
# #Xgb
# xgb_clf = XGBClassifier(n_estimators=1000, random_state=156, learning_rate=0.02, max_depth=5,\
#                         min_child_weight=1, colsample_bytree=0.75, reg_alpha=0.03)

# # evaluation metric을 auc로, early stopping은 200 으로 설정하고 학습 수행. 
# xgb_clf.fit(X_train, y_train, early_stopping_rounds=200, 
#             eval_metric="auc",eval_set=[(X_train, y_train), (X_test, y_test)])

# xgb_roc_score = roc_auc_score(y_test, xgb_clf.predict_proba(X_test)[:,1],average='macro')
# print('ROC AUC: {0:.4f}'.format(xgb_roc_score))
# get_model_train_eval(xgb_Clf, ftr_train=X_train, ftr_test=X_test, tgt_train=y_train, tgt_test=y_test)    

#lgbm 
LGBM_clf = LGBMClassifier(n_estimators=1000)

params = {'num_leaves': [32, 64 ],
          'max_depth':[128, 160],
          'min_child_samples':[60, 100],
          'subsample':[0.8, 1]}

# 
# 하이퍼 파라미터 테스트의 수행속도를 향상 시키기 위해 cv 를 지정하지 않습니다. 
gridcv = GridSearchCV(LGBM_clf, param_grid=params,cv=5)
gridcv.fit(X_train, y_train, early_stopping_rounds=30, eval_metric="auc",
           eval_set=[(X_train, y_train),(X_test, y_test)])

print('GridSearchCV 최적 파라미터:', gridcv.best_params_)
lgbm_roc_score = roc_auc_score(y_test, gridcv.predict_proba(X_test)[:,1], average='macro')
print('ROC AUC: {0:.4f}'.format(lgbm_roc_score))

lgbm_clf = LGBMClassifier(n_estimators=1000,max_depth=128,min_child_samples=60,num_iterations=500, num_leaves=32,subsmaple=0.8,n_jobs=-1, boost_from_average=False)
get_model_train_eval(i, ftr_train=X_train, ftr_test=X_test, tgt_train=y_train, tgt_test=y_test)

# score.rank(xgb_clf)
ftr_importances_values =i.feature_importances_
ftr_importances = pd.Series(ftr_importances_values,index=X_train.columns)
ftr_top20 = ftr_importances.sort_values(ascending=False)[:20]
plt.figure(figsize=(8,10))
print(ftr_top20)
plt.title('Feature importances Top 20')
sns.barplot(x=ftr_top20.index , y =ftr_top20)
plt.xticks(rotation=90)
plt.show()

top=[]

for i in range(len(ftr_top20)):
    top.append(ftr_top20.index[i])

print(top)

#Featur 제거 
# svc = SVC(kernel="linear")
# rfecv = RFECV(estimator=svc, step=1, cv=StratifiedKFold(2),
#               scoring='accuracy', verbose=2)
# rfecv.fit(X_train,y_train)
# print("Optimal number of features : %d" % rfecv.n_features_)

# # Plot number of features VS. cross-validation scores
# plt.figure()
# plt.xlabel("Number of features selected")
# plt.ylabel("Cross validation score (nb of correct classifications)")
# plt.plot(range(1, len(rfecv.grid_scores_) + 1), rfecv.grid_scores_)
# plt.show()
