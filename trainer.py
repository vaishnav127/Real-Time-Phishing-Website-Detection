import pandas
from sklearn import preprocessing
from sklearn.ensemble import RandomForestClassifier
import numpy
from sklearn import svm
from sklearn import cross_validation as cv
import matplotlib.pylab as plt
import warnings
from sklearn.ensemble import BaggingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
warnings.filterwarnings("ignore", category=DeprecationWarning,
                        module="pandas", lineno=570)
from sklearn.ensemble import GradientBoostingClassifier


#from xgboost import XGBClassifier
def return_nonstring_col(data_cols): # giving columns that are not string in nature like url , host, path
	cols_to_keep=[]
	train_cols=[]
	for col in data_cols:
		if col!='URL' and col!='host' and col!='path':
			cols_to_keep.append(col)
			if col!='malicious' and col!='result':
				train_cols.append(col)
	return [cols_to_keep,train_cols]

def svm_classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	
	clf = svm.SVC()


	
	print (clf.fit(train[train_cols], train['malicious']))
	scores = cv.cross_val_score(clf, train[train_cols], train['malicious'], cv=30)
	print('Estimated score SVM: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

	query['result']=clf.predict(query[train_cols])
	
	print (query[['URL','result']])
	query[['URL','result']].to_csv("C:/Users/hp/phishing/test_predicted_target_svm.csv")


# Called from gui
def forest_classifier_gui(train,query,train_cols):# train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious
	rf = RandomForestClassifier(n_estimators=150)

	print (rf.fit(train[train_cols], train['malicious']))

	query['result']=rf.predict(query[train_cols])

	print (query[['URL','result']].head(2))
	return query['result']


def svm_classifier_gui(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	
	clf = svm.SVC()

	train[train_cols] = preprocessing.scale(train[train_cols])
	query[train_cols] = preprocessing.scale(query[train_cols])
	
	print (clf.fit(train[train_cols], train['malicious']))

	query['result']=clf.predict(query[train_cols])
	
	print (query[['URL','result']].head(2))
	return query['result']


def GradientBoosting_Classifier_gui(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	grad = GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1, random_state=0)
    
	print (grad.fit(train[train_cols], train['malicious']))
	query['result']=grad.predict(query[train_cols])
	print (query[['URL','result']].head(2))
	return query['result']

    
    
    
def forest_classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	rf = RandomForestClassifier(n_estimators=150)

	print (rf.fit(train[train_cols], train['malicious']))
	scores = cv.cross_val_score(rf, train[train_cols], train['malicious'], cv=30)
	print('Estimated score RandomForestClassifier: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

	query['result']=rf.predict(query[train_cols])
	print (query[['URL','result']])
	query[['URL','result']].to_csv("C:/Users/hp/phishing/test_predicted_target_rf.csv")

def Bagging_Classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	bag = BaggingClassifier(n_estimators=150)

	print (bag.fit(train[train_cols], train['malicious']))
	scores = cv.cross_val_score(bag, train[train_cols], train['malicious'], cv=30)
	print('Estimated score BaggingClassifier : %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

	query['result']=bag.predict(query[train_cols])
	print (query[['URL','result']])
	query[['URL','result']].to_csv("C:/Users/hp/phishing/test_predicted_target_bag.csv")

	
def logistic_regression(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	logis = LogisticRegression()
    
	print (logis.fit(train[train_cols], train['malicious']))
	scores = cv.cross_val_score(logis, train[train_cols], train['malicious'], cv=30)
	print('Estimated score logisticregression : %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

	query['result']=logis.predict(query[train_cols])
	print (query[['URL','result']])
	query[['URL','result']].to_csv("C:/Users/hp/phishing/test_predicted_target_logis.csv")


def DecisionTree_Classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	deci = DecisionTreeClassifier(random_state = 100,max_depth=3, min_samples_leaf=5)
	print (deci.fit(train[train_cols], train['malicious']))
	scores = cv.cross_val_score(deci, train[train_cols], train['malicious'], cv=30)
	print('Estimated score decisiontreeclassifier : %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

	query['result']=deci.predict(query[train_cols])
	print (query[['URL','result']])
	query[['URL','result']].to_csv("C:/Users/hp/phishing/test_predicted_target_deci.csv")

        
def KNeighbors_Classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	Kneigh = KNeighborsClassifier()
	print (Kneigh.fit(train[train_cols], train['malicious']))
	scores = cv.cross_val_score(Kneigh, train[train_cols], train['malicious'], cv=30)
	print('Estimated score KNeighborsClassifier : %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

	query['result']=Kneigh.predict(query[train_cols])
	print (query[['URL','result']])
	query[['URL','result']].to_csv("C:/Users/hp/phishing/test_predicted_target_Kneigh.csv")

    
    
def GradientBoosting_Classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	grad = GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1, random_state=0)
    
	print (grad.fit(train[train_cols], train['malicious']))
	scores = cv.cross_val_score(grad, train[train_cols], train['malicious'], cv=30)
	print('Estimated score GradientBoostingClassifier : %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

	query['result']=grad.predict(query[train_cols])
	print (query[['URL','result']])
	query[['URL','result']].to_csv("C:/Users/hp/phishing/test_predicted_target_grad.csv")

    
def Xg_boost(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious

	xg = XGBClassifier()
    
	print (xg.fit(train[train_cols], train['malicious']))
	scores = cv.cross_val_score(xg, train[train_cols], train['malicious'], cv=30)
	print('Estimated score Xgboost : %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))

	query['result']=xg.predict(query[train_cols])
	print (query[['URL','result']])
	query[['URL','result']].to_csv("C:/Users/hp/phishing/test_predicted_target_xg.csv")


def train(db,test_db):

	query_csv = pandas.read_csv(test_db)
	cols_to_keep,train_cols=return_nonstring_col(query_csv.columns)
	#query=query_csv[cols_to_keep]

	train_csv = pandas.read_csv(db)
	cols_to_keep,train_cols=return_nonstring_col(train_csv.columns)
	train=train_csv[cols_to_keep]

	#svm_classifier(train_csv,query_csv,train_cols)

	#forest_classifier(train_csv,query_csv,train_cols)
    
	#Bagging_Classifier(train_csv,query_csv,train_cols)
	
	#logistic_regression(train_csv,query_csv,train_cols)

	#DecisionTree_Classifier(train_csv,query_csv,train_cols)
	
	#KNeighbors_Classifier(train_csv,query_csv,train_cols)
	GradientBoosting_Classifier(train_csv,query_csv,train_cols)
	#Xg_boost(train_csv,query_csv,train_cols)
def gui_caller(db,test_db):
	
	query_csv = pandas.read_csv(test_db)
	cols_to_keep,train_cols=return_nonstring_col(query_csv.columns)
	#query=query_csv[cols_to_keep]

	train_csv = pandas.read_csv(db)
	cols_to_keep,train_cols=return_nonstring_col(train_csv.columns)
	train=train_csv[cols_to_keep]

	return forest_classifier_gui(train_csv,query_csv,train_cols)	
	#return svm_classifier_gui(train_csv,query_csv,train_cols)	

	#return GradientBoosting_Classifier_gui(train_csv,query_csv,train_cols)