from sklearn.cluster import AgglomerativeClustering
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from syscall_parser import count_syscalls

import argparse
import time
import matplotlib.pyplot as plt
import numpy as np
import os


dir_path = os.path.dirname(os.path.realpath(__file__))


parser = argparse.ArgumentParser(
    description='Uses machine learning algorithms to classify malware samples using as feautures the syscalls and their number of times called.')
parser.add_argument("-p", "--path", default=str(dir_path) +
                    "\\..\\samples_label.txt", help="Label file path (Format is \"hash256 label\"")
parser.add_argument("-d", "--dictionary", default = None, help="Sample dictionary (Must be a dictionary where hash256 is the key containing a dictionary of syscalls with the times they were called.")

args = parser.parse_args()

path = str(args.path)


f = open(path, "r")
samples_data = f.read().split("\n")
f.close()

samples_label_dict = {}
labels = []
print("Getting and preparing features...")
t = time.time()
if args.dictionary is None:
    dictionary = count_syscalls(0)

for sample in samples_data:
    name = sample.split(" ")[0]
    label = sample.split(" ")[1]
    if(label != "NO_LABEL"):
        samples_label_dict[name] = label
        

intersection = []
for key in dictionary.keys():
    if key in samples_label_dict.keys():
        intersection.append(key)

values = []
hashes = []
for key in intersection:
    values.append(dictionary[key])
    hashes.append(key)

v = DictVectorizer(sparse=False)
X = v.fit_transform(values)
features = v.get_feature_names()

y = []
for key in hashes:
    val = samples_label_dict[key]
    y.append(val)
    if val not in labels:
        labels.append(val)

print("Features extracted and prepared in " + str(time.time()-t)+" seconds.")

classifiers = [
    RandomForestClassifier(),
    make_pipeline(StandardScaler(), SVC(gamma="auto")),
    AdaBoostClassifier(),
    DecisionTreeClassifier()]
names = [
    "RFC",
    "SVC",
    "ABC",
    "DTC"]

scores = []
sizes = [0.2,0.3,0.4,0.5,0.6]
confMat=[]
for tsize in sizes:
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=tsize, random_state=0)
    for j, name, clf in zip(range(len(names)),names, classifiers):
        scores.append([])

        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)
        score = clf.score(X_test, y_test)
        scores[j].append(score)

        if(tsize == 0.4):
            confMat = confusion_matrix(y_test, y_pred, labels=labels)
            classRep = classification_report(y_test, y_pred, labels=labels, zero_division=0)
            print("Results for "+name+":")
            print(classRep)
            fClas = open("..\\results\\Report"+name+".txt", "w")
            fClas.write(classRep)
            fClas.close()
            
            np.savetxt("..\\results\\ConfMatrix"+name+".csv", confMat, delimiter=",",fmt="%d", header=(','.join(labels)), comments="")

print("Confusion Matrix saved in " + str(os.path.dirname(dir_path+"\\.."))+".")



colors = ['b','g','r','y']

for i in range(len(names)):
    
    plt.plot(sizes, scores[i], colors[i]+'-', label=names[i])

    plt.plot(sizes, scores[i], colors[i]+'o')
    

plt.ylabel("Score")
plt.xlabel("Test Size")
plt.title("Scores based in test size for different ML algorithms.")
plt.legend(loc='best')
plt.show()

