from sklearn.cluster import AgglomerativeClustering
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import time
import matplotlib.pyplot as plt
import numpy as np
from syscall_parser import count_syscalls

# def plot_clustering(X_red, labels, title=None):
#     x_min, x_max = np.min(X_red, axis=0), np.max(X_red, axis=0)
#     X_red = (X_red - x_min) / (x_max - x_min)

#     plt.figure(figsize=(6, 4))

#     plt.xticks([])
#     plt.yticks([])
#     if title is not None:
#         plt.title(title, size=17)
#     plt.axis('off')
#     plt.tight_layout(rect=[0, 0.03, 1, 0.95])




f = open(r"C:\Users\Iván\Desktop\TFG Github\net_analyzer.py\samples_label.txt", "r")
samples_data = f.read().split("\n")
f.close()

samples_label_dict = {}
print("Getting and preparing features...")
t = time.time()
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
    y.append(samples_label_dict[key])

print("Features extracted and prepared in " + str(time.time()-t)+" seconds.")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=0)
print("Training...")
t0 = time.time()
clf = RandomForestClassifier()#max_depth=5, random_state=0)
svc = make_pipeline(StandardScaler(),SVC(gamma="auto"))
clf.fit(X_train, y_train)
svc.fit(X_train, y_train)
t1 = time.time()
print("Training finished in "+str(t1-t0)+" seconds.")
print("Starting score evaluation...")
print("Classification for Random Forest: "+ str(clf.score(X_test,y_test)))
print("Classification for SVC: " + str(svc.score(X_test, y_test)))
t2 = time.time()
print("Score evaluation finished in "+str(t2-t1)+" seconds.")
print("Total time for training and evaluating: "+str(t2-t0)+" seconds.")
