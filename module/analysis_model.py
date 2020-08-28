from sklearn.cluster import AgglomerativeClustering
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.model_selection import ShuffleSplit

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

dictionary = count_syscalls("LIMIT 2000")

for sample in samples_data:
    name = sample.split(" ")[0]
    label = sample.split(" ")[1]
    if(label != "NO_LABEL"):
        samples_label_dict[name] = label

intersection = []
for key in query[1].keys():
    if query[1][key] in samples_label_dict.keys():
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
    y.append(samples_label_dict[query[1][key]])

sss = ShuffleSplit(n_splits=10, random_state=0, test_size=0.7)
train, test = sss.split(X, y)
print(test)
print("Train:\n")
print(train)
# clf = RandomForestClassifier(max_depth=5, random_state=0)
# clf.fit(X, y)
# clf.predict()
