import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import f1_score
import joblib
import datetime

DATA_STORED = "website_data_more.npy"
data_array = np.load(DATA_STORED)

features = data_array[:,:-1]
labels = data_array[:,-1]

# Split the data into training and testing sets
features_train, features_test, labels_train, labels_test = train_test_split(
    features, labels, test_size=0.2, random_state=42)

# Train the SVM classifier
svm_classifier = SVC(kernel='linear', C=1.0, random_state=42)
svm_classifier.fit(features_train, labels_train)

# Predict on the test set
predictions = svm_classifier.predict(features_test)

# Compute F1 score
f1 = f1_score(labels_test, predictions)

print("F1 Score:", f1)

# Specify the file path where you want to save the model
model_filename = 'trained_weights/svm_classifier_model.pkl'

# Save the trained SVM model to a file
joblib.dump(svm_classifier, model_filename)

print("Model saved successfully at:", model_filename)