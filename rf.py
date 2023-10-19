import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
import joblib
import datetime

DATA_STORED = "trimmed_data.npy"
data_array = np.load(DATA_STORED)

if data_array.shape[0] == 21:
    data_array = data_array.T

# Assuming numpy array has the shape (num_datapoints, 21)
# The last column is the label, and the first 20 columns are the features
features = data_array[:,:-1]
labels = data_array[:,-1]

# Split the data into training and testing sets
features_train, features_test, labels_train, labels_test = train_test_split(
    features, labels, test_size=0.2, random_state=42)

print(features_train.shape)

# Train the Random Forest classifier
random_forest = RandomForestClassifier(n_estimators=100, random_state=42)
random_forest.fit(features_train, labels_train)

# Predict on the test set
predictions = random_forest.predict(features_test)
print(predictions.shape)

# Compute F1 score
f1 = f1_score(labels_test, predictions)

print("F1 Score:", f1)

save_input = input("Save file? (y/n)")
while save_input != "y" and save_input != "n":
    save_input = input("Save file? (y/n)")
if save_input == "y":
    print("File will be saved under 'trained_weights' folder")
    model_path = input("Filename to save (****.pkl) ")
    if model_path == "":
        model_path = '{}.pkl'.format(str(datetime.datetime.now()))
    else:
        model_path = '{}_.pkl'.format(model_path)
    save_path = '{}/{}'.format("trained_weights/rf", model_path)
    joblib.dump(random_forest, save_path)
    print("Model saved successfully at:", save_path)