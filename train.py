# About: Use supervised learning classifiers to predict intrusion/suspicious activities in HTTP logs
# Author: Updated for enhanced functionality

import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE  # To handle class imbalance
from utilities import save_model, get_accuracy

SPECIAL_CHARS = set("[$&+,:;=?@#|'<>.^*()%!-]")

# Paths to training and testing datasets
TRAINING_DATA_PATH = "C:/Users/Nathan/Desktop/Intrusion-and-anomaly-detection-with-machine-learning-master/SAMPLE_DATA/labeled-encoded-data-samples/aug_sep_oct_2021.csv"
TESTING_DATA_PATH = "C:/Users/Nathan/Desktop/Intrusion-and-anomaly-detection-with-machine-learning-master/SAMPLE_DATA/labeled-encoded-data-samples/may_jun_jul_2021.csv"

# Default training algorithm
TRAINING_ALGORITHM = 'rf'  # Options: 'rf' for Random Forest, 'lr' for Logistic Regression

# Function to preprocess raw HTTP log data
def preprocess_data(csv_data):
    """
    Preprocess the raw HTTP log data to extract numerical features.

    Args:
        csv_data (str): Path to the CSV file.

    Returns:
        tuple: A tuple containing:
            - features (numpy.ndarray): The feature matrix.
            - labels (numpy.ndarray): The labels.
    """
    try:
        # Load the raw log data
        data = pd.read_csv(csv_data)

        # Extract labels (assuming the column is named 'label')
        labels = data['label'].to_numpy()

        # Extract numerical features from raw logs
        features = []
        for log_line in data['log_line']:
            parsed_features = parse_log_line(log_line)
            features.append(parsed_features)

        return np.array(features), labels

    except Exception as e:
        print(f"Error preprocessing data: {e}")
        sys.exit(1)

# Function to parse a single HTTP log line
def parse_log_line(log_line):
    """
    Parse a single HTTP log line and extract numerical features.

    Args:
        log_line (str): A single HTTP log line.

    Returns:
        list: Extracted features [url_length, return_code, size, special_chars, url_depth, contains_suspicious_keywords].
    """
    try:
        parts = log_line.split('"')
        if len(parts) < 3:
            return [0, 0, 0, 0, 0, 0]

        request_part = parts[1].split(' ')
        url = request_part[1] if len(request_part) > 1 else ""

        response_part = parts[2].strip().split(' ')
        return_code = int(response_part[0]) if len(response_part) > 0 and response_part[0].isdigit() else 0
        size = int(response_part[1]) if len(response_part) > 1 and response_part[1].isdigit() else 0

        # Additional features
        special_chars = sum(1 for char in url if char in SPECIAL_CHARS)
        url_depth = url.count("/")
        contains_suspicious_keywords = int(any(keyword in url.lower() for keyword in ['sql', 'xss', 'eval', 'union']))

        return [len(url), return_code, size, special_chars, url_depth, contains_suspicious_keywords]

    except Exception as e:
        print(f"Error parsing log line: {e}")
        return [0, 0, 0, 0, 0, 0]

# Main script
try:
    # Preprocess training and testing data
    print(f"Loading training data from: {TRAINING_DATA_PATH}")
    training_features, training_labels = preprocess_data(TRAINING_DATA_PATH)

    print(f"Loading testing data from: {TESTING_DATA_PATH}")
    testing_features, testing_labels = preprocess_data(TESTING_DATA_PATH)

    # Debugging: Print sample features and labels
    print("Sample Training Features:", training_features[:5])
    print("Sample Testing Features:", testing_features[:5])

    # Handle class imbalance using SMOTE
    smote = SMOTE(random_state=42)
    training_features, training_labels = smote.fit_resample(training_features, training_labels)

    # Scale features to handle varying ranges
    scaler = StandardScaler()
    training_features = scaler.fit_transform(training_features)
    testing_features = scaler.transform(testing_features)

    # Check correlation of features with labels (optional for debugging)
    df = pd.DataFrame(training_features, columns=["url_length", "return_code", "size", "special_chars", "url_depth", "contains_suspicious_keywords"])
    df["label"] = training_labels
    print("Feature-Label Correlation:")
    print(df.corr())

    # Initialize the model
    if TRAINING_ALGORITHM == 'rf':
        print("\n\n=-=-=-=-=-=-=- Random Forest Classifier -=-=-=-=-=-=-=-\n")
        attack_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    elif TRAINING_ALGORITHM == 'lr':
        print("\n\n=-=-=-=-=-=-=- Logistic Regression Classifier -=-=-=-=-=-\n")
        attack_classifier = LogisticRegression(max_iter=1000, random_state=42)
    else:
        print(f'{TRAINING_ALGORITHM} is not recognized as a training algorithm. Defaulting to Random Forest.')
        attack_classifier = RandomForestClassifier(n_estimators=100, random_state=42)

    # Train and test the model
    attack_classifier.fit(training_features, training_labels)

    # Predict on testing data
    predictions = attack_classifier.predict(testing_features)

    # Calculate and display accuracy
    print("The precision of the detection model is: " +
          str(get_accuracy(testing_labels, predictions, 1)) + " %")

    # Save the trained classifier
    model_location = save_model(attack_classifier, TRAINING_ALGORITHM)
    print(f"Your model has been saved at {model_location}")

except Exception as e:
    print('Something went wrong training the model.\nExiting.', e)
    sys.exit(1)
