import configparser
import pickle
import re
import sys
import time
import pandas as pd


# Wingdings Transformation
def to_wingdings(text):
    wingdings_map = {
        'a': '🂡', 'b': '🂢', 'c': '🂣',
        '1': '①', '2': '②', '3': '③',
        'd': '🂤', 'e': '🂥', 'f': '🂦',
        'g': '🂧', 'h': '🂨', 'i': '🂩',
        'j': '🂪', 'k': '🂫', 'l': '🂬',
        'm': '🂭', 'n': '🂮', 'o': '🂯',
        'p': '🂰', 'q': '🂱', 'r': '🂲',
        's': '🂳', 't': '🂴', 'u': '🂵',
        'v': '🂶', 'w': '🂷', 'x': '🂸',
        'y': '🂹', 'z': '🂺',
    }
    return ''.join(wingdings_map.get(char, char) for char in text.lower())


# Password-Protected Decryption
def decrypt_text(encrypted_text, password):
    correct_password = "hello123"
    if password == correct_password:
        reverse_map = {
            '🂡': 'a', '🂢': 'b', '🂣': 'c',
            '①': '1', '②': '2', '③': '3',
            '🂤': 'd', '🂥': 'e', '🂦': 'f',
            '🂧': 'g', '🂨': 'h', '🂩': 'i',
            '🂪': 'j', '🂫': 'k', '🂬': 'l',
            '🂭': 'm', '🂮': 'n', '🂯': 'o',
            '🂰': 'p', '🂱': 'q', '🂲': 'r',
            '🂳': 's', '🂴': 't', '🂵': 'u',
            '🂶': 'v', '🂷': 'w', '🂸': 'x',
            '🂹': 'y', '🂺': 'z',
        }
        return ''.join(reverse_map.get(char, char) for char in encrypted_text)
    else:
        return "Invalid password"


# Encode log file
def encode_log_file(log_file, log_type):
    encoded_logs = {}
    try:
        with open(log_file, 'r') as file:
            for line in file:
                features = {
                    "url_length": len(line),
                    "special_chars": sum(1 for char in line if char in SPECIAL_CHARS),
                    "slashes": line.count('/'),
                }
                encoded_logs[line] = features
    except Exception as e:
        print(f"Error encoding log file: {e}")
        sys.exit(1)
    return encoded_logs


# Construct encoded data file
def construct_encoded_data_file(encoded_logs, simulation_label):
    """
    Construct a CSV string from encoded logs for further processing.

    Args:
        encoded_logs (dict): Encoded log data.
        simulation_label (bool): Whether to set labels based on patterns for simulation.

    Returns:
        tuple: Number of logs and CSV string.
    """
    labelled_data_str = "url_length,special_chars,slashes,label,log_line\n"
    for log_line, features in encoded_logs.items():
        label = "0"
        if simulation_label:
            if any(keyword in log_line.lower() for keyword in ['sql', 'xss', 'eval', 'union']):
                label = "1"
        labelled_data_str += f"{features['url_length']},{features['special_chars']},{features['slashes']},{label},{log_line.strip()}\n"
    return len(encoded_logs), labelled_data_str


# Save the trained model
def save_model(model, label):
    try:
        model_file_name = f'MODELS/attack_classifier_{label}_{int(time.time())}.pkl'
        with open(model_file_name, 'wb') as file:
            pickle.dump(model, file)
        return model_file_name
    except Exception as e:
        print(f"Error saving model: {e}")
        raise


# Calculate the accuracy of the predictions
def get_accuracy(real_labels, predicted_labels, fltr):
    true_positives = sum(1 for real, pred in zip(real_labels, predicted_labels) if real == fltr and pred == fltr)
    false_positives = sum(1 for real, pred in zip(real_labels, predicted_labels) if real != fltr and pred == fltr)
    if true_positives + false_positives == 0:
        return 0
    precision = (true_positives / (true_positives + false_positives)) * 100
    return precision


# Generate a report
def gen_report(findings, log_file, log_type):
    gmt_time = time.strftime("%d/%m/%y at %H:%M:%S GMT", time.gmtime())
    report_str = f"""
    <html>
        <head>
            <style>
                td {{ padding: 5px; }}
                th {{ text-align:left; padding: 10px; background-color: whitesmoke; }}
                div {{ font-family:monospace; padding: 50px; }}
            </style>
        </head>
        <body>
            <h1>Webhawk Catch Report</h1>
            <p>Unsupervised learning Web logs attack detection.</p>
            <p>Date: {gmt_time}</p>
            <p>Log file: {log_file}</p>
            <p>Log type: {log_type}</p>
            <table border="1">
                <tr>
                    <th>Severity</th>
                    <th>Line#</th>
                    <th>Log line</th>
                </tr>
    """
    for finding in findings:
        report_str += f"""
        <tr>
            <td>{finding['severity']}</td>
            <td>{finding['log_line_number']}</td>
            <td>{finding['log_line']}</td>
        </tr>
        """
    report_str += "</table></body></html>"
    with open(f'./SCANS/scan_result_{log_file.split("/")[-1]}.html', 'w') as result_file:
        result_file.write(report_str)


# Configuration parser
config = configparser.ConfigParser()
config.sections()
config.read('settings.conf')

SPECIAL_CHARS = set("[$&+,:;=?@#|'<>.^*()%!-]")
