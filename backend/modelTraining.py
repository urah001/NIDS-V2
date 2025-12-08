import pandas as pd #type:ignore
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

# Load your dataset
train=pd.read_csv('https://raw.githubusercontent.com/urah001/wiresharkDataset/refs/heads/main/Train_data.csv') # Replace with actual path

# Encode categorical columns
categorical_cols = ['protocol_type', 'service', 'flag']  # Add more if needed
le = LabelEncoder()

for col in categorical_cols:
    train[col] = le.fit_transform(train[col])

# Separate features and label
# Instead of:
# X = train[["duration", "src_bytes", "dst_bytes", "count", "srv_count"]]


X = train.drop(columns=["class"])  # All features except the label

 # Your label column is 'class', not 'label'
y = train["class"]

# Encode labels (optional if not already binary or numerical)
y = LabelEncoder().fit_transform(y)

# Train the model
model = RandomForestClassifier()
model.fit(X, y)

#print(train.columns.tolist())

# Save model
joblib.dump(model, "nids_model.pkl")
