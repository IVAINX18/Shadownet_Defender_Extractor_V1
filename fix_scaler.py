import joblib
import sklearn
from sklearn.preprocessing import StandardScaler
import warnings

# Suppress the warning during load
warnings.filterwarnings("ignore", category=UserWarning)

SCALER_PATH = "models/scaler.pkl"

print(f"Loading scaler from {SCALER_PATH}...")
try:
    scaler = joblib.load(SCALER_PATH)
    print(f"Scaler loaded. Current sklearn version: {sklearn.__version__}")
    
    # Re-save the scaler
    print(f"Re-saving scaler to {SCALER_PATH}...")
    joblib.dump(scaler, SCALER_PATH)
    print("Scaler updated successfully.")
except Exception as e:
    print(f"Error updating scaler: {e}")
