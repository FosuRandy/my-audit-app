from app import app
import firebase_routes  # This imports all the Firebase-based routes
from data_store import initialize_sample_data

# Initialize sample data on startup
initialize_sample_data()
print("Initialized sample data: 4 users, 4 departments")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
