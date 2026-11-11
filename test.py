import requests

URL = "http://localhost:8080/api/rates"

try:
    response = requests.get(URL)
    response.raise_for_status()  # Raise an error for bad responses (4xx and 5xx)
    print(response.json())  # Return the JSON response if successful
except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")