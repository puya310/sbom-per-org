import requests
import os
import json

#the following few lines PLEASE CHANGE to your own variables

api_key = os.environ.get("SNYK_TOKEN")  # Set this in your local env OR just hardcode it here if you want :)
org_id = "123456789"  # Use the org ID here - go to Snyk UI -> choose the Org -> Settings, copy the ID
version_format = "cyclonedx1.5%2Bjson"  # Define your version format here - not sure if 1.6 is supported here yet 


headers = {
    'Authorization': f"token {api_key}",
    'Accept': 'application/vnd.api+json'
}

def fetch_ids(base_endpoint):
    """
    Fetch the list of Target IDs from the base endpoint.
    """
    try:
        response = requests.get(base_endpoint, headers=headers)
        response.raise_for_status()
        data = response.json()
        return [item['id'] for item in data.get('data', [])]
    except Exception as e:
        print(f"Error fetching IDs: {e}")
        return []

def fetch_details(endpoint, item_id):
    """
    Fetch details for a given Target ID from the endpoint.
    """
    try:
        url = endpoint.replace("{item_id}", str(item_id)) + f"?sbom&format={version_format}&version=2024-10-14~experimental"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching details for ID {item_id}: {e}")
        return {}

def save_to_json(data, filename):
    """
    Save the data to a JSON file.
    """
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)
        print(f"Data saved to {filename}")

def main(base_endpoint, details_endpoint):
    """
    Main function to fetch and process data.
    """
    # Step 1: Fetch IDs from the get targets API endpoint 
    ids = fetch_ids(base_endpoint)
    if not ids:
        print("No IDs found. Exiting.")
        return

    # Step 2: Fetch details for each target ID and aggregate results
    results = []
    for item_id in ids:
        print(f"Fetching details for ID: {item_id}")
        details = fetch_details(details_endpoint, item_id)
        if details:
            results.append(details)

    save_to_json(results, "sbom.json")

    # Step 3: Display the aggregated results
    print("\nAggregated Results:")
    for result in results:
        print(result)

if __name__ == "__main__":

    base_api_endpoint = f"https://api.snyk.io/rest/orgs/{org_id}/targets?version=2024-10-13%7Ebeta&starting_after=v1.eyJpZCI6IjEwMDAifQo%3D&ending_before=v1.eyJpZCI6IjExMDAifQo%3D&limit=10&created_gte=2022-01-01T16%3A00%3A00Z"
    details_api_endpoint = f"https://api.snyk.io/rest/orgs/{org_id}/targets/{{item_id}}/sbom"
    
    main(base_api_endpoint, details_api_endpoint)
